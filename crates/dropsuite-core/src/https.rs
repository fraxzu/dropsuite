use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::pki_types::CertificateDer;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::allowlist::InterceptAllowlist;
use crate::ca::{self, CaError, CaManager, CaMaterial, CaStatus, LEAF_VALIDITY};

pub const MAX_LEAF_CACHE: usize = 1000;

pub struct HttpsInterceptConfig {
    pub ca_dir: PathBuf,
    pub allowlist: InterceptAllowlist,
    pub upstream_roots: Vec<CertificateDer<'static>>,
}

pub struct HttpsInterception {
    ca_manager: CaManager,
    allowlist: RwLock<InterceptAllowlist>,
    ca: tokio::sync::RwLock<Option<Arc<CaMaterial>>>,
    leaf_cache: Arc<RwLock<LeafCache>>,
    connector: TlsConnector,
}

#[derive(Clone)]
pub struct LeafEntry {
    pub acceptor: TlsAcceptor,
    pub fingerprint: String,
    pub cert_der: Vec<u8>,
    pub expires: SystemTime,
}

#[derive(Default)]
pub struct LeafCache {
    /// host_key -> LeafEntry
    pub by_host: HashMap<String, LeafEntry>,
    /// fingerprint -> host_key
    pub by_fingerprint: HashMap<String, String>,
}

impl LeafCache {
    pub fn clear(&mut self) {
        self.by_host.clear();
        self.by_fingerprint.clear();
    }

    pub fn get_host(&self, fp: &str) -> Option<&str> {
        self.by_fingerprint
            .get(&fp.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn contains_fingerprint(&self, fp: &str) -> bool {
        self.by_fingerprint.contains_key(&fp.to_ascii_lowercase())
    }

    pub fn insert(
        &mut self,
        host: String,
        acceptor: TlsAcceptor,
        fingerprint: String,
        cert_der: Vec<u8>,
        expires: SystemTime,
    ) {
        let now = SystemTime::now();
        let fp_clean = fingerprint.trim().to_ascii_lowercase();
        debug_assert!(fp_clean
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // 1. Evict expired entries
        self.by_host.retain(|_, e| e.expires > now);
        let valid_fps: HashSet<String> = self
            .by_host
            .values()
            .map(|e| e.fingerprint.to_ascii_lowercase())
            .collect();
        self.by_fingerprint.retain(|fp, _| valid_fps.contains(fp));

        // 2. Bound size to MAX_LEAF_CACHE
        if self.by_host.len() >= MAX_LEAF_CACHE {
            if let Some(oldest_host) = self
                .by_host
                .iter()
                .min_by_key(|(_, e)| e.expires)
                .map(|(h, _)| h.clone())
            {
                if let Some(removed) = self.by_host.remove(&oldest_host) {
                    self.by_fingerprint.remove(&removed.fingerprint);
                }
            }
        }

        // 3. Insert new leaf
        self.by_fingerprint.insert(fp_clean.clone(), host.clone());
        self.by_host.insert(
            host,
            LeafEntry {
                acceptor,
                fingerprint: fp_clean,
                cert_der,
                expires,
            },
        );
    }
}

pub struct UpstreamTls {
    pub reader: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    pub writer: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("CA error: {0}")]
    Ca(#[from] CaError),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("connect: {0}")]
    Connect(String),
}

impl HttpsInterception {
    pub fn new(config: HttpsInterceptConfig) -> Result<Self, TlsError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca_manager = CaManager::new(config.ca_dir);

        let mut root_store = rustls::RootCertStore::empty();
        if config.upstream_roots.is_empty() {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for root in &config.upstream_roots {
                root_store
                    .add(root.clone())
                    .map_err(|e| TlsError::Tls(e.to_string()))?;
            }
        }

        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = TlsConnector::from(Arc::new(client_config));

        Ok(HttpsInterception {
            ca_manager,
            allowlist: RwLock::new(config.allowlist),
            ca: tokio::sync::RwLock::new(None),
            leaf_cache: Arc::new(RwLock::new(LeafCache::default())),
            connector,
        })
    }

    pub fn allowlist(&self) -> InterceptAllowlist {
        self.allowlist.read().unwrap().clone()
    }

    pub fn set_allowlist(&self, list: InterceptAllowlist) {
        *self.allowlist.write().unwrap() = list;
    }

    pub fn allows(&self, host: &str, port: u16) -> bool {
        self.allowlist.read().unwrap().allows(host, port)
    }

    pub fn ca_status(&self) -> CaStatus {
        self.ca_manager.status()
    }

    pub fn is_minted_leaf(&self, fp: &str) -> bool {
        let Ok(cache) = self.leaf_cache.read() else {
            return false;
        };
        cache.contains_fingerprint(fp)
    }

    pub fn minted_leaf_host(&self, fp: &str) -> Option<String> {
        let Ok(cache) = self.leaf_cache.read() else {
            return None;
        };
        cache.get_host(fp).map(|s| s.to_string())
    }

    pub fn leaf_cache(&self) -> Arc<RwLock<LeafCache>> {
        self.leaf_cache.clone()
    }

    pub async fn remove_ca(&self) -> Result<(), CaError> {
        self.ca_manager.remove()?;
        *self.ca.write().await = None;
        if let Ok(mut cache) = self.leaf_cache.write() {
            cache.clear();
        }
        Ok(())
    }

    pub async fn load_or_generate_ca(&self) -> Result<Arc<CaMaterial>, CaError> {
        let mut ca = self.ca.write().await;
        let material = Arc::new(self.ca_manager.load_or_generate()?);
        *ca = Some(material.clone());
        if let Ok(mut cache) = self.leaf_cache.write() {
            cache.clear();
        }
        Ok(material)
    }

    /// The CA used to sign leaf certificates, loaded from disk when needed. It is never created
    /// here: without an explicitly generated CA, interception fails with [`CaError::NotGenerated`].
    pub async fn ca_material(&self) -> Result<Arc<CaMaterial>, CaError> {
        {
            let ca = self.ca.read().await;
            if let Some(ref m) = *ca {
                return Ok(m.clone());
            }
        }
        let mut ca = self.ca.write().await;
        if let Some(ref m) = *ca {
            return Ok(m.clone());
        }
        let material = Arc::new(self.ca_manager.load()?);
        *ca = Some(material.clone());
        Ok(material)
    }

    pub async fn acceptor_for(&self, host: &str) -> Result<TlsAcceptor, TlsError> {
        let host_key = host.to_ascii_lowercase();

        {
            if let Ok(cache) = self.leaf_cache.read() {
                if let Some(entry) = cache.by_host.get(&host_key) {
                    if SystemTime::now() < entry.expires {
                        return Ok(entry.acceptor.clone());
                    }
                }
            }
        }

        let ca = self.ca_material().await?;
        let leaf = ca::issue_leaf(&ca, host)?;

        let fp = ca::sha256_hex(leaf.cert_der.as_ref());

        let key_der = rustls::pki_types::PrivateKeyDer::try_from(leaf.key_der)
            .map_err(|e| TlsError::Tls(e.to_string()))?;
        let cert_der_bytes = leaf.cert_der.to_vec();
        let certs = vec![leaf.cert_der];

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .map_err(|e| TlsError::Tls(e.to_string()))?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let expires = SystemTime::now() + LEAF_VALIDITY - std::time::Duration::from_secs(3600);
        if let Ok(mut cache) = self.leaf_cache.write() {
            cache.insert(host_key, acceptor.clone(), fp, cert_der_bytes, expires);
        }

        Ok(acceptor)
    }

    pub async fn connect_upstream_targets(
        &self,
        host: &str,
        targets: &[std::net::SocketAddr],
    ) -> Result<UpstreamTls, TlsError> {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(targets),
        )
        .await
        .map_err(|_| TlsError::Connect(format!("connect to {host} timed out")))?
        .map_err(|e| TlsError::Connect(format!("connect to {host}: {e}")))?;

        let server_name: rustls::pki_types::ServerName<'static> = host
            .to_string()
            .try_into()
            .map_err(|e| TlsError::Tls(format!("invalid hostname {host}: {e}")))?;

        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| TlsError::Tls(format!("TLS handshake with {host} timed out")))?
        .map_err(|e| TlsError::Tls(format!("TLS handshake with {host} failed: {e}")))?;

        let (reader, writer) = tokio::io::split(tls_stream);
        Ok(UpstreamTls { reader, writer })
    }

    pub async fn connect_upstream(&self, host: &str, port: u16) -> Result<UpstreamTls, TlsError> {
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| TlsError::Connect(format!("resolve {host}: {e}")))?;
        let targets: Vec<std::net::SocketAddr> = addrs.collect();
        self.connect_upstream_targets(host, &targets).await
    }
}
