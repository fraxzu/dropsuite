//! h2 on the intercepted upstream leg: when a destination negotiates h2, the proxy must speak h2
//! to it while still answering the client over HTTP/1.1, and must leave an h1-only destination
//! untouched.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dropsuite_core::models::HistoryFilter;
use dropsuite_core::{HttpsInterceptConfig, InterceptAllowlist, ProxyEngine, StorageManager};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HOST: &str = "mitm.h2.test";

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("dropsuite-h2-{tag}-{:x}{t:x}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_ca() -> (CertificateDer<'static>, KeyPair, rcgen::Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "h2 upstream test root");
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(24);
    let cert = params.self_signed(&key).unwrap();
    (cert.der().clone(), key, cert)
}

fn make_leaf(
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    host: &str,
) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(host.try_into().unwrap())];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(24);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params.signed_by(&key, ca, ca_key).unwrap();
    (cert.der().clone(), key.serialize_der())
}

#[derive(Default, Clone)]
struct Seen {
    authority: String,
    path: String,
    connection_header: bool,
    body: Vec<u8>,
}

/// h2 server; echoes the request back so body streaming is observable.
async fn h2_origin(alpn: &[u8]) -> (u16, Arc<Mutex<Vec<Seen>>>, CertificateDer<'static>) {
    let (ca_der, ca_key, ca_cert) = make_ca();
    let (leaf, key) = make_leaf(&ca_cert, &ca_key, HOST);
    let key = PrivateKeyDer::try_from(key).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();

    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    let Ok(mut conn) = h2::server::handshake(tls).await else {
                        return;
                    };
                    while let Some(Ok((request, mut respond))) = conn.accept().await {
                        let (parts, mut body) = request.into_parts();
                        let mut raw = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            raw.extend_from_slice(&chunk);
                            let _ = body.flow_control().release_capacity(chunk.len());
                        }
                        sink.lock().unwrap().push(Seen {
                            authority: parts
                                .uri
                                .authority()
                                .map(|a| a.to_string())
                                .unwrap_or_default(),
                            path: parts.uri.path().to_string(),
                            connection_header: parts.headers.contains_key("connection"),
                            body: raw.clone(),
                        });
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(())
                            .unwrap();
                        if let Ok(mut stream) = respond.send_response(response, false) {
                            let mut payload = b"via h2:".to_vec();
                            payload.extend_from_slice(&raw);
                            let _ = stream.send_data(payload.into(), true);
                        }
                    }
                } else {
                    // h1 fallback, enough for the parity case.
                    let mut buf = vec![0u8; 8192];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nvia h1")
                        .await;
                }
            });
        }
    });
    (port, seen, ca_der)
}

/// Starts the proxy with interception for HOST pinned to the given origin port.
async fn proxy_for(
    _port: u16,
    dir: &std::path::Path,
    origin_ca: CertificateDer<'static>,
) -> (ProxyEngine, StorageManager) {
    let storage = StorageManager::new(dir.join("test.db")).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    let https = HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist: InterceptAllowlist::from_user_entries(&[HOST.to_string()]).unwrap(),
        upstream_roots: vec![origin_ca],
    };
    proxy.set_https_interception(https);
    proxy.set_resolver_override(Arc::new(move |_host: &str| {
        Some(vec![std::net::IpAddr::from([127, 0, 0, 1])])
    }));
    proxy.start().await.unwrap();
    proxy.load_or_generate_ca().await.unwrap();
    (proxy, storage)
}

/// CONNECT, TLS to the proxy, send one HTTP/1.1 request, return the raw response.
async fn through_proxy(
    proxy_port: u16,
    ca: CertificateDer<'static>,
    origin_port: u16,
    raw_req: &[u8],
) -> Vec<u8> {
    let mut sock = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect =
        format!("CONNECT {HOST}:{origin_port} HTTP/1.1\r\nHost: {HOST}:{origin_port}\r\n\r\n");
    sock.write_all(connect.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
        "CONNECT must succeed"
    );

    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let name: ServerName<'static> = HOST.try_into().unwrap();
    let mut tls = connector.connect(name, sock).await.unwrap();
    tls.write_all(raw_req).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut out)).await;
    out
}

fn proxy_ca(dir: &std::path::Path) -> CertificateDer<'static> {
    dropsuite_core::ca::CaManager::new(dir.join("ca"))
        .load()
        .expect("CA was generated")
        .cert_der
}

#[tokio::test]
async fn intercepted_upstream_uses_h2_when_offered() {
    let dir = temp_dir("h2");
    let (origin_port, seen, origin_ca) = h2_origin(b"h2").await;
    let (proxy, storage) = proxy_for(origin_port, &dir, origin_ca).await;
    let ca = proxy_ca(&dir);

    let resp = through_proxy(
        proxy.port(),
        ca,
        origin_port,
        format!("GET /deep/path?q=1 HTTP/1.1\r\nHost: {HOST}:{origin_port}\r\n\r\n").as_bytes(),
    )
    .await;
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "client stays on h1: {text}"
    );
    eprintln!("RAW RESPONSE: {:?}", text);
    assert!(
        text.contains("via h2"),
        "destination must have spoken h2: {text}"
    );

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].authority, format!("{HOST}:{origin_port}"));
    assert_eq!(seen[0].path, "/deep/path");
    assert!(!seen[0].connection_header, "h2 must not carry Connection");

    let records = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(records.len(), 1, "the exchange is still recorded");
    assert_eq!(records[0].status_code, 200);
}

#[tokio::test]
async fn intercepted_upstream_streams_a_request_body_over_h2() {
    let dir = temp_dir("h2body");
    let (origin_port, seen, origin_ca) = h2_origin(b"h2").await;
    let (proxy, _storage) = proxy_for(origin_port, &dir, origin_ca).await;
    let ca = proxy_ca(&dir);

    let body = "name=admin&x=1";
    let resp = through_proxy(
        proxy.port(),
        ca,
        origin_port,
        format!(
            "POST /save HTTP/1.1\r\nHost: {HOST}:{origin_port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await;

    assert!(String::from_utf8_lossy(&resp).contains("via h2"));
    assert_eq!(seen.lock().unwrap()[0].body, body.as_bytes());
}

#[tokio::test]
async fn h1_only_destination_is_unchanged() {
    let dir = temp_dir("h1");
    let (origin_port, _seen, origin_ca) = h2_origin(b"http/1.1").await;
    let (proxy, _storage) = proxy_for(origin_port, &dir, origin_ca).await;
    let ca = proxy_ca(&dir);

    let resp = through_proxy(
        proxy.port(),
        ca,
        origin_port,
        format!("GET /plain HTTP/1.1\r\nHost: {HOST}:{origin_port}\r\n\r\n").as_bytes(),
    )
    .await;
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains("200"), "{text}");
    assert!(
        text.contains("via h1"),
        "h1 fallback must still proxy: {text}"
    );
}

#[tokio::test]
async fn connector_reports_h2_when_the_destination_offers_it() {
    let (origin_port, _seen, origin_ca) = h2_origin(b"h2").await;
    let dir = temp_dir("alpn");
    let https = HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist: InterceptAllowlist::from_user_entries(&[HOST.to_string()]).unwrap(),
        upstream_roots: vec![origin_ca],
    };
    let https = dropsuite_core::HttpsInterception::new(https).unwrap();
    let targets = [std::net::SocketAddr::from(([127, 0, 0, 1], origin_port))];
    let up = https
        .connect_upstream_targets(HOST, &targets)
        .await
        .unwrap();
    assert!(up.h2, "ALPN must select h2 when both sides offer it");
}
