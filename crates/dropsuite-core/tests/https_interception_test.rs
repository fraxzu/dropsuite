use std::sync::Arc;
use std::time::Duration;

use dropsuite_core::allowlist::InterceptAllowlist;
use dropsuite_core::ca::CaManager;
use dropsuite_core::https::HttpsInterceptConfig;
use dropsuite_core::models::HistoryFilter;
use dropsuite_core::replay::{
    send as replay_send, send_with as replay_send_with, NetworkSeams, ReplayOptions, ReplayRequest,
};
use dropsuite_core::{ProxyEngine, StorageManager};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Create a test upstream CA and return (ca_cert_der, ca_key, ca_cert_rcgen).
fn make_test_ca() -> (CertificateDer<'static>, KeyPair, rcgen::Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test Upstream Root CA");
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(30);
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().clone();
    (cert_der, key, cert)
}

/// Issue a leaf certificate for the given domain name signed by the test CA.
fn make_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    host: &str,
) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![SanType::DnsName(host.to_string().try_into().unwrap())];
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(7);
    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
    (cert.der().clone(), key.serialize_der())
}

/// Start a mock HTTPS origin server presenting the given cert/key.
async fn start_mock_https_server(
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let key = PrivateKeyDer::try_from(key_der).unwrap();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = vec![0u8; 4096];
                    if let Ok(n) = tls.read(&mut buf).await {
                        if n > 0 {
                            let body = b"{\"status\":\"hello from mock https\"}";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = tls.write_all(resp.as_bytes()).await;
                            let _ = tls.write_all(body).await;
                            let _ = tls.shutdown().await;
                        }
                    }
                }
            });
        }
    });

    (port, handle)
}

static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let id = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("dropsuite-https-{tag}-{id}-{t:x}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Mock connector: attempts are still counted, but only loopback sockets are ever opened, so a
/// policy regression cannot reach a real metadata endpoint from a test.
fn loopback_only_gate() -> dropsuite_core::proxy::ConnectGate {
    Arc::new(|targets: &[std::net::SocketAddr]| targets.iter().all(|t| t.ip().is_loopback()))
}

/// Set up a test proxy with an isolated temporary directory and storage.
async fn setup_test_proxy(
    allowlist_entries: &[&str],
    upstream_roots: Vec<CertificateDer<'static>>,
) -> (ProxyEngine, StorageManager, std::path::PathBuf, u16) {
    let dir = temp_dir("proxy");
    let db_path = dir.join("test.db");
    let storage = StorageManager::new(&db_path).unwrap();

    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    let allowlist = InterceptAllowlist::from_user_entries(
        &allowlist_entries.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();

    let https_cfg = HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist,
        upstream_roots,
    };
    proxy.set_https_interception(https_cfg);
    proxy.set_connect_gate(loopback_only_gate());
    proxy.start().await.unwrap();
    // Interception needs an explicitly generated CA (the user's Generate action).
    proxy.load_or_generate_ca().await.unwrap();
    let port = proxy.port();

    (proxy, storage, dir, port)
}

#[tokio::test]
async fn connect_malformed_authority_rejected() {
    let (_proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    stream
        .write_all(b"CONNECT bad:authority:format HTTP/1.1\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request"));
}

#[tokio::test]
async fn connect_own_listener_loop_rejected() {
    let (_proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("CONNECT 127.0.0.1:{proxy_port} HTTP/1.1\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 508 Loop Detected"));
}

#[tokio::test]
async fn successful_tls_interception_and_capture() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "localhost");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let (proxy, storage, dir, proxy_port) =
        setup_test_proxy(&["localhost"], vec![ca_der]).await;

    // Connect to proxy and send CONNECT
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT localhost:{server_port} HTTP/1.1\r\nHost: localhost:{server_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 Connection Established"));

    // Now establish client TLS using the proxy's local CA certificate as trusted root
    let ca_status = proxy.https_status().unwrap();
    assert!(ca_status.present);
    let cert_pem = ca_status.cert_pem.unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let proxy_ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    for cert in proxy_ca_certs {
        root_store.add(cert).unwrap();
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    let mut tls_client = connector.connect(server_name, stream).await.unwrap();

    // Send an HTTP request over the intercepted TLS tunnel
    let http_req = format!("GET /test-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls_client.write_all(http_req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 2048];
    let n = tls_client.read(&mut response_buf).await.unwrap();
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(response_str.contains("200 OK"));
    assert!(response_str.contains("hello from mock https"));

    // Verify the transaction was captured in SQLite storage with https:// URL!
    tokio::time::sleep(Duration::from_millis(50)).await;
    let records = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status_code, 200);

    let full_record = storage.get_transaction_by_id(records[0].id).unwrap().unwrap();
    assert!(full_record.url.starts_with("https://localhost"));
    assert_eq!(full_record.method, "GET");
    assert_eq!(proxy.outbound_connect_attempts(), 1, "Exactly one pinned upstream connect");

    // Clean up
    let _ = proxy;
    let _ = dir;
}

#[tokio::test]
async fn untrusted_client_tls_handshake_fails() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "localhost");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let (_proxy, _storage, _dir, proxy_port) =
        setup_test_proxy(&["localhost"], vec![ca_der]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT localhost:{server_port} HTTP/1.1\r\nHost: localhost:{server_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"));

    // Client with empty root store (does NOT trust DropSuite CA)
    let client_config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    let handshake_res = connector.connect(server_name, stream).await;
    assert!(handshake_res.is_err(), "Handshake must fail when client does not trust the CA");
}

#[tokio::test]
async fn upstream_hostname_mismatch_rejected() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    // Server presents cert for "wrong.domain.test", but client asks for "localhost"
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "wrong.domain.test");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let (proxy, _storage, _dir, proxy_port) =
        setup_test_proxy(&["localhost"], vec![ca_der]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT localhost:{server_port} HTTP/1.1\r\nHost: localhost:{server_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"));

    // Client connects with TLS to the proxy
    let ca_status = proxy.https_status().unwrap();
    let cert_pem = ca_status.cert_pem.unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let proxy_ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    for cert in proxy_ca_certs {
        root_store.add(cert).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    let mut tls_client = connector.connect(server_name, stream).await.unwrap();

    // Send HTTP request — upstream verification should fail because the cert hostname is wrong!
    let http_req = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_client.write_all(http_req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 1024];
    let n = tls_client.read(&mut response_buf).await.unwrap_or(0);
    let resp = String::from_utf8_lossy(&response_buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 502 Bad Gateway"), "Expected 502 Bad Gateway on hostname mismatch, got: {resp}");
}

#[tokio::test]
async fn non_allowlisted_connect_is_tunneled_without_decryption() {
    // Start an echo server on a port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            if let Ok(n) = sock.read(&mut buf).await {
                let _ = sock.write_all(&buf[..n]).await;
            }
        }
    });

    // Proxy only allowlists "lumens.my.id", NOT 127.0.0.1 or localhost
    let (proxy, storage, _dir, proxy_port) =
        setup_test_proxy(&["lumens.my.id"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 200 Connection Established"));

    // Send arbitrary bytes through the tunnel (not decrypted)
    let payload = b"arbitrary raw bytes through blind tunnel";
    stream.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    // Verify NOTHING was captured in SQLite storage (zero records!)
    tokio::time::sleep(Duration::from_millis(50)).await;
    let records = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(records.len(), 0, "Non-allowlisted traffic must NOT be decrypted or stored in history");
    assert_eq!(proxy.outbound_connect_attempts(), 1, "Blind tunnel connects upstream exactly once");
}

#[tokio::test]
async fn replay_https_request_succeeds() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "localhost");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let req = ReplayRequest {
        method: "GET".into(),
        url: format!("https://localhost:{server_port}/echo"),
        headers: vec![],
        body: "".into(),
    };
    let opts = ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: vec![ca_der],
        apply: dropsuite_core::replay::ApplyConfig::default(),
    };

    let res = replay_send(&req, &opts).await.unwrap();
    assert_eq!(res.status, 200);
    assert_eq!(res.reason, "OK");
    assert!(String::from_utf8_lossy(&res.message).contains("hello from mock https"));
}

#[tokio::test]
async fn replay_https_hostname_mismatch_rejected() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "wrong.domain.test");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let req = ReplayRequest {
        method: "GET".into(),
        url: format!("https://localhost:{server_port}/echo"),
        headers: vec![],
        body: "".into(),
    };
    let opts = ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: vec![ca_der],
        apply: dropsuite_core::replay::ApplyConfig::default(),
    };

    let err = replay_send(&req, &opts).await.unwrap_err();
    assert_eq!(err.kind, "tls", "Expected tls error on hostname mismatch, got: {:?}", err);
}

#[test]
fn ca_manager_lifecycle_and_fingerprint_stability() {
    let dir = temp_dir("ca-lifecycle");
    let ca_dir = dir.join("ca");
    let mgr = CaManager::new(ca_dir.clone());

    // Initially not present
    let s0 = mgr.status();
    assert!(!s0.present);

    // Generate
    let mat1 = mgr.load_or_generate().unwrap();
    let s1 = mgr.status();
    assert!(s1.present);
    assert_eq!(s1.fingerprint, Some(mat1.fingerprint.clone()));
    assert!(s1.cert_pem.is_some());

    // Reload from disk: must be identical fingerprint
    let mat2 = mgr.load_or_generate().unwrap();
    assert_eq!(mat1.fingerprint, mat2.fingerprint);

    // Remove
    mgr.remove().unwrap();
    let s3 = mgr.status();
    assert!(!s3.present);
}

#[tokio::test]
async fn connect_ipv4_mapped_ipv6_loop_rejected() {
    let (_proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // IPv4-mapped IPv6 loopback representation
    let req = format!("CONNECT [::ffff:127.0.0.1]:{proxy_port} HTTP/1.1\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 508 Loop Detected"), "Must reject IPv4-mapped loopback with 508, got: {resp}");
}

#[tokio::test]
async fn connect_cloud_metadata_link_local_rejected() {
    let (proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    // Cloud metadata IMDS IP
    let req = "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "Must block cloud metadata / link-local with 403, got: {resp}");
    assert_eq!(proxy.outbound_connect_attempts(), 0, "No tunnel connection may be attempted");
}

#[tokio::test]
async fn connect_smtp_port_25_rejected() {
    let (_proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = "CONNECT 1.2.3.4:25 HTTP/1.1\r\nHost: 1.2.3.4:25\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 403 Forbidden"), "Must block port 25 SMTP with 403, got: {resp}");
}

#[tokio::test]
async fn connect_userinfo_or_path_in_authority_rejected() {
    let (_proxy, _storage, _dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    for bad_authority in [
        "user:pass@localhost:443",
        "localhost:443/evil",
        "localhost:443?query=1",
        "localhost:443#fragment",
    ] {
        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("CONNECT {bad_authority} HTTP/1.1\r\nHost: {bad_authority}\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "Authority '{bad_authority}' must be rejected with 400, got: {resp}");
    }
}

#[tokio::test]
async fn tls_session_cross_host_absolute_target_rejected() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "localhost");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let (proxy, _storage, _dir, proxy_port) =
        setup_test_proxy(&["localhost"], vec![ca_der]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT localhost:{server_port} HTTP/1.1\r\nHost: localhost:{server_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"));

    let ca_status = proxy.https_status().unwrap();
    let cert_pem = ca_status.cert_pem.unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let proxy_ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    for cert in proxy_ca_certs {
        root_store.add(cert).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    let mut tls_client = connector.connect(server_name, stream).await.unwrap();

    // Cross-host absolute URI inside the TLS session (attempting history spoofing)
    let http_req = "GET https://bank.example.com/transfer HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    tls_client.write_all(http_req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 1024];
    let n = tls_client.read(&mut response_buf).await.unwrap_or(0);
    let resp = String::from_utf8_lossy(&response_buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "Must reject cross-host absolute target with 400, got: {resp}");
}

#[tokio::test]
async fn tls_session_missing_host_header_rejected() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, "localhost");
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let (proxy, _storage, _dir, proxy_port) =
        setup_test_proxy(&["localhost"], vec![ca_der]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let connect_req = format!("CONNECT localhost:{server_port} HTTP/1.1\r\nHost: localhost:{server_port}\r\n\r\n");
    stream.write_all(connect_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"));

    let ca_status = proxy.https_status().unwrap();
    let cert_pem = ca_status.cert_pem.unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let proxy_ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut root_store = RootCertStore::empty();
    for cert in proxy_ca_certs {
        root_store.add(cert).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    let mut tls_client = connector.connect(server_name, stream).await.unwrap();

    // Missing Host header in HTTP/1.1 request
    let http_req = "GET /test HTTP/1.1\r\nConnection: close\r\n\r\n";
    tls_client.write_all(http_req.as_bytes()).await.unwrap();

    let mut response_buf = vec![0u8; 1024];
    let n = tls_client.read(&mut response_buf).await.unwrap_or(0);
    let resp = String::from_utf8_lossy(&response_buf[..n]);
    assert!(resp.starts_with("HTTP/1.1 400 Bad Request"), "Must reject missing Host header with 400, got: {resp}");
}

#[tokio::test]
async fn ca_removal_clears_in_memory_state() {
    let (proxy, _storage, dir, _proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;

    // Trigger CA generation
    proxy.load_or_generate_ca().await.unwrap();
    let status_before = proxy.https_status().unwrap();
    assert!(status_before.present);
    assert!(dir.join("ca").join("root-ca.pem").exists());

    // Remove CA via proxy
    proxy.remove_ca().await.unwrap();

    // Verify in-memory state is cleared
    let status_after = proxy.https_status().unwrap();
    assert!(!status_after.present);
    assert!(!dir.join("ca").join("root-ca.pem").exists());
}

#[tokio::test]
async fn non_loopback_listener_bind_is_rejected() {
    let dir = temp_dir("non-loopback");
    let storage = StorageManager::new(&dir.join("test.db")).unwrap();

    // 0.0.0.0 (all interfaces) must fail closed
    let mut proxy_any = ProxyEngine::new("0.0.0.0", 0, storage.clone());
    let err_any = proxy_any.start().await.unwrap_err();
    assert!(
        err_any.to_string().contains("Non-loopback bind address '0.0.0.0' is prohibited"),
        "Must fail closed on 0.0.0.0, got: {err_any}"
    );

    // Private network interface must fail closed
    let mut proxy_lan = ProxyEngine::new("192.168.1.1", 0, storage.clone());
    let err_lan = proxy_lan.start().await.unwrap_err();
    assert!(
        err_lan.to_string().contains("Non-loopback bind address '192.168.1.1' is prohibited"),
        "Must fail closed on LAN IP, got: {err_lan}"
    );
}

#[tokio::test]
async fn interception_allowlist_cannot_override_cloud_metadata_block() {
    // Hostname is explicitly added to the interception allowlist
    let (proxy, _storage, _dir, proxy_port) =
        setup_test_proxy(&["169.254.169.254", "metadata.local"], vec![]).await;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n";
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "Interception allowlist must NOT override metadata block, got: {resp}"
    );
    assert!(
        resp.contains("link-local and cloud metadata addresses are strictly prohibited"),
        "Expected strict prohibition message, got: {resp}"
    );
    assert_eq!(proxy.outbound_connect_attempts(), 0, "No interception upstream may be attempted");
}

#[tokio::test]
async fn dns_resolution_connection_pinning_prevents_toctou() {
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    // Hostname does NOT exist in DNS. If any code path attempts to resolve it via DNS, it fails.
    let unresolvable_host = "pinned-target.unresolvable-test.invalid";
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, unresolvable_host);
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let dir = temp_dir("pinning");
    let https_cfg = HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist: InterceptAllowlist::loopback_default(),
        upstream_roots: vec![ca_der],
    };
    let https = dropsuite_core::HttpsInterception::new(https_cfg).unwrap();

    // Pass the pinned SocketAddr (127.0.0.1:server_port).
    // The connector must connect to this pinned IP directly and use unresolvable_host only for TLS SNI/verification.
    let pinned_targets = [std::net::SocketAddr::from(([127, 0, 0, 1], server_port))];
    let upstream = https
        .connect_upstream_targets(unresolvable_host, &pinned_targets)
        .await
        .expect("Must connect to pinned SocketAddr without DNS resolution");

    let mut reader = upstream.reader;
    let mut writer = upstream.writer;

    let req = format!("GET /pinning-test HTTP/1.1\r\nHost: {unresolvable_host}\r\nConnection: close\r\n\r\n");
    writer.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = reader.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("hello from mock https"));
}

#[tokio::test]
async fn windows_dpapi_fails_closed_when_key_unusable_or_plaintext() {
    let dir = temp_dir("dpapi-failclosed");
    let ca_dir = dir.join("ca");
    let mgr = CaManager::new(ca_dir.clone());

    // 1. Generate legitimate CA to get valid cert, params, and meta
    let legitimate = mgr.load_or_generate().unwrap();
    assert!(mgr.status().present);

    // 2. Delete the DPAPI-protected key file
    let dpapi_file = ca_dir.join("root-ca.key.dpapi");
    if dpapi_file.exists() {
        std::fs::remove_file(&dpapi_file).unwrap();
    }

    // 3. Place an unencrypted plaintext PEM key file in its place
    let plaintext_key_file = ca_dir.join("root-ca.key");
    let key = KeyPair::generate().unwrap();
    std::fs::write(&plaintext_key_file, key.serialize_pem()).unwrap();

    // 4. On Windows: load_or_generate MUST fail closed and refuse the plaintext key!
    #[cfg(windows)]
    {
        let load_res = mgr.load_or_generate();
        match load_res {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("DPAPI-protected") || err_msg.contains("not found"),
                    "Expected DPAPI failure message, got: {err_msg}"
                );
            }
            Ok(_) => panic!("Windows must refuse to load plaintext PEM key without DPAPI"),
        }
    }

    // 5. Corrupted DPAPI blob must also fail closed
    std::fs::write(&dpapi_file, b"corrupted invalid dpapi ciphertext bytes").unwrap();
    #[cfg(windows)]
    {
        let load_res2 = mgr.load_or_generate();
        assert!(
            load_res2.is_err(),
            "Corrupted DPAPI ciphertext must fail closed"
        );
    }

    let _ = legitimate;
}

#[tokio::test]
async fn tls_session_request_rechecks_destination_after_rebinding() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // CONNECT resolves rebind.test to loopback (permitted; interception opens no upstream yet).
    // The request inside the TLS session resolves again and now gets the metadata address: it
    // must be refused before the pinned upstream connect is attempted.
    let dir = temp_dir("rebind");
    let storage = StorageManager::new(&dir.join("test.db")).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage);
    proxy.set_https_interception(HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist: InterceptAllowlist::from_user_entries(&["rebind.test".into()]).unwrap(),
        upstream_roots: vec![],
    });
    let lookups = Arc::new(AtomicUsize::new(0));
    let seen = lookups.clone();
    proxy.set_resolver_override(Arc::new(move |host: &str| {
        (host == "rebind.test").then(|| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![std::net::IpAddr::from([127, 0, 0, 1])]
            } else {
                vec![std::net::IpAddr::from([169, 254, 169, 254])]
            }
        })
    }));
    proxy.set_connect_gate(loopback_only_gate());
    proxy.start().await.unwrap();
    proxy.load_or_generate_ca().await.unwrap();
    let proxy_port = proxy.port();

    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    stream
        .write_all(b"CONNECT rebind.test:443 HTTP/1.1\r\nHost: rebind.test:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200 Connection Established"));

    let ca_status = proxy.https_status().unwrap();
    let cert_pem = ca_status.cert_pem.unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let proxy_ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut root_store = RootCertStore::empty();
    for cert in proxy_ca_certs {
        root_store.add(cert).unwrap();
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name: ServerName<'static> = "rebind.test".to_string().try_into().unwrap();
    let mut tls_client = connector.connect(server_name, stream).await.unwrap();

    tls_client
        .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: rebind.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response_buf = vec![0u8; 1024];
    let n = tls_client.read(&mut response_buf).await.unwrap_or(0);
    let resp = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "Rebound session host must be refused, got: {resp}"
    );
    assert!(resp.contains("link-local and cloud metadata addresses are strictly prohibited"));
    assert_eq!(lookups.load(Ordering::SeqCst), 2, "CONNECT and the request each resolve");
    assert_eq!(proxy.outbound_connect_attempts(), 0, "No upstream connect after rebinding");
}

#[tokio::test]
async fn replay_https_connects_to_checked_address_and_verifies_original_hostname() {
    // The name is not in DNS (.test is reserved): the only way to reach the server is the
    // resolved, policy-checked address. TLS still verifies the certificate for the name.
    let host = "pinned-replay.test";
    let (ca_der, ca_key, ca_cert) = make_test_ca();
    let (leaf_der, leaf_key) = make_leaf(&ca_cert, &ca_key, host);
    let (server_port, _server_task) = start_mock_https_server(leaf_der, leaf_key).await;

    let gate_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = gate_calls.clone();
    let net = NetworkSeams {
        resolver: Some(Arc::new(move |h: &str| {
            (h == host).then(|| vec![std::net::IpAddr::from([127, 0, 0, 1])])
        })),
        connect_gate: Some(Arc::new(move |targets: &[std::net::SocketAddr]| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            targets.iter().all(|t| t.ip().is_loopback())
        })),
    };
    let req = ReplayRequest {
        method: "GET".into(),
        url: format!("https://{host}:{server_port}/echo"),
        headers: vec![],
        body: "".into(),
    };
    let opts = |roots: Vec<CertificateDer<'static>>| ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: roots,
        apply: dropsuite_core::replay::ApplyConfig::default(),
    };

    let res = replay_send_with(&req, &opts(vec![ca_der]), &net).await.unwrap();
    assert_eq!(res.status, 200);
    assert!(String::from_utf8_lossy(&res.message).contains("hello from mock https"));
    assert_eq!(gate_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Without the test root (what the app passes: an empty list, meaning webpki roots) the same
    // server is not trusted: test trust is opt-in per call and never the default.
    let err = replay_send_with(&req, &opts(Vec::new()), &net).await.unwrap_err();
    assert_eq!(err.kind, "tls", "Expected tls error with default roots, got: {err:?}");
}

/// CONNECT to an allowlisted host and read the proxy's answer to it.
async fn connect_head(proxy_port: u16, target: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    (stream, String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Full TLS handshake through the tunnel, trusting only the given CA certificate.
async fn handshake_trusting(stream: TcpStream, ca_pem: &str) -> Result<(), std::io::Error> {
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    let mut root_store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let name: ServerName<'static> = "localhost".to_string().try_into().unwrap();
    TlsConnector::from(Arc::new(config)).connect(name, stream).await.map(|_| ())
}

#[tokio::test]
async fn allowlisted_connect_without_ca_fails_closed_and_creates_none() {
    // A proxy whose user never pressed Generate: no CA exists, and interception must not make one.
    let dir = temp_dir("no-ca");
    let storage = StorageManager::new(&dir.join("test.db")).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage);
    proxy.set_https_interception(HttpsInterceptConfig {
        ca_dir: dir.join("ca"),
        allowlist: InterceptAllowlist::loopback_default(),
        upstream_roots: vec![],
    });
    proxy.set_connect_gate(loopback_only_gate());
    proxy.start().await.unwrap();

    let (_stream, head) = connect_head(proxy.port(), "localhost:443").await;
    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway"), "Expected 502 without a CA, got: {head}");
    assert!(head.contains("needs a root CA"), "Expected the generate hint, got: {head}");
    assert!(!head.contains("200 Connection Established"));
    assert!(!proxy.https_status().unwrap().present, "No CA may be created implicitly");
    assert!(!dir.join("ca").join("root-ca.pem").exists());
    assert_eq!(proxy.outbound_connect_attempts(), 0);
}

#[tokio::test]
async fn ca_removal_disables_interception_until_explicit_generate() {
    let (proxy, _storage, dir, proxy_port) = setup_test_proxy(&["localhost"], vec![]).await;
    let pem1 = proxy.https_status().unwrap().cert_pem.unwrap();
    let (stream, head) = connect_head(proxy_port, "localhost:443").await;
    assert!(head.starts_with("HTTP/1.1 200 Connection Established"));
    handshake_trusting(stream, &pem1).await.expect("interception with the generated CA");

    // Remove: interception fails closed and nothing is regenerated behind the user's back.
    proxy.remove_ca().await.unwrap();
    for _ in 0..2 {
        let (_stream, head) = connect_head(proxy_port, "localhost:443").await;
        assert!(head.starts_with("HTTP/1.1 502 Bad Gateway"), "Expected 502 after removal, got: {head}");
    }
    assert!(!proxy.https_status().unwrap().present, "Removal must stick until Generate");
    assert!(!dir.join("ca").join("root-ca.pem").exists());

    // Explicit Generate: interception works again, with a new CA the old trust does not cover.
    proxy.load_or_generate_ca().await.unwrap();
    let status = proxy.https_status().unwrap();
    let pem2 = status.cert_pem.unwrap();
    assert_ne!(pem1, pem2, "a new CA, not the removed one");
    let (stream, head) = connect_head(proxy_port, "localhost:443").await;
    assert!(head.starts_with("HTTP/1.1 200 Connection Established"));
    handshake_trusting(stream, &pem2).await.expect("interception with the new CA");
    let (stream, _) = connect_head(proxy_port, "localhost:443").await;
    assert!(handshake_trusting(stream, &pem1).await.is_err(), "the removed CA must not sign anything");
}
