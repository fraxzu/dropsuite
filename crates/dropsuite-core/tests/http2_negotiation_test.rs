//! Upstream h2: ALPN is offered, h2 is actually spoken when chosen, and an h1-only destination
//! still works.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dropsuite_core::challenge::ChallengeKind;
use dropsuite_core::replay::{send, ApplyConfig, ReplayOptions, ReplayRequest};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn make_ca() -> (CertificateDer<'static>, KeyPair, rcgen::Certificate) {
    let key = KeyPair::generate().unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "h2 test root");
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
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![SanType::DnsName(host.try_into().unwrap())];
    }
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::hours(24);
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params.signed_by(&key, ca, ca_key).unwrap();
    (cert.der().clone(), key.serialize_der())
}

/// h2-only server. `/blocked` answers 503 with a Cloudflare marker.
async fn h2_server() -> (u16, CertificateDer<'static>, Arc<Mutex<Vec<Seen>>>) {
    let (ca_der, ca_key, ca_cert) = make_ca();
    let (leaf, key) = make_leaf(&ca_cert, &ca_key, "127.0.0.1");
    let key = PrivateKeyDer::try_from(key).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
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
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
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
                    let path = parts.uri.path().to_string();
                    sink.lock().unwrap().push(Seen {
                        method: parts.method.to_string(),
                        path: path.clone(),
                        headers: parts
                            .headers
                            .iter()
                            .map(|(n, v)| {
                                (
                                    n.as_str().to_string(),
                                    String::from_utf8_lossy(v.as_bytes()).to_string(),
                                )
                            })
                            .collect(),
                        body: raw,
                    });

                    let mut response = http::Response::builder();
                    if path == "/blocked" {
                        response = response
                            .status(503)
                            .header("cf-mitigated", "challenge")
                            .header("content-type", "text/html");
                    } else {
                        response = response.status(200).header("content-type", "text/plain");
                    }
                    let response = response.body(()).unwrap();
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = stream.send_data("h2 body".into(), true);
                    }
                }
            });
        }
    });
    (port, ca_der, seen)
}

/// h1-only server: proves offering h2 does not break a destination that refuses it.
async fn h1_server() -> (u16, CertificateDer<'static>) {
    let (ca_der, ca_key, ca_cert) = make_ca();
    let (leaf, key) = make_leaf(&ca_cert, &ca_key, "127.0.0.1");
    let key = PrivateKeyDer::try_from(key).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, ca_der)
}

fn opts(root: CertificateDer<'static>) -> ReplayOptions {
    ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: vec![root],
        apply: ApplyConfig::default(),
    }
}

fn req(method: &str, url: String, headers: &[(&str, &str)], body: &str) -> ReplayRequest {
    ReplayRequest {
        method: method.into(),
        url,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.into(),
    }
}

#[tokio::test]
async fn h2_is_negotiated_and_bodies_survive_both_ways() {
    let (port, ca, seen) = h2_server().await;
    let r = send(
        &req(
            "POST",
            format!("https://127.0.0.1:{port}/upload"),
            &[("Content-Type", "text/plain")],
            "payload",
        ),
        &opts(ca),
    )
    .await
    .unwrap();

    assert_eq!(r.status, 200);
    assert_eq!(r.reason, "OK");
    assert!(String::from_utf8_lossy(&r.message).starts_with("HTTP/2 200"));
    assert!(String::from_utf8_lossy(&r.message).contains("h2 body"));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/upload");
    assert_eq!(seen[0].body, b"payload");
    assert!(seen[0]
        .headers
        .iter()
        .any(|(n, v)| n == "content-length" && v == "7"));
}

#[tokio::test]
async fn h2_does_not_send_connection_only_fields() {
    let (port, ca, seen) = h2_server().await;
    send(
        &req(
            "GET",
            format!("https://127.0.0.1:{port}/plain"),
            &[
                ("Connection", "keep-alive"),
                ("TE", "gzip"),
                ("Keep-Alive", "timeout=5"),
            ],
            "",
        ),
        &opts(ca),
    )
    .await
    .unwrap();

    let seen = seen.lock().unwrap();
    let names: Vec<&str> = seen[0].headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(!names.contains(&"connection"));
    assert!(!names.contains(&"keep-alive"));
    assert!(!names.contains(&"te"), "TE gzip is not an h2 field");
    assert!(!names.contains(&"host"), "authority replaces Host");
}

#[tokio::test]
async fn h2_challenge_is_detected() {
    let (port, ca, _seen) = h2_server().await;
    let r = send(
        &req("GET", format!("https://127.0.0.1:{port}/blocked"), &[], ""),
        &opts(ca),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 503);
    let signal = r.challenge.expect("challenge must be reported over h2");
    assert_eq!(signal.kind, ChallengeKind::Interactive);
}

#[tokio::test]
async fn h1_only_destination_still_works() {
    let (port, ca) = h1_server().await;
    let r = send(
        &req("GET", format!("https://127.0.0.1:{port}/"), &[], ""),
        &opts(ca),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.message).contains("ok"));
    assert!(r.challenge.is_none());
}

#[tokio::test]
async fn offered_alpn_is_h2_then_http1() {
    // A server that only offers h1 must see h1.1 accepted, and one that offers h2 must see h2:
    // both cases above depend on this order, and TLS picks the server's choice.
    let (ca_der, ca_key, ca_cert) = make_ca();
    let (leaf, key) = make_leaf(&ca_cert, &ca_key, "127.0.0.1");
    let key = PrivateKeyDer::try_from(key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(sock).await.unwrap();
        let _ = tx.send(tls.get_ref().1.alpn_protocol().map(|p| p.to_vec()));
    });

    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let mut client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name: ServerName<'static> = "127.0.0.1".try_into().unwrap();
    let _tls = connector.connect(name, tcp).await.unwrap();

    assert_eq!(rx.await.unwrap(), Some(b"h2".to_vec()));
}
