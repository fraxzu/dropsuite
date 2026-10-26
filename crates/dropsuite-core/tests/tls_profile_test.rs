//! The ClientHello actually changes shape with the profile. The server side here is a raw TCP
//! socket that only sniffs the first flight, so nothing depends on a completed handshake.

use std::sync::Arc;

use dropsuite_core::tls_profile::{provider, TlsProfile};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// First cipher suite advertised in a ClientHello, or `None` if the bytes are not one.
fn first_cipher_suite(bytes: &[u8]) -> Option<u16> {
    // record header (5) + handshake header (4) + version (2) + random (32)
    let mut i = 5 + 4 + 2 + 32;
    let session_len = *bytes.get(i)? as usize;
    i += 1 + session_len;
    let len = u16::from_be_bytes([*bytes.get(i)?, *bytes.get(i + 1)?]) as usize;
    i += 2;
    if len < 2 || i + 2 > bytes.len() {
        return None;
    }
    Some(u16::from_be_bytes([bytes[i], bytes[i + 1]]))
}

async fn offer(profile: TlsProfile) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let config = rustls::ClientConfig::builder_with_provider(provider(profile))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let sniff = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        first_cipher_suite(&buf[..n]).expect("a ClientHello was sent")
    });

    // Verification fails (empty root store); the ClientHello has already been written.
    let _ = connector
        .connect(
            "example.test".try_into().unwrap(),
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap(),
        )
        .await;
    sniff.await.unwrap()
}

#[tokio::test]
async fn chromium_starts_with_aes_128() {
    assert_eq!(offer(TlsProfile::Chromium).await, 0x1301);
}

#[tokio::test]
async fn rustls_default_starts_with_aes_256() {
    assert_eq!(offer(TlsProfile::Off).await, 0x1302);
}

#[tokio::test]
async fn firefox_starts_with_aes_128_and_differs_from_default() {
    let firefox = offer(TlsProfile::Firefox).await;
    assert_eq!(firefox, 0x1301);
    assert_ne!(firefox, offer(TlsProfile::Off).await);
}
