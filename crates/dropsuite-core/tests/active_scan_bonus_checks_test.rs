//! Dedicated test suite for active scanner bonus checks (TAHAP 7):
//! - CORS misconfiguration (with and without credentials)
//! - CRLF injection into headers
//! - Host header injection (X-Forwarded-Host)
//! - HTTP method override

use std::time::Duration;

use dropsuite_core::active_scan::{scan, CheckKind, Confidence, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn bonus_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split(' ').nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));

                let header = |name: &str| -> Option<String> {
                    head.lines().find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        if n.trim().eq_ignore_ascii_case(name) {
                            Some(v.trim().to_string())
                        } else {
                            None
                        }
                    })
                };

                let mut status = 200;
                let mut extra = String::new();
                let mut body = "default".to_string();

                if let Some(origin) = header("origin") {
                    if origin == "https://evil.example" {
                        if path == "/cors-creds" {
                            extra.push_str("Access-Control-Allow-Origin: https://evil.example\r\nAccess-Control-Allow-Credentials: true\r\n");
                        } else if path == "/cors-nocreds" {
                            extra.push_str("Access-Control-Allow-Origin: *\r\n");
                        }
                    }
                }

                if let Some(xfh) = header("x-forwarded-host") {
                    if path == "/host-header" {
                        body = format!("<html><body>Reset password link: https://{xfh}/reset?token=123</body></html>");
                    }
                }

                if let Some(override_m) = header("x-http-method-override") {
                    if path == "/override" && override_m == "DELETE" {
                        status = 204;
                        body = String::new();
                    }
                }

                if path == "/crlf" && query.contains("X-Injected") {
                    extra.push_str("X-Injected: 1\r\n");
                }

                let resp = format!(
                    "HTTP/1.1 {status} OK\r\n{extra}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn opts() -> ReplayOptions {
    ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: Vec::new(),
        apply: ApplyConfig::default(),
    }
}

fn fast() -> ScanOptions {
    ScanOptions {
        delay: Duration::ZERO,
        max_requests: 60,
        stop_after_blocks: 3,
        backoff: false,
    }
}

fn req(url: String) -> ReplayRequest {
    ReplayRequest {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: String::new(),
    }
}

#[tokio::test]
async fn cors_with_credentials_flagged_as_high_confidence() {
    let port = bonus_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/cors-creds?x=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::CorsMisconfig)
        .expect("cors misconfig must be detected");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.contains("ACAC: true"));
}

#[tokio::test]
async fn cors_without_credentials_flagged_as_medium_confidence() {
    let port = bonus_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/cors-nocreds?x=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::CorsMisconfig)
        .expect("cors misconfig must be detected");
    assert_eq!(hit.confidence, Confidence::Medium);
}

#[tokio::test]
async fn crlf_injection_flagged_as_high_confidence() {
    let port = bonus_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/crlf?param=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::CrlfInjection)
        .expect("crlf injection must be detected");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.contains("X-Injected: 1"));
}

#[tokio::test]
async fn host_header_injection_detected() {
    let port = bonus_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/host-header?q=test")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::HostHeaderInjection)
        .expect("host header injection must be detected");
    assert_eq!(hit.confidence, Confidence::Medium);
    assert!(hit.evidence.contains("X-Forwarded-Host reflected"));
}

#[tokio::test]
async fn method_override_detected_on_differing_response() {
    let port = bonus_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/override?item=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::MethodOverride)
        .expect("method override must be detected");
    assert_eq!(hit.confidence, Confidence::Medium);
    assert_eq!(hit.status, 204);
}
