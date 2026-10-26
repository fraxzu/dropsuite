//! A challenge page must not be scanned as if it were the application.

use std::time::Duration;

use dropsuite_core::active_scan::{scan, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split(' ').nth(1).unwrap_or("/").to_string();
                let path = target.split('?').next().unwrap_or("/");
                let resp = match path {
                    "/challenge" => concat!(
                        "HTTP/1.1 403 Forbidden\r\n",
                        "Server: cloudflare\r\n",
                        "cf-mitigated: challenge\r\n",
                        "Content-Type: text/html\r\n",
                        "Content-Length: 31\r\n\r\n",
                        "<title>Just a moment...</title>"
                    )
                    .to_string(),
                    "/akamai" => concat!(
                        "HTTP/1.1 403 Forbidden\r\n",
                        "Content-Type: text/html\r\n",
                        "Content-Length: 31\r\n\r\n",
                        "Access Denied Reference #18.abc"
                    )
                    .to_string(),
                    _ => concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/html\r\n",
                        "Content-Length: 12\r\n\r\n",
                        "<p>hello</p>"
                    )
                    .to_string(),
                };
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
        max_requests: 40,
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
async fn a_challenge_page_is_skipped_with_the_vendor_named() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/challenge?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    assert!(report.skipped_waf);
    assert_eq!(report.waf_vendor.as_deref(), Some("Cloudflare"));
    assert!(
        report.findings.is_empty(),
        "nothing on the page is the app's"
    );
    assert_eq!(report.requests, 1, "only the baseline was sent");
}

#[tokio::test]
async fn a_hard_block_is_reported_as_blocked() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/akamai?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    eprintln!(
        "DBG stopped={:?} vendor={:?} req={}",
        report.stopped, report.waf_vendor, report.requests
    );
    assert!(report.blocked_by_waf);
    eprintln!(
        "DBG stopped={:?} vendor={:?} req={}",
        report.stopped, report.waf_vendor, report.requests
    );
    assert_eq!(report.waf_vendor.as_deref(), Some("Akamai"));
    assert_eq!(report.requests, 1);
}

#[tokio::test]
async fn infrastructure_paths_are_skipped_without_a_request() {
    let port = origin().await;
    let report = scan(
        &req(format!(
            "http://127.0.0.1:{port}/cdn-cgi/challenge-platform/h/b?q=1"
        )),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    assert!(report.skipped_infrastructure);
    assert_eq!(report.requests, 0);
}

#[tokio::test]
async fn a_normal_page_is_scanned() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/page?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    assert!(!report.skipped_waf && !report.blocked_by_waf && !report.skipped_infrastructure);
    assert!(report.requests > 1);
}
