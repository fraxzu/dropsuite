//! Context-aware reflection: the same marker means different things in different places.

use std::time::Duration;

use dropsuite_core::active_scan::{scan, CheckKind, Confidence, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn origin() -> u16 {
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
                let raw = query
                    .split('&')
                    .find_map(|p| {
                        p.split_once('=')
                            .filter(|(k, _)| *k == "q")
                            .map(|(_, v)| v.to_string())
                    })
                    .unwrap_or_default();
                let value = decode(&raw);
                let (ctype, body) = match path {
                    "/json" => ("application/json", format!("{{\"q\":\"{value}\"}}")),
                    "/attr" => ("text/html", format!("<input value=\"{value}\">")),
                    "/attr-enc" => (
                        "text/html",
                        format!(
                            "<input value=\"{}\">",
                            value.replace('"', "&quot;").replace('<', "&lt;")
                        ),
                    ),
                    "/script" => ("text/html", format!("<script>var a = '{value}';</script>")),
                    "/encode" => (
                        "text/html",
                        format!("<p>{}</p>", value.replace('<', "&lt;").replace('>', "&gt;")),
                    ),
                    _ => ("text/html", format!("<p>{value}</p>")),
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
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
        max_requests: 80,
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

async fn run(path: &str, port: u16) -> dropsuite_core::active_scan::ScanReport {
    scan(
        &req(format!("http://127.0.0.1:{port}{path}?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await
}

fn xss(report: &dropsuite_core::active_scan::ScanReport) -> Option<&dropsuite_core::ActiveFinding> {
    report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::ReflectedXss)
}

#[tokio::test]
async fn non_html_baseline_skips_reflection_checks() {
    let port = origin().await;
    let report = run("/json", port).await;
    assert!(report.skipped_non_html);
    assert!(xss(&report).is_none(), "JSON cannot execute markup");
}

#[tokio::test]
async fn attribute_context_is_medium() {
    let port = origin().await;
    let report = run("/attr", port).await;
    let hit = xss(&report).expect("reflection reported");
    assert_eq!(hit.confidence, Confidence::Medium);
    assert_eq!(hit.context.as_deref(), Some("double-quoted attribute"));
}

#[tokio::test]
async fn script_string_context_is_medium() {
    let port = origin().await;
    let report = run("/script", port).await;
    let hit = xss(&report).expect("reflection reported");
    assert_eq!(hit.confidence, Confidence::Medium);
    assert_eq!(hit.context.as_deref(), Some("script string"));
}

#[tokio::test]
async fn fully_encoded_reflection_is_info() {
    let port = origin().await;
    let report = run("/encode", port).await;
    let hit = xss(&report).expect("still logged");
    assert_eq!(hit.confidence, Confidence::Info);
}

#[tokio::test]
async fn a_breakout_that_does_not_survive_downgrades() {
    let port = origin().await;
    let report = run("/attr-enc", port).await;
    let hit = xss(&report).expect("reflection reported");
    // Quotes are encoded, so the breakout payload cannot escape the attribute.
    assert!(
        hit.confidence <= Confidence::Low,
        "got {:?}",
        hit.confidence
    );
    assert!(hit.evidence.contains("breakout not reflected"));
}
