//! Dedicated test suite for active scanner SQL injection detection:
//! - Boolean-based differential analysis
//! - Time-based confirmation
//! - Error-based with database engine fingerprinting

use std::time::Duration;

use dropsuite_core::active_scan::{scan, CheckKind, Confidence, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn sqli_origin() -> u16 {
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

                let param = |name: &str| -> String {
                    query
                        .split('&')
                        .find_map(|p| {
                            p.split_once('=')
                                .filter(|(k, _)| *k == name)
                                .map(|(_, v)| decode(v))
                        })
                        .unwrap_or_default()
                };

                let (status, body) = match path {
                    "/bool" => {
                        let id = param("id");
                        if id.contains("1' AND '1'='1") {
                            (200, "<html><body><h1>User Account: Alice</h1><p>Full Profile data here with lots of content...</p></body></html>".to_string())
                        } else if id.contains("1' AND '1'='2") {
                            (
                                200,
                                "<html><body><h1>User Not Found</h1></body></html>".to_string(),
                            )
                        } else {
                            (200, "<html><body><h1>User Account: Alice</h1><p>Normal view</p></body></html>".to_string())
                        }
                    }
                    "/error-pg" => {
                        let id = param("id");
                        if id.contains('\'') {
                            (500, "ERROR: syntax error at or near \"'\" at character 42\nSTATEMENT: SELECT * FROM users WHERE id = '".to_string())
                        } else {
                            (200, "ok".to_string())
                        }
                    }
                    "/error-mysql" => {
                        let id = param("id");
                        if id.contains('\'') {
                            (500, "Fatal error: You have an error in your SQL syntax near ''' at line 1".to_string())
                        } else {
                            (200, "ok".to_string())
                        }
                    }
                    "/time" => {
                        let id = param("id");
                        if id.contains("SLEEP(3)") {
                            tokio::time::sleep(Duration::from_millis(2600)).await;
                        }
                        (200, "done".to_string())
                    }
                    _ => (200, "default".to_string()),
                };

                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn opts() -> ReplayOptions {
    ReplayOptions {
        connect_timeout: Duration::from_secs(10),
        response_timeout: Duration::from_secs(10),
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
async fn boolean_based_sqli_detected_with_high_confidence() {
    let port = sqli_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/bool?id=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::SqlBoolean)
        .expect("boolean sqli must be detected");
    assert_eq!(finding.confidence, Confidence::High);
    assert!(finding.evidence.contains("differing responses"));
}

#[tokio::test]
async fn postgres_error_fingerprint_identified() {
    let port = sqli_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/error-pg?id=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::SqlError)
        .expect("postgres error sqli must be detected");
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.db_type.as_deref(), Some("postgresql"));
}

#[tokio::test]
async fn mysql_error_fingerprint_identified() {
    let port = sqli_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/error-mysql?id=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::SqlError)
        .expect("mysql error sqli must be detected");
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.db_type.as_deref(), Some("mysql"));
}

#[tokio::test]
async fn time_based_sqli_detected_when_no_error_or_boolean() {
    let port = sqli_origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/time?id=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::SqlTime)
        .expect("time based sqli must be detected");
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.db_type.as_deref(), Some("mysql"));
    assert!(finding.evidence.contains("sleep median"));
}
