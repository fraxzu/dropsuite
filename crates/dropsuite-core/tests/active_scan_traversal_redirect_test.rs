//! Dedicated test suite for active scanner Path Traversal and Open Redirect:
//! - Priority parameter budgeting
//! - Windows win.ini and Linux /etc/passwd signatures
//! - Open redirect bypass techniques
//! - Open redirect to XSS chain escalation (javascript: / data: in Location)

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dropsuite_core::active_scan::{scan, CheckKind, Confidence, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default, Clone)]
struct ProbeLog {
    queries: Vec<String>,
}

async fn test_origin(log: Arc<Mutex<ProbeLog>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split(' ').nth(1).unwrap_or("/").to_string();
                let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));

                log.lock().unwrap().queries.push(query.to_string());

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

                let (status, extra, body) = match path {
                    "/win" => {
                        let f = param("file");
                        if f.contains(r"windows\win.ini") || f.contains("win.ini") {
                            (200, String::new(), "; for 16-bit app support\n[fonts]\nArial=arial.ttf\n[extensions]\n".to_string())
                        } else {
                            (404, String::new(), "file not found".to_string())
                        }
                    }
                    "/linux" => {
                        let f = param("path");
                        if f.contains("etc/passwd") {
                            (200, String::new(), "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n".to_string())
                        } else {
                            (404, String::new(), "file not found".to_string())
                        }
                    }
                    "/redir" => {
                        let u = param("url");
                        (302, format!("Location: {u}\r\n"), String::new())
                    }
                    _ => (200, String::new(), "ok".to_string()),
                };

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
        max_requests: 100,
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
async fn windows_win_ini_traversal_detected() {
    let log = Arc::new(Mutex::new(ProbeLog::default()));
    let port = test_origin(log).await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/win?file=test")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::PathTraversal)
        .expect("win.ini traversal must be detected");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.contains("win.ini"));
}

#[tokio::test]
async fn linux_etc_passwd_traversal_detected() {
    let log = Arc::new(Mutex::new(ProbeLog::default()));
    let port = test_origin(log).await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/linux?path=test")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::PathTraversal)
        .expect("passwd traversal must be detected");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.contains("passwd"));
}

#[tokio::test]
async fn open_redirect_to_xss_chain_detected_with_high_confidence() {
    let log = Arc::new(Mutex::new(ProbeLog::default()));
    let port = test_origin(log).await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/redir?url=normal")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::OpenRedirectXss)
        .expect("javascript/data redirect to XSS must be detected");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.contains("Location scheme executable"));
}

#[tokio::test]
async fn non_priority_parameter_tests_only_capped_payloads() {
    let log = Arc::new(Mutex::new(ProbeLog::default()));
    let port = test_origin(log.clone()).await;
    let _ = scan(
        &req(format!(
            "http://127.0.0.1:{port}/test?random_unimportant_param=xyz"
        )),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;

    let queries = log.lock().unwrap().queries.clone();
    let traversal_probes = queries
        .iter()
        .filter(|q| q.contains("passwd") || q.contains("win.ini") || q.contains("hostname"))
        .count();

    // Should only be 3 payloads for non-priority parameters
    assert_eq!(
        traversal_probes, 3,
        "Non-priority params should only test 3 traversal payloads"
    );
}
