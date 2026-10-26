//! Active scan behaviour against a local origin that reflects, errors, serves files and redirects.

use std::time::Duration;

use dropsuite_core::active_scan::{
    insertion_points, scan, CheckKind, Confidence, Point, ScanOptions, StopReason,
};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Percent-decode like a real server does before routing.
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
                    "/echo" => (200, String::new(), format!("<p>{}</p>", param("q"))),
                    "/enc" => {
                        let v = param("q").replace('<', "&lt;").replace('>', "&gt;");
                        (200, String::new(), format!("<p>{v}</p>"))
                    }
                    "/sql" => {
                        let v = param("id");
                        if v.contains('\'') {
                            (
                                200,
                                String::new(),
                                "You have an error in your SQL syntax near '''".to_string(),
                            )
                        } else {
                            (200, String::new(), "ok".to_string())
                        }
                    }
                    "/file" => {
                        let v = param("p");
                        if v.contains("etc/passwd") {
                            (
                                200,
                                String::new(),
                                "root:x:0:0:root:/root:/bin/bash\n".to_string(),
                            )
                        } else {
                            (200, String::new(), "missing".to_string())
                        }
                    }
                    "/go" => (302, format!("Location: {}\r\n", param("u")), String::new()),
                    "/blocked" => (403, String::new(), "Access Denied".to_string()),
                    _ => (200, String::new(), "ok".to_string()),
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\n{extra}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn req(url: String) -> ReplayRequest {
    ReplayRequest {
        method: "GET".into(),
        url,
        headers: Vec::new(),
        body: String::new(),
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

#[test]
fn points_come_from_query_body_and_headers() {
    let mut r = req("https://a.test/p?x=1&__VIEWSTATE=z&y=2".into());
    r.method = "POST".into();
    r.headers = vec![
        (
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        ),
        ("X-Trace".into(), "abc".into()),
        ("Cookie".into(), "sid=1".into()),
    ];
    r.body = "a=1&b=2".into();
    let points = insertion_points(&r);
    assert_eq!(
        points,
        vec![
            Point::Query("x".into()),
            Point::Query("y".into()),
            Point::Body("a".into()),
            Point::Body("b".into()),
            Point::Header("X-Trace".into()),
        ]
    );
}

#[tokio::test]
async fn unencoded_reflection_is_high_confidence() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/echo?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::ReflectedXss)
        .expect("reflection must be reported");
    eprintln!("EVIDENCE: {} | payload: {}", hit.evidence, hit.payload);
    assert_eq!(hit.confidence, Confidence::High);
    eprintln!("EVIDENCE: {} | payload: {}", hit.evidence, hit.payload);
    assert_eq!(hit.point, "query:q");
    assert!(hit.evidence.contains("metacharacters intact"));
}

#[tokio::test]
async fn fully_encoded_reflection_is_info() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/enc?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::ReflectedXss)
        .expect("encoded reflection is still a finding");
    assert_eq!(hit.confidence, Confidence::Info);
}

#[tokio::test]
async fn sql_error_is_reported_with_evidence() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/sql?id=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::SqlError)
        .expect("sql error must be reported");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.evidence.to_ascii_lowercase().contains("sql syntax"));
}

#[tokio::test]
async fn traversal_is_reported_only_when_the_file_comes_back() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/file?p=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::PathTraversal)
        .expect("passwd content must be reported");
    assert!(hit.evidence.contains("passwd content returned"));
}

#[tokio::test]
async fn redirect_to_another_host_is_reported() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/go?u=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    let hit = report
        .findings
        .iter()
        .find(|f| f.kind == CheckKind::OpenRedirect)
        .expect("cross-host redirect must be reported");
    assert!(hit.evidence.contains("evil.com"));
}

#[tokio::test]
async fn a_blocking_target_stops_the_run_early() {
    let port = origin().await;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/blocked?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    assert_eq!(report.stopped, Some(StopReason::Blocked));
    assert!(
        report.requests < 10,
        "must not keep hammering: {}",
        report.requests
    );
}

#[tokio::test]
async fn budget_is_respected() {
    let port = origin().await;
    let mut o = fast();
    o.max_requests = 3;
    let report = scan(
        &req(format!("http://127.0.0.1:{port}/echo?q=1")),
        &ApplyConfig::default(),
        &opts(),
        &o,
    )
    .await;
    assert!(report.requests <= 3);
    assert_eq!(report.stopped, Some(StopReason::Budget));
}

#[tokio::test]
async fn a_url_without_points_reports_nothing() {
    let report = scan(
        &req("http://127.0.0.1:1/".into()),
        &ApplyConfig::default(),
        &opts(),
        &fast(),
    )
    .await;
    assert_eq!(report.points, 0);
    assert!(report.findings.is_empty());
}
