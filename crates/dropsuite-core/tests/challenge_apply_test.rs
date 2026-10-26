//! Preset, jar and challenge behaviour, exercised through the real send path against a local
//! fixture that records exactly what arrived.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dropsuite_core::challenge::{ChallengeKind, ChallengeVendor};
use dropsuite_core::cookies::StoredCookie;
use dropsuite_core::header_preset::BrowserPreset;
use dropsuite_core::replay::{send, ApplyConfig, ReplayOptions, ReplayRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Seen {
    head: String,
}

/// Serves `/blocked` as a Cloudflare-style challenge and everything else as 200.
async fn fixture() -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move { serve(sock, sink).await });
        }
    });
    (port, seen)
}

async fn serve(mut sock: TcpStream, sink: Arc<Mutex<Vec<Seen>>>) {
    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
    sink.lock().unwrap().push(Seen { head });

    let resp = if path == "/blocked" {
        let body = "<title>Just a moment...</title><script src=\"/cdn-cgi/challenge-platform/h/b\"></script>";
        format!(
            "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\ncf-mitigated: challenge\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok".to_string()
    };
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.shutdown().await;
}

fn opts(apply: ApplyConfig) -> ReplayOptions {
    ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: Vec::new(),
        apply,
    }
}

fn req(url: String, headers: &[(&str, &str)]) -> ReplayRequest {
    ReplayRequest {
        method: "GET".into(),
        url,
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: String::new(),
    }
}

fn cookie(name: &str, value: &str, path: &str, secure: bool) -> StoredCookie {
    StoredCookie {
        domain: None,
        host: "127.0.0.1".into(),
        name: name.into(),
        value: value.into(),
        path: path.into(),
        secure,
        http_only: true,
        expires_at: None,
        created_at: 1_700_000_000,
    }
}

fn header_line<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[tokio::test]
async fn preset_fills_missing_browser_headers() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        preset: BrowserPreset::Chrome,
        ..Default::default()
    };
    send(&req(format!("http://127.0.0.1:{port}/"), &[]), &opts(apply))
        .await
        .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    let ua = header_line(&head, "user-agent").expect("preset must add a User-Agent");
    assert!(ua.contains("Chrome/131"));
    assert!(header_line(&head, "sec-ch-ua")
        .unwrap()
        .contains("Google Chrome"));
    assert_eq!(header_line(&head, "sec-fetch-dest"), Some("document"));
    assert_eq!(
        header_line(&head, "accept-language"),
        Some("en-US,en;q=0.9")
    );
}

#[tokio::test]
async fn explicit_headers_survive_the_preset() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        preset: BrowserPreset::Chrome,
        ..Default::default()
    };
    send(
        &req(
            format!("http://127.0.0.1:{port}/"),
            &[
                ("User-Agent", "MyAgent/1.0"),
                ("Accept", "application/json"),
            ],
        ),
        &opts(apply),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    assert_eq!(header_line(&head, "user-agent"), Some("MyAgent/1.0"));
    assert_eq!(header_line(&head, "accept"), Some("application/json"));
    let ua_lines = head
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("user-agent:"))
        .count();
    assert_eq!(ua_lines, 1, "no duplicate User-Agent");
    assert!(
        header_line(&head, "sec-ch-ua").is_some(),
        "other preset fields still fill"
    );
}

#[tokio::test]
async fn off_preset_leaves_the_request_alone() {
    let (port, seen) = fixture().await;
    send(
        &req(format!("http://127.0.0.1:{port}/plain"), &[]),
        &opts(ApplyConfig::default()),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    assert_eq!(
        head,
        format!("GET /plain HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
    );
}

#[tokio::test]
async fn jar_cookies_are_attached_when_they_match() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        attach_cookies: true,
        cookies: vec![
            cookie("cf_clearance", "good", "/", false),
            cookie("__Host-sec", "skipped-http", "/", true),
            cookie("narrow", "only-under-app", "/app", false),
        ],
        ..Default::default()
    };
    send(
        &req(format!("http://127.0.0.1:{port}/app/x"), &[]),
        &opts(apply),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    let sent = header_line(&head, "cookie").expect("matching cookies must be sent");
    assert!(sent.contains("cf_clearance=good"));
    assert!(sent.contains("narrow=only-under-app"));
    assert!(
        !sent.contains("__Host-sec"),
        "secure cookie must not go over plain HTTP"
    );
}

#[tokio::test]
async fn jar_skips_cookies_for_other_paths() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        attach_cookies: true,
        cookies: vec![cookie("narrow", "1", "/app", false)],
        ..Default::default()
    };
    send(
        &req(format!("http://127.0.0.1:{port}/elsewhere"), &[]),
        &opts(apply),
    )
    .await
    .unwrap();
    assert!(header_line(&seen.lock().unwrap()[0].head, "cookie").is_none());
}

#[tokio::test]
async fn jar_replaces_a_stale_value_and_keeps_other_names() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        attach_cookies: true,
        cookies: vec![cookie("from", "jar", "/", false)],
        ..Default::default()
    };
    let r = send(
        &req(
            format!("http://127.0.0.1:{port}/"),
            &[("Cookie", "from=stale; keep=me")],
        ),
        &opts(apply),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    let sent = header_line(&head, "cookie").unwrap();
    assert!(
        sent.contains("from=jar"),
        "the jar holds the current value: {sent}"
    );
    assert!(!sent.contains("from=stale"));
    assert!(sent.contains("keep=me"), "unrelated names survive: {sent}");
    assert_eq!(r.cookies_attached, 1);
    assert_eq!(
        head.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("cookie:"))
            .count(),
        1
    );
}

#[tokio::test]
async fn jar_off_keeps_the_request_cookie_untouched() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        attach_cookies: false,
        cookies: vec![cookie("from", "jar", "/", false)],
        ..Default::default()
    };
    let r = send(
        &req(
            format!("http://127.0.0.1:{port}/"),
            &[("Cookie", "from=stale")],
        ),
        &opts(apply),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    assert_eq!(header_line(&head, "cookie"), Some("from=stale"));
    assert_eq!(r.cookies_attached, 0);
}

#[tokio::test]
async fn attach_disabled_sends_no_cookie() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        cookies: vec![cookie("a", "1", "/", false)],
        ..Default::default()
    };
    send(&req(format!("http://127.0.0.1:{port}/"), &[]), &opts(apply))
        .await
        .unwrap();
    assert!(header_line(&seen.lock().unwrap()[0].head, "cookie").is_none());
}

#[tokio::test]
async fn challenge_is_reported_with_vendor_and_kind() {
    let (port, _seen) = fixture().await;
    let r = send(
        &req(format!("http://127.0.0.1:{port}/blocked"), &[]),
        &opts(ApplyConfig::default()),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 403);
    let signal = r.challenge.expect("a challenge must be reported");
    assert_eq!(signal.vendor, ChallengeVendor::Cloudflare);
    assert_eq!(signal.kind, ChallengeKind::Interactive);
    assert!(signal.evidence.contains("cf-mitigated"));
}

#[tokio::test]
async fn ordinary_response_has_no_challenge() {
    let (port, _seen) = fixture().await;
    let r = send(
        &req(format!("http://127.0.0.1:{port}/fine"), &[]),
        &opts(ApplyConfig::default()),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    assert!(r.challenge.is_none());
}

#[tokio::test]
async fn preset_and_jar_are_transparent_to_the_snapshot() {
    let (port, _seen) = fixture().await;
    let apply = ApplyConfig {
        preset: BrowserPreset::Chrome,
        attach_cookies: true,
        cookies: vec![cookie("cf_clearance", "abc", "/", false)],
        ..Default::default()
    };
    let r = send(&req(format!("http://127.0.0.1:{port}/"), &[]), &opts(apply))
        .await
        .unwrap();

    // The snapshot is what history would keep, so injected fields must be visible there too.
    // Cookie values are redacted there while names survive, so only the name is asserted.
    assert!(r
        .request_headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("user-agent")));
    assert!(r
        .request_headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("cookie") && v.contains("cf_clearance")));
    assert!(r.sent_bytes > 0);
}

#[tokio::test]
async fn attached_cookie_count_is_reported() {
    let (port, _seen) = fixture().await;
    let apply = ApplyConfig {
        attach_cookies: true,
        cookies: vec![cookie("a", "1", "/", false), cookie("b", "2", "/", false)],
        ..Default::default()
    };
    let r = send(&req(format!("http://127.0.0.1:{port}/"), &[]), &opts(apply))
        .await
        .unwrap();
    assert_eq!(r.cookies_attached, 2);
}

#[tokio::test]
async fn forced_preset_replaces_browser_fields_without_duplicates() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        preset: BrowserPreset::Edge,
        force_preset: true,
        ..Default::default()
    };
    send(
        &req(
            format!("http://127.0.0.1:{port}/"),
            &[
                ("User-Agent", "DropSuite/0.1"),
                ("Accept", "*/*"),
                ("X-Keep", "yes"),
            ],
        ),
        &opts(apply),
    )
    .await
    .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    let ua = header_line(&head, "user-agent").unwrap();
    assert!(
        ua.contains("Edg/"),
        "preset UA replaces the placeholder: {ua}"
    );
    assert!(!head.contains("DropSuite/0.1"));
    assert!(header_line(&head, "accept").unwrap().contains("text/html"));
    assert_eq!(
        header_line(&head, "x-keep"),
        Some("yes"),
        "unrelated fields survive"
    );
    assert_eq!(
        head.lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("user-agent:"))
            .count(),
        1
    );
}

#[tokio::test]
async fn pinned_user_agent_wins_and_hints_follow_it() {
    let (port, seen) = fixture().await;
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
    let apply = ApplyConfig {
        preset: BrowserPreset::Edge,
        force_preset: true,
        pin_user_agent: Some(ua.to_string()),
        ..Default::default()
    };
    send(&req(format!("http://127.0.0.1:{port}/"), &[]), &opts(apply))
        .await
        .unwrap();

    let head = seen.lock().unwrap()[0].head.clone();
    assert_eq!(header_line(&head, "user-agent"), Some(ua));
    let hints = header_line(&head, "sec-ch-ua").unwrap();
    assert!(
        hints.contains("Microsoft Edge\";v=\"141"),
        "hint version follows the pinned UA: {hints}"
    );
}

#[tokio::test]
async fn without_force_the_request_headers_are_kept() {
    let (port, seen) = fixture().await;
    let apply = ApplyConfig {
        preset: BrowserPreset::Edge,
        ..Default::default()
    };
    send(
        &req(
            format!("http://127.0.0.1:{port}/"),
            &[("User-Agent", "Mine/1")],
        ),
        &opts(apply),
    )
    .await
    .unwrap();
    assert_eq!(
        header_line(&seen.lock().unwrap()[0].head, "user-agent"),
        Some("Mine/1")
    );
}
