//! P2 M1: Replay sends exactly one request per call to a localhost fixture and reads the whole
//! response. The fixture records every connection and the raw bytes it received.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dropsuite_core::replay::{send, send_with, NetworkSeams, ReplayOptions, ReplayRequest};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MB5: usize = 5 * 1024 * 1024;

fn sha(d: &[u8]) -> String {
    Sha256::digest(d)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn text(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| b"abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + i / 13) % 36])
        .collect()
}

#[derive(Default)]
struct Log {
    connections: usize,
    requests: Vec<Vec<u8>>,
}

async fn fixture() -> (u16, Arc<Mutex<Log>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Log::default()));
    let shared = log.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            shared.lock().unwrap().connections += 1;
            tokio::spawn(serve(sock, shared.clone()));
        }
    });
    (port, log)
}

async fn serve(mut sock: TcpStream, log: Arc<Mutex<Log>>) {
    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 65536];
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
    let cl: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    while buf.len() < head_end + cl {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    log.lock().unwrap().requests.push(buf.clone());
    let path = head
        .split(' ')
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap()
        .to_string();
    let body = &buf[head_end..head_end + cl];
    let ok = |ct: &str, b: Vec<u8>| {
        [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n",
                b.len()
            )
            .into_bytes(),
            b,
        ]
        .concat()
    };
    let resp: Vec<u8> = match path.as_str() {
        "/echo" => ok("application/json", format!("{{\"len\":{},\"sha256\":\"{}\"}}", body.len(), sha(body)).into_bytes()),
        "/status/400" => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\n\r\nbad".to_vec(),
        "/status/404" => b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope".to_vec(),
        "/status/500" => b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\noops".to_vec(),
        "/redirect" => b"HTTP/1.1 302 Found\r\nLocation: /echo\r\nContent-Length: 0\r\n\r\n".to_vec(),
        "/chunked" => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=1\r\n world\r\n0\r\nX-T: 1\r\n\r\n".to_vec(),
        "/big" => ok("text/plain", text(MB5)),
        "/token" => {
            let b = b"{\"user\":\"synthetic\",\"access_token\":\"DSMARKREPLAYTOKEN\"}".to_vec();
            [format!("HTTP/1.1 200 OK\r\nSet-Cookie: s=DSMARKREPLAYCOOKIE; HttpOnly\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", b.len()).into_bytes(), b].concat()
        }
        "/hang" => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            return;
        }
        "/drop" => return,
        _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
    };
    let _ = sock.write_all(&resp).await;
    let _ = sock.shutdown().await;
}

fn opts() -> ReplayOptions {
    ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: Vec::new(),
        apply: dropsuite_core::replay::ApplyConfig::default(),
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

fn body_of(message: &[u8]) -> &[u8] {
    let p = message.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    &message[p + 4..]
}

#[tokio::test]
async fn get_post_and_edited_requests_arrive_exactly() {
    let (port, log) = fixture().await;
    let base = format!("http://127.0.0.1:{port}");
    let r = send(&req("GET", format!("{base}/echo?q=1"), &[], ""), &opts())
        .await
        .unwrap();
    assert_eq!((r.status, r.reason.as_str()), (200, "OK"));
    assert_eq!(
        String::from_utf8_lossy(&log.lock().unwrap().requests[0]),
        format!("GET /echo?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
    );

    let json = "{\"user\":\"synthetic\",\"note\":\"caf\u{e9}\"}";
    let r = send(
        &req(
            "POST",
            format!("{base}/echo"),
            &[("Content-Type", "application/json")],
            json,
        ),
        &opts(),
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(body_of(&r.message)),
        format!(
            "{{\"len\":{},\"sha256\":\"{}\"}}",
            json.len(),
            sha(json.as_bytes())
        )
    );
    // Edited header and body, sent again.
    let edited = "{\"user\":\"synthetic-2\"}";
    send(
        &req(
            "PATCH",
            format!("{base}/echo"),
            &[("Content-Type", "application/json"), ("X-Edited", "yes")],
            edited,
        ),
        &opts(),
    )
    .await
    .unwrap();
    let last = String::from_utf8(log.lock().unwrap().requests.last().unwrap().clone()).unwrap();
    assert_eq!(last, format!("PATCH /echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nX-Edited: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{edited}", edited.len()));
    assert_eq!(
        log.lock().unwrap().connections,
        3,
        "one connection per send"
    );
}

#[tokio::test]
async fn error_statuses_chunked_and_large_responses() {
    let (port, _log) = fixture().await;
    let base = format!("http://127.0.0.1:{port}");
    for (path, code, reason) in [
        ("/status/400", 400, "Bad Request"),
        ("/status/404", 404, "Not Found"),
        ("/status/500", 500, "Internal Server Error"),
    ] {
        let r = send(&req("GET", format!("{base}{path}"), &[], ""), &opts())
            .await
            .unwrap();
        assert_eq!((r.status, r.reason.as_str()), (code, reason));
    }
    let r = send(&req("GET", format!("{base}/chunked"), &[], ""), &opts())
        .await
        .unwrap();
    assert_eq!(
        body_of(&r.message),
        b"b\r\nhello world\r\n0\r\n\r\n",
        "de-chunked body kept as one chunk"
    );
    let r = send(&req("GET", format!("{base}/big"), &[], ""), &opts())
        .await
        .unwrap();
    let body = String::from_utf8_lossy(body_of(&r.message)).to_string();
    assert!(
        body.starts_with(
            "[DropSuite: body not stored] reason=body exceeds the 1024 KB capture limit"
        ),
        "{body}"
    );
    assert!(
        body.contains(&format!("length={MB5} bytes")) && body.contains(&sha(&text(MB5))),
        "full 5 MB received, hash matches"
    );
    assert_eq!(
        r.total_bytes as usize,
        MB5 + format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {MB5}\r\n\r\n"
        )
        .len()
    );
}

#[tokio::test]
async fn no_redirects_and_no_retries() {
    let (port, log) = fixture().await;
    let base = format!("http://127.0.0.1:{port}");
    let r = send(&req("GET", format!("{base}/redirect"), &[], ""), &opts())
        .await
        .unwrap();
    assert_eq!(r.status, 302);
    assert!(r
        .headers
        .iter()
        .any(|(k, v)| k == "Location" && v == "/echo"));
    assert_eq!(
        log.lock().unwrap().requests.len(),
        1,
        "the redirect was not followed"
    );
    let e = send(&req("GET", format!("{base}/drop"), &[], ""), &opts())
        .await
        .unwrap_err();
    assert_eq!(e.kind, "malformed");
    assert_eq!(
        log.lock().unwrap().connections,
        2,
        "a failed send is not retried"
    );
}

#[tokio::test]
async fn refused_timeout_and_own_listener() {
    let free = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let e = send(
        &req("GET", format!("http://127.0.0.1:{free}/"), &[], ""),
        &opts(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, "refused", "{}", e.message);

    let (port, _log) = fixture().await;
    let quick = ReplayOptions {
        response_timeout: Duration::from_secs(1),
        ..opts()
    };
    let started = std::time::Instant::now();
    let e = send(
        &req("GET", format!("http://127.0.0.1:{port}/hang"), &[], ""),
        &quick,
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind, "timeout");
    assert!(started.elapsed() < Duration::from_secs(4));

    let own = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let own_addr = own.local_addr().unwrap();
    let guarded = ReplayOptions {
        own_listener: Some(own_addr),
        ..opts()
    };
    for host in ["127.0.0.1", "localhost"] {
        let e = send(
            &req(
                "GET",
                format!("http://{host}:{}/", own_addr.port()),
                &[],
                "",
            ),
            &guarded,
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind, "loop");
    }
    let accepted = tokio::time::timeout(Duration::from_millis(300), own.accept()).await;
    assert!(accepted.is_err(), "nothing connected to the listener");
}

#[tokio::test]
async fn responses_are_sanitized_and_repeated_sends_stay_clean() {
    let (port, log) = fixture().await;
    let base = format!("http://127.0.0.1:{port}");
    let r = send(&req("GET", format!("{base}/token"), &[], ""), &opts())
        .await
        .unwrap();
    let all = [r.message.clone(), serde_json::to_vec(&r.headers).unwrap()].concat();
    assert!(
        !all.windows(17).any(|w| w == b"DSMARKREPLAYTOKEN")
            && !all.windows(18).any(|w| w == b"DSMARKREPLAYCOOKIE")
    );
    assert!(String::from_utf8_lossy(&r.message).contains("\"access_token\":\"[REDACTED]\""));
    for i in 0..200 {
        let r = send(
            &req("POST", format!("{base}/echo"), &[], &format!("n={i}")),
            &opts(),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200);
    }
    assert_eq!(
        log.lock().unwrap().connections,
        201,
        "exactly one connection per send"
    );
}

#[tokio::test]
async fn request_snapshots_are_sanitized_and_capped() {
    let (port, log) = fixture().await;
    let url = format!("http://127.0.0.1:{port}/echo?page=2&api_key=DSMARKSNAPKEY&next=%2Fcb%3Ftoken%3DDSMARKSNAPNEST");
    let body = r#"{"user":"synthetic","p\u0061ssword":"DSMARKSNAPPW"}"#;
    let r = send(
        &req(
            "POST",
            url,
            &[
                ("Authorization", "Bearer DSMARKSNAPAUTH"),
                ("Cookie", "sid=DSMARKSNAPCK"),
                ("X-Plain", "visible"),
            ],
            body,
        ),
        &opts(),
    )
    .await
    .unwrap();
    // The target received the real values...
    let sent = log.lock().unwrap().requests.last().unwrap().clone();
    for m in [
        "DSMARKSNAPKEY",
        "DSMARKSNAPNEST",
        "DSMARKSNAPPW",
        "DSMARKSNAPAUTH",
        "DSMARKSNAPCK",
    ] {
        assert!(sent.windows(m.len()).any(|w| w == m.as_bytes()), "{m} sent");
    }
    // ...the snapshot kept for the attempt list holds none of them.
    let snap = [
        r.request_target.clone().into_bytes(),
        serde_json::to_vec(&r.request_headers).unwrap(),
        r.request_message.clone(),
    ]
    .concat();
    for m in [
        "DSMARKSNAPKEY",
        "DSMARKSNAPNEST",
        "DSMARKSNAPPW",
        "DSMARKSNAPAUTH",
        "DSMARKSNAPCK",
    ] {
        assert!(
            !snap.windows(m.len()).any(|w| w == m.as_bytes()),
            "{m} kept in snapshot"
        );
    }
    assert!(
        r.request_target.contains("page=2")
            && r.request_headers
                .iter()
                .any(|(k, v)| k == "X-Plain" && v == "visible")
    );

    // Bodies over the capture limit are summarised, not kept.
    let big = "y".repeat(40 * 1024);
    let r = send(
        &req("POST", format!("http://127.0.0.1:{port}/echo"), &[], &big),
        &opts(),
    )
    .await
    .unwrap();
    let snap = String::from_utf8_lossy(body_of(&r.request_message)).to_string();
    assert!(
        snap.starts_with(
            "[DropSuite: body not stored] reason=body exceeds the 16 KB capture limit"
        ) && snap.len() < 400,
        "{snap}"
    );
}

/// Deterministic resolution plus a connector stand-in: every invocation is counted, and only
/// loopback sockets are ever opened, so nothing here can reach a metadata endpoint.
fn seams(table: &[(&str, &[&str])]) -> (NetworkSeams, Arc<AtomicUsize>) {
    let map: HashMap<String, Vec<IpAddr>> = table
        .iter()
        .map(|(h, ips)| {
            (
                h.to_string(),
                ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            )
        })
        .collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let net = NetworkSeams {
        resolver: Some(Arc::new(move |host: &str| map.get(host).cloned())),
        connect_gate: Some(Arc::new(move |targets: &[SocketAddr]| {
            counted.fetch_add(1, Ordering::SeqCst);
            targets.iter().all(|t| t.ip().is_loopback())
        })),
    };
    (net, calls)
}

#[tokio::test]
async fn restricted_destinations_are_refused_before_the_connector() {
    let (net, calls) = seams(&[
        ("metadata.test", &["169.254.169.254"]),
        ("alibaba.test", &["100.100.100.200"]),
        ("aws6.test", &["fd00:ec2::254"]),
        ("nat64.test", &["64:ff9b::a9fe:a9fe"]),
        ("ll6.test", &["fe80::1"]),
    ]);
    for url in [
        // Cloud metadata, direct.
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        // Other restricted classes.
        "http://169.254.0.1/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://224.0.0.1/",
        "http://[ff02::1]/",
        // IPv4-mapped, legacy IPv4-compatible and well-known NAT64 spellings.
        "http://[::ffff:169.254.169.254]/",
        "http://[::169.254.169.254]/",
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://[64:ff9b::6464:64c8]/",
        // Hostnames that resolve to restricted addresses.
        "http://metadata.test/latest/meta-data/",
        "https://metadata.test/",
        "http://alibaba.test/",
        "http://aws6.test/",
        "http://nat64.test/",
        "http://ll6.test/",
    ] {
        let e = send_with(&req("GET", url.into(), &[], ""), &opts(), &net)
            .await
            .unwrap_err();
        assert_eq!(e.kind, "blocked", "{url}: {}", e.message);
        assert!(e.message.contains("prohibited"), "{url}: {}", e.message);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{url}: connector never invoked"
        );
    }
}

#[tokio::test]
async fn mixed_dns_answer_is_refused_without_trying_the_permitted_address() {
    let (port, log) = fixture().await;
    let (net, calls) = seams(&[
        ("mixed.test", &["127.0.0.1", "169.254.169.254"]),
        ("mixed-rev.test", &["100.100.100.200", "127.0.0.1"]),
    ]);
    for host in ["mixed.test", "mixed-rev.test"] {
        let url = format!("http://{host}:{port}/echo");
        let e = send_with(&req("GET", url, &[], ""), &opts(), &net)
            .await
            .unwrap_err();
        assert_eq!(e.kind, "blocked", "{host}: {}", e.message);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "connector never invoked");
    assert_eq!(
        log.lock().unwrap().connections,
        0,
        "the permitted address was not tried either"
    );
}

#[tokio::test]
async fn loopback_and_private_destinations_stay_permitted() {
    // Loopback API by name: the resolved address is used, the name stays in Host.
    let (port, log) = fixture().await;
    let (net, calls) = seams(&[
        ("api.test", &["127.0.0.1"]),
        ("private.test", &["10.1.2.3"]),
    ]);
    let r = send_with(
        &req("GET", format!("http://api.test:{port}/echo"), &[], ""),
        &opts(),
        &net,
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let sent = String::from_utf8_lossy(&log.lock().unwrap().requests[0]).to_string();
    assert!(
        sent.contains(&format!("\r\nHost: api.test:{port}\r\n")),
        "{sent}"
    );

    // Private-network and other permitted addresses pass the policy and reach the connector;
    // the gate then refuses the non-loopback socket, so nothing leaves this machine.
    for (i, url) in [
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.10/",
        "http://100.64.0.1/",
        "http://[fd00::5]/",
        "http://[64:ff9b::808:808]/",
        "http://private.test/",
    ]
    .iter()
    .enumerate()
    {
        let e = send_with(&req("GET", url.to_string(), &[], ""), &opts(), &net)
            .await
            .unwrap_err();
        assert_eq!(e.kind, "connect", "{url}: {}", e.message);
        assert!(e.message.contains("connect gate"), "{url}: {}", e.message);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            i + 2,
            "{url}: policy permitted it"
        );
    }
}
