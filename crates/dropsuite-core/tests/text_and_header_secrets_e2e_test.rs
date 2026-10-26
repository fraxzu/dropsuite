//! P2 M2 hardening regression: secrets in URLs written in plain-text and HTML bodies, and
//! credential-format values in headers with unrecognised names, never reach SQLite (db, WAL,
//! shm), the history API, Replay results or the logs, while the traffic itself is forwarded
//! byte-for-byte. All credentials are synthetic.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dropsuite_core::models::HistoryFilter;
use dropsuite_core::replay::{send, ReplayOptions, ReplayRequest};
use dropsuite_core::{ProxyEngine, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Everything the core logs during the test, at every level.
static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogSink;

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains(hay: &[u8], m: &str) -> bool {
    hay.windows(m.len()).any(|w| w == m.as_bytes())
}

/// Accepts connections, records each complete request, and answers with `reply`.
async fn origin(reply: String) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut tmp = vec![0u8; 65536];
            loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                    let cl: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse().unwrap());
                    if buf.len() >= p + 4 + cl {
                        break;
                    }
                }
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            log.lock().unwrap().push(buf);
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (port, seen)
}

#[tokio::test]
async fn text_url_and_custom_header_secrets_never_reach_storage_replay_or_logs() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(|| LogSink)
        .init();

    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mark = |k: &str| format!("DSMARK{k}{t:x}");
    let pad36 = |s: String| format!("{s:0<36}");
    // Response-side secrets.
    let html_mark = mark("HTML");
    let ent_mark = mark("ENT");
    let jwt_mark = mark("JWT");
    let cb_mark = mark("CB");
    let link_mark = mark("LINK");
    let frag_mark = mark("FRAG");
    // Request-side secrets.
    let text_mark = mark("TEXT");
    let gh_mark = pad36(mark("GH"));
    let bearer_mark = mark("BR");
    let replay_mark = mark("RPL");
    let replay_gh = pad36(mark("RGH"));
    let ref_mark = mark("REF");

    let jwt = format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.{jwt_mark}");
    let html = format!(
        "<!doctype html><p>Tom &amp; Jerry</p>\n\
         <a href=\"/cb?id=7&amp;access_token={html_mark}\">continue</a>\n\
         <a href=\"/cb&#x3F;secret&#61;{ent_mark}&amp;page=2\">enc</a>\n\
         <a href=\"/search?q=hello%20world&amp;page=2\">harmless</a>\n"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         X-Debug-Ident: {jwt}\r\n\
         X-Callback: https://h.test/cb?state=s1&access_token={cb_mark}\r\n\
         Link: <https://h.test/p?page=2&api_key={link_mark}>; rel=\"next\"\r\n\
         X-Request-Id: 550e8400-e29b-41d4-a716-446655440000\r\n\
         Content-Location: https://app.test/cb#access_token={frag_mark}&next=/x?y=1\r\n\
         Content-Length: {}\r\n\r\n{html}",
        html.len()
    );
    let (up_port, received) = origin(response.clone()).await;

    let db = std::env::temp_dir().join(format!("dropsuite-m2-text-headers-{t:x}.db"));
    let storage = StorageManager::new(&db).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let port = proxy.status().port;

    // ---- Through the proxy ----
    let req_body = format!(
        "Please open https://h.test/reset?lang=en&password={text_mark} today.\nTicket 4bf92f3577b34da6"
    );
    let fields = format!(
        "Host: 127.0.0.1:{up_port}\r\n\
         X-Client-Info: ghp_{gh_mark}\r\nX-Trace: Bearer {bearer_mark}\r\n\
         X-Plan: Basic plan\r\nContent-Type: text/plain\r\n\
         Referer: https://app.test/p#id_token={ref_mark}&r=/a?b=1\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{req_body}",
        req_body.len()
    );
    let request = format!("POST http://127.0.0.1:{up_port}/notes?page=2 HTTP/1.1\r\n{fields}");
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut reply_bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply_bytes))
        .await
        .unwrap()
        .unwrap();

    // Wait for the record rather than for a fixed time.
    let mut summaries = Vec::new();
    for _ in 0..100 {
        summaries = storage.list_summaries(&HistoryFilter::default()).unwrap();
        if !summaries.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(summaries.len(), 1);

    // Forwarding is untouched in both directions: the only changes are the origin-form target
    // and the proxy's own `Connection: close` (P1.9), never a redaction.
    let upstream_saw = received.lock().unwrap()[0].clone();
    assert_eq!(
        String::from_utf8_lossy(&upstream_saw),
        format!("POST /notes?page=2 HTTP/1.1\r\n{fields}"),
        "origin got the original request"
    );
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        String::from_utf8_lossy(&reply_bytes),
        format!("{head}\r\nConnection: close\r\n\r\n{body}"),
        "client got the original response"
    );

    // ---- Replay: sent as typed, kept sanitized ----
    let replay_body = format!("see /cb?x=1&amp;token={replay_mark}");
    let replayed = send(
        &ReplayRequest {
            method: "POST".into(),
            url: format!("http://127.0.0.1:{up_port}/replay?page=3"),
            headers: vec![
                ("X-Client-Info".into(), format!("ghp_{replay_gh}")),
                ("Content-Type".into(), "text/html".into()),
            ],
            body: replay_body.clone(),
        },
        &ReplayOptions {
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(5),
            own_listener: None,
            tls_roots: Vec::new(),
            apply: dropsuite_core::replay::ApplyConfig::default(),
        },
    )
    .await
    .unwrap();
    let replay_saw = received.lock().unwrap()[1].clone();
    assert!(
        contains(&replay_saw, &replay_body) && contains(&replay_saw, &replay_gh),
        "Replay sent the request as typed"
    );

    let marks = [
        &html_mark,
        &ent_mark,
        &jwt_mark,
        &cb_mark,
        &link_mark,
        &frag_mark,
        &ref_mark,
        &text_mark,
        &gh_mark,
        &bearer_mark,
        &replay_mark,
        &replay_gh,
    ];

    // Nothing in what history and Replay serve...
    let record = storage
        .get_transaction_by_id(summaries[0].id)
        .unwrap()
        .unwrap();
    let served = [
        serde_json::to_vec(&summaries).unwrap(),
        serde_json::to_vec(&record).unwrap(),
        record.request_body.clone(),
        record.response_body.clone(),
        serde_json::to_vec(&replayed).unwrap(),
        replayed.message.clone(),
        replayed.request_message.clone(),
    ]
    .concat();
    for m in marks {
        assert!(
            !contains(&served, m),
            "{m} exposed through history or Replay"
        );
    }
    // ...in the SQLite files, WAL and shared memory included...
    proxy.shutdown().await;
    let files: Vec<u8> = ["", "-wal", "-shm"]
        .iter()
        .filter_map(|s| std::fs::read(format!("{}{s}", db.display())).ok())
        .collect::<Vec<_>>()
        .concat();
    assert!(!files.is_empty());
    for m in marks {
        assert!(!contains(&files, m), "{m} found in SQLite files");
    }
    // ...or in anything logged, at any level.
    let logged = LOG.lock().unwrap().clone();
    assert!(
        contains(&logged, "Persisted transaction"),
        "the capture was logged"
    );
    for m in marks {
        assert!(!contains(&logged, m), "{m} found in the log");
    }

    // Diagnostics stay useful: harmless headers, parameters and markup keep their bytes.
    let req = String::from_utf8(record.request_body.clone()).unwrap();
    let res = String::from_utf8(record.response_body.clone()).unwrap();
    assert!(req.contains(
        "X-Client-Info: [REDACTED]\r\nX-Trace: Bearer [REDACTED]\r\nX-Plan: Basic plan\r\n"
    ));
    assert!(req.ends_with(
        "Please open https://h.test/reset?lang=en&password=[REDACTED] today.\nTicket 4bf92f3577b34da6"
    ));
    assert!(res.contains("X-Debug-Ident: [REDACTED]\r\n"));
    assert!(res.contains("X-Callback: https://h.test/cb?state=s1&access_token=[REDACTED]\r\n"));
    assert!(res.contains("Link: <https://h.test/p?page=2&api_key=[REDACTED]>; rel=\"next\"\r\n"));
    assert!(res.contains("X-Request-Id: 550e8400-e29b-41d4-a716-446655440000\r\n"));
    // Fragment parameters before a later `?` (regression after the hash-route rule).
    assert!(res
        .contains("Content-Location: https://app.test/cb#access_token=[REDACTED]&next=/x?y=1\r\n"));
    assert!(req.contains("Referer: https://app.test/p#id_token=[REDACTED]&r=/a?b=1\r\n"));
    assert!(res.contains("<p>Tom &amp; Jerry</p>"));
    assert!(res.contains("<a href=\"/cb?id=7&amp;access_token=[REDACTED]\">continue</a>"));
    assert!(res.contains("<a href=\"/cb&#x3F;secret&#61;[REDACTED]&amp;page=2\">enc</a>"));
    assert!(res.contains("<a href=\"/search?q=hello%20world&amp;page=2\">harmless</a>"));
    let replay_req = String::from_utf8(replayed.request_message.clone()).unwrap();
    assert!(
        replay_req.ends_with("see /cb?x=1&amp;token=[REDACTED]"),
        "{replay_req}"
    );

    drop(storage);
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{s}", db.display()));
    }
}
