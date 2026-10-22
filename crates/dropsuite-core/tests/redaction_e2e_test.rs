//! P1.6 regression: credentials in captured traffic never reach persisted artifacts, while the
//! proxy still forwards the original bytes. Uses synthetic markers and a temporary database.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dropsuite_core::models::{HistoryFilter, TransactionRecord};
use dropsuite_core::{ProxyEngine, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn nonce() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), t)
}

/// One synthetic marker per credential location, all unique to this run.
struct Markers(Vec<String>);
impl Markers {
    fn new(labels: &[&str]) -> Self {
        let n = nonce();
        Markers(labels.iter().map(|l| format!("DSMARK{l}{n}")).collect())
    }
    fn get(&self, i: usize) -> &str {
        &self.0[i]
    }
    /// Count of markers found in `bytes`; the markers themselves are never printed.
    fn found_in(&self, bytes: &[u8]) -> usize {
        self.0.iter().filter(|m| contains(bytes, m)).count()
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// What the API exposes for a record: its JSON plus the decoded body bytes. serde writes the
/// bodies as number arrays, so a text scan of the JSON alone would miss their content.
fn api_view(rec: &TransactionRecord) -> Vec<u8> {
    let mut v = serde_json::to_vec(rec).unwrap();
    v.extend_from_slice(&rec.request_body);
    v.extend_from_slice(&rec.response_body);
    v
}

fn temp_db() -> PathBuf {
    std::env::temp_dir().join(format!("dropsuite-p16-e2e-{}.db", nonce()))
}

fn sqlite_files(db: &Path) -> Vec<Vec<u8>> {
    ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| std::fs::read(format!("{}{}", db.display(), suffix)).ok())
        .collect()
}

fn remove_db(db: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", db.display(), suffix));
    }
}

/// Local upstream that records exactly what it receives and answers by path.
async fn start_upstream(responses: Arc<Vec<(String, Vec<u8>)>>) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let rec = rec.clone();
            let responses = responses.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = buf[..n].to_vec();
                let line = String::from_utf8_lossy(&req)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                rec.lock().unwrap().push(req);
                let resp = responses
                    .iter()
                    .find(|(p, _)| line.contains(p.as_str()))
                    .map(|(_, r)| r.clone())
                    .unwrap_or_else(|| b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 9\r\n\r\nNot Found".to_vec());
                let _ = sock.write_all(&resp).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, received)
}

async fn send_via_proxy(proxy_port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut out)).await;
    out
}

fn http(method: &str, target: &str, host: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut s = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    s.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    s.into_bytes()
}

#[tokio::test]
async fn credentials_never_reach_persisted_artifacts() {
    let m = Markers::new(&[
        "AUTH",
        "COOKIEA",
        "COOKIEB",
        "KEYA",
        "KEYB",
        "PROXYAUTH",
        "QUERY",
        "JSONPW",
        "JSONRT",
        "SETCOOKIEA",
        "SETCOOKIEB",
        "RESPTOKEN",
        "FORMPW",
    ]);

    let resp_body = format!("{{\"user\":\"alice\",\"access_token\":\"{}\"}}", m.get(11));
    let login_response = format!(
        "HTTP/1.1 200 OK\r\nSet-Cookie: session={}; Path=/; HttpOnly\r\nset-cookie: csrf={}\r\n\
         Content-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{resp_body}",
        m.get(9),
        m.get(10),
        resp_body.len()
    )
    .into_bytes();
    let ok_response =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 11\r\n\r\n{\"ok\":true}".to_vec();
    let responses = Arc::new(vec![
        ("/login".to_string(), login_response.clone()),
        ("/form".to_string(), ok_response.clone()),
        ("/ok".to_string(), ok_response.clone()),
    ]);
    let (up_port, received) = start_upstream(responses).await;
    let host = format!("127.0.0.1:{up_port}");

    let db = temp_db();
    let storage = StorageManager::new(&db).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let proxy_port = proxy.status().port;
    assert_ne!(proxy_port, 0, "proxy reports its bound port");
    let mut events = proxy.subscribe();

    // 1. Credential-heavy JSON request: duplicates, mixed case, query secret, JSON secrets.
    let json_body = format!(
        "{{\"username\":\"alice\",\"password\":\"{}\",\"profile\":{{\"refresh_token\":\"{}\",\"plan\":\"pro\"}}}}",
        m.get(7),
        m.get(8)
    );
    let auth = format!("Bearer {}", m.get(0));
    let c1 = format!("sid={}", m.get(1));
    let c2 = format!("theme={}", m.get(2));
    let pa = format!("Basic {}", m.get(5));
    let login_req = http(
        "POST",
        &format!("http://{host}/login?api_key={}&page=1", m.get(6)),
        &host,
        &[
            ("aUtHoRiZaTiOn", &auth),
            ("Cookie", &c1),
            ("COOKIE", &c2),
            ("X-API-Key", m.get(3)),
            ("x-api-key", m.get(4)),
            ("Proxy-Authorization", &pa),
            ("Content-Type", "application/json"),
        ],
        &json_body,
    );
    let login_reply = send_via_proxy(proxy_port, &login_req).await;

    // 2. Form-urlencoded password.
    let form_body = format!("user=alice&password={}&keep=1", m.get(12));
    let form_req = http(
        "POST",
        &format!("http://{host}/form"),
        &host,
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form_body,
    );
    send_via_proxy(proxy_port, &form_req).await;

    // 3. Ordinary GET, 4. upstream 404, 5. unreachable upstream (proxy answers 502).
    let ok_reply = send_via_proxy(
        proxy_port,
        &http("GET", &format!("http://{host}/ok"), &host, &[], ""),
    )
    .await;
    let missing_reply = send_via_proxy(
        proxy_port,
        &http("GET", &format!("http://{host}/missing"), &host, &[], ""),
    )
    .await;
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let dead_host = format!("127.0.0.1:{dead_port}");
    let dead_reply = send_via_proxy(
        proxy_port,
        &http("GET", &format!("http://{dead_host}/x"), &dead_host, &[], ""),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Forwarding: upstream saw the request in origin form with its end-to-end fields and body
    // unchanged (P1.9 drops only hop-by-hop and proxy-only fields); the client got the exact reply.
    let got = received.lock().unwrap().clone();
    let forwarded = |req: &[u8]| -> Vec<u8> {
        let text = String::from_utf8_lossy(req);
        let (line, rest) = text.split_once("\r\n").unwrap();
        let mut parts = line.splitn(3, ' ');
        let (method, target, version) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let origin = &target[target[7..].find('/').unwrap() + 7..];
        let (headers, body) = rest.split_once("\r\n\r\n").unwrap();
        let kept: Vec<&str> = headers
            .split("\r\n")
            .filter(|l| !l.starts_with("Proxy-Authorization:") && !l.starts_with("Connection:"))
            .collect();
        format!(
            "{method} {origin} {version}\r\n{}\r\nConnection: close\r\n\r\n{body}",
            kept.join("\r\n")
        )
        .into_bytes()
    };
    assert!(
        got.contains(&forwarded(&login_req)),
        "upstream received the login request in origin form, body and end-to-end fields intact"
    );
    assert!(
        got.contains(&forwarded(&form_req)),
        "upstream received the form request in origin form, body intact"
    );
    // The server's `Connection: close` is its own hop's; the proxy appends its own because the
    // client asked to close. Everything else reaches the client unchanged.
    let to_client = |resp: &[u8]| -> Vec<u8> {
        let text = String::from_utf8_lossy(resp).replacen("Connection: close\r\n", "", 1);
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        format!("{head}\r\nConnection: close\r\n\r\n{body}").into_bytes()
    };
    assert_eq!(
        login_reply,
        to_client(&login_response),
        "client received the upstream response unchanged apart from Connection"
    );
    assert_eq!(ok_reply, to_client(&ok_response));
    assert!(String::from_utf8_lossy(&missing_reply).starts_with("HTTP/1.1 404"));
    assert!(String::from_utf8_lossy(&dead_reply).starts_with("HTTP/1.1 502"));
    assert_eq!(
        m.found_in(&got.concat()),
        9,
        "the request-side markers reached upstream intact, except the proxy credential"
    );
    assert!(
        !contains(&got.concat(), m.get(5)),
        "Proxy-Authorization never reaches the origin"
    );

    // Stored records and the API payload (the JSON the bridge serves) hold no marker.
    assert_eq!(
        storage.count_transactions().unwrap(),
        4,
        "502 is not stored; the other four are"
    );
    let summaries = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(
        m.found_in(serde_json::to_string(&summaries).unwrap().as_bytes()),
        0,
        "history list"
    );
    let mut methods_status = Vec::new();
    for s in &summaries {
        let rec = storage.get_transaction_by_id(s.id).unwrap().unwrap();
        assert_eq!(
            m.found_in(&api_view(&rec)),
            0,
            "record {} API payload and bodies",
            rec.id
        );
        methods_status.push((rec.method.clone(), rec.status_code));
        if rec.path.contains("/login") {
            assert!(rec
                .request_headers
                .contains(&("aUtHoRiZaTiOn".into(), "Bearer [REDACTED]".into())));
            assert!(rec
                .request_headers
                .contains(&("COOKIE".into(), "theme=[REDACTED]".into())));
            assert!(
                rec.request_headers
                    .iter()
                    .filter(|(k, v)| k.eq_ignore_ascii_case("x-api-key") && v == "[REDACTED]")
                    .count()
                    == 2
            );
            assert!(rec.path.contains("api_key=[REDACTED]&page=1"));
            let req_raw = String::from_utf8_lossy(&rec.request_body);
            assert!(
                req_raw.contains("\"username\":\"alice\"") && req_raw.contains("\"plan\":\"pro\""),
                "diagnostics kept"
            );
            let resp_raw = String::from_utf8_lossy(&rec.response_body);
            assert!(resp_raw.contains("Set-Cookie: session=[REDACTED]; Path=/; HttpOnly"));
            assert!(resp_raw.contains("\"access_token\":\"[REDACTED]\""));
        }
        if rec.path.contains("/form") {
            assert!(String::from_utf8_lossy(&rec.request_body)
                .ends_with("user=alice&password=[REDACTED]&keep=1"));
        }
    }
    methods_status.sort();
    assert_eq!(
        methods_status,
        vec![
            ("GET".into(), 200),
            ("GET".into(), 404),
            ("POST".into(), 200),
            ("POST".into(), 200)
        ]
    );

    // Live events broadcast to the interface are sanitized too.
    let mut event_bytes = Vec::new();
    while let Ok(ev) = events.try_recv() {
        event_bytes.extend(api_view(&ev));
    }
    assert!(!event_bytes.is_empty());
    assert_eq!(m.found_in(&event_bytes), 0, "broadcast events");

    // No marker anywhere in the SQLite files, WAL and shared memory included.
    assert_eq!(
        m.found_in(&sqlite_files(&db).concat()),
        0,
        "db, -wal and -shm while open"
    );
    proxy.stop();
    drop(storage);

    // Persistence across restart, still clean.
    let reopened = StorageManager::new(&db).unwrap();
    assert_eq!(reopened.count_transactions().unwrap(), 4);
    for s in reopened.list_summaries(&HistoryFilter::default()).unwrap() {
        let rec = reopened.get_transaction_by_id(s.id).unwrap().unwrap();
        assert_eq!(m.found_in(&api_view(&rec)), 0);
    }
    drop(reopened);
    assert_eq!(
        m.found_in(&sqlite_files(&db).concat()),
        0,
        "db, -wal and -shm after restart"
    );
    remove_db(&db);
}
