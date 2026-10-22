//! P1.8 regression: complete HTTP/1.1 message forwarding.
//!
//! The proxy once did a single 16 KB read per request and per response, so larger bodies were
//! cut off. These tests push deterministic payloads through the proxy and compare length and
//! SHA-256 at both ends. The fixture upstream and the test client parse HTTP on their own (not
//! with the proxy's code), so a framing bug in the proxy cannot hide behind shared logic.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dropsuite_core::models::{HistoryFilter, TransactionRecord};
use dropsuite_core::{ProxyEngine, StorageManager};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const KB: usize = 1024;
const MB: usize = 1024 * 1024;
const SIZES: [usize; 7] = [1, 16383, 16384, 16385, 20 * KB, MB, 5 * MB];
const CAPTURE_LIMIT: usize = 16 * KB;
const OMITTED_PREFIX: &str = "[DropSuite: body not stored]";

// ---------- payloads ----------

fn lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    move || {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        x >> 33
    }
}

/// Deterministic printable text (never starts like JSON, so it is stored as plain text).
fn text_payload(n: usize, seed: u64) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .";
    let mut r = lcg(seed);
    (0..n)
        .map(|_| ALPHABET[(r() % ALPHABET.len() as u64) as usize])
        .collect()
}

/// Deterministic bytes covering the full 0..=255 range.
fn bin_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut r = lcg(seed);
    (0..n).map(|_| (r() & 0xff) as u8).collect()
}

fn sha(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Chunked encoding with uneven chunk sizes, one chunk extension and a trailer field.
fn chunked_encode(payload: &[u8]) -> Vec<u8> {
    const SIZES: [usize; 7] = [1, 10, 4095, 4096, 4097, 65536, 100_000];
    let mut out = Vec::new();
    let (mut i, mut k) = (0, 0);
    while i < payload.len() {
        let n = SIZES[k % SIZES.len()].min(payload.len() - i);
        if k == 1 {
            out.extend(format!("{n:x};ext=dropsuite\r\n").as_bytes());
        } else {
            out.extend(format!("{n:X}\r\n").as_bytes());
        }
        out.extend(&payload[i..i + n]);
        out.extend(b"\r\n");
        i += n;
        k += 1;
    }
    out.extend(b"0\r\nX-Trailer: done\r\n\r\n");
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A valid gzip stream (one stored deflate block), so the bytes are real compressed framing.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    assert!(data.len() <= 65535);
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1];
    let len = data.len() as u16;
    out.extend(len.to_le_bytes());
    out.extend((!len).to_le_bytes());
    out.extend(data);
    out.extend(crc32(data).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    find(hay, needle).is_some()
}

// ---------- fixture upstream ----------

#[derive(Default)]
struct Log {
    /// Every complete request as received, head and raw body.
    requests: Vec<Vec<u8>>,
    /// Notable events (incomplete bodies, aborted downloads).
    events: Vec<String>,
}

struct Upstream {
    port: u16,
    log: Arc<Mutex<Log>>,
}

impl Upstream {
    async fn start() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Log::default()));
        let shared = log.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve(sock, shared.clone()));
            }
        });
        Upstream { port, log }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.log.lock().unwrap().requests.clone()
    }

    fn events(&self) -> Vec<String> {
        self.log.lock().unwrap().events.clone()
    }

    async fn wait_event(&self, needle: &str) -> bool {
        for _ in 0..100 {
            if self.events().iter().any(|e| e.contains(needle)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

async fn fill(sock: &mut TcpStream, buf: &mut Vec<u8>) -> usize {
    let mut tmp = vec![0u8; 64 * KB];
    let n = sock.read(&mut tmp).await.unwrap_or(0);
    buf.extend_from_slice(&tmp[..n]);
    n
}

/// Take one CRLF line (CRLF included) from `buf`, reading more as needed.
async fn line(sock: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(p) = find(buf, b"\r\n") {
            return Some(buf.drain(..p + 2).collect());
        }
        if fill(sock, buf).await == 0 {
            return None;
        }
    }
}

async fn exact(sock: &mut TcpStream, buf: &mut Vec<u8>, n: usize) -> Option<Vec<u8>> {
    while buf.len() < n {
        if fill(sock, buf).await == 0 {
            return None;
        }
    }
    Some(buf.drain(..n).collect())
}

fn head_fields(head: &[u8]) -> (String, String, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (method, target, headers)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Route from an absolute or origin-form target, without the query.
fn route(target: &str) -> String {
    let path = match target.strip_prefix("http://") {
        Some(rest) => &rest[rest.find('/').unwrap_or(rest.len())..],
        None => target,
    };
    path.split('?').next().unwrap_or("/").to_string()
}

fn size_arg(path: &str) -> usize {
    path.rsplit('/').next().unwrap().parse().unwrap()
}

async fn serve(mut sock: TcpStream, log: Arc<Mutex<Log>>) {
    let mut buf = Vec::new();
    loop {
        let head = loop {
            if let Some(p) = find(&buf, b"\r\n\r\n") {
                break buf.drain(..p + 4).collect::<Vec<u8>>();
            }
            if fill(&mut sock, &mut buf).await == 0 {
                return;
            }
        };
        let (method, target, headers) = head_fields(&head);
        let path = route(&target);
        let mut raw = head.clone();

        if path == "/continue" && header(&headers, "expect") == Some("100-continue") {
            let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        }
        if path == "/early-hints" {
            let _ = sock
                .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
                .await;
        }

        // Body, decoded, with the raw bytes appended to `raw`.
        let mut body = Vec::new();
        if header(&headers, "transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            loop {
                let Some(l) = line(&mut sock, &mut buf).await else {
                    log.lock()
                        .unwrap()
                        .events
                        .push(format!("incomplete chunked body on {path}"));
                    return;
                };
                raw.extend(&l);
                let size_text = String::from_utf8_lossy(&l[..l.len() - 2]);
                let Ok(size) =
                    usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16)
                else {
                    log.lock()
                        .unwrap()
                        .events
                        .push(format!("bad chunk size on {path}"));
                    return;
                };
                if size == 0 {
                    loop {
                        let Some(t) = line(&mut sock, &mut buf).await else {
                            return;
                        };
                        raw.extend(&t);
                        if t == b"\r\n" {
                            break;
                        }
                    }
                    break;
                }
                let Some(data) = exact(&mut sock, &mut buf, size + 2).await else {
                    log.lock()
                        .unwrap()
                        .events
                        .push(format!("incomplete chunked body on {path}"));
                    return;
                };
                raw.extend(&data);
                body.extend(&data[..size]);
            }
        } else if let Some(cl) = header(&headers, "content-length") {
            let cl: usize = cl.parse().unwrap();
            match exact(&mut sock, &mut buf, cl).await {
                Some(data) => {
                    raw.extend(&data);
                    body = data;
                }
                None => {
                    let got = buf.len();
                    log.lock()
                        .unwrap()
                        .events
                        .push(format!("incomplete body on {path}: {got} of {cl} bytes"));
                    return;
                }
            }
        }
        log.lock().unwrap().requests.push(raw);
        if !respond(&mut sock, &method, &path, &body, &log).await {
            return;
        }
    }
}

fn ok_head(content_type: &str, len: usize) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n\r\n")
}

/// Answer one request; false when the connection must end.
async fn respond(
    sock: &mut TcpStream,
    method: &str,
    path: &str,
    body: &[u8],
    log: &Arc<Mutex<Log>>,
) -> bool {
    let w = |data: Vec<u8>| data;
    let resp: Vec<u8> = match path {
        "/echo-hash" | "/continue" => {
            let text = format!("len={} sha256={}", body.len(), sha(body));
            w([ok_head("text/plain", text.len()).into_bytes(), text.into_bytes()].concat())
        }
        "/early-hints" => w([ok_head("text/plain", 2).into_bytes(), b"ok".to_vec()].concat()),
        "/head-len" if method == "HEAD" => w(ok_head("text/plain", 1000).into_bytes()),
        "/head-len" => w([ok_head("text/plain", 1000).into_bytes(), text_payload(1000, 9)].concat()),
        "/204" => w(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
        "/hop-resp" => w(b"HTTP/1.1 200 OK\r\nConnection: close, X-Srv-Hop\r\nX-Srv-Hop: internal\r\nKeep-Alive: timeout=5\r\nProxy-Connection: close\r\nX-End: kept\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\npong".to_vec()),
        "/srv-101" => w(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n".to_vec()),
        "/304" => w(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n".to_vec()),
        "/gzip" => {
            let gz = gzip_stored(&text_payload(3000, 5));
            w([
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gz.len()).into_bytes(),
                gz,
            ]
            .concat())
        }
        "/bad-te-cl" => w(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()),
        "/bad-cl" => w(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!".to_vec()),
        "/bad-chunk" => {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZ\r\nmore\r\n0\r\n\r\n")
                .await;
            return false;
        }
        "/upgrade" => {
            let _ = sock
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
                .await;
            let mut tmp = vec![0u8; 4096];
            loop {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => {
                        if sock.write_all(&tmp[..n]).await.is_err() {
                            return false;
                        }
                    }
                }
            }
        }
        p if p.starts_with("/bytes/") => {
            let n = size_arg(p);
            w([ok_head("text/plain", n).into_bytes(), text_payload(n, n as u64)].concat())
        }
        p if p.starts_with("/bin/") => {
            let n = size_arg(p);
            w([ok_head("application/octet-stream", n).into_bytes(), bin_payload(n, n as u64)].concat())
        }
        p if p.starts_with("/chunked/") => {
            let n = size_arg(p);
            w([
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
                chunked_encode(&text_payload(n, n as u64)),
            ]
            .concat())
        }
        p if p.starts_with("/close/") => {
            let n = size_arg(p);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n")
                .await;
            let _ = sock.write_all(&text_payload(n, n as u64)).await;
            let _ = sock.shutdown().await;
            return false;
        }
        p if p.starts_with("/slow/") => {
            // Head in three pieces and the body in 997-byte pieces, with pauses between.
            let n = size_arg(p);
            let all = [ok_head("text/plain", n).into_bytes(), text_payload(n, n as u64)].concat();
            for piece in [&all[..7], &all[7..20], &all[20..40]] {
                let _ = sock.write_all(piece).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            for piece in all[40..].chunks(997) {
                if sock.write_all(piece).await.is_err() {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            return true;
        }
        p if p.starts_with("/drip/") => {
            let n = size_arg(p);
            let all = [ok_head("text/plain", n).into_bytes(), text_payload(n, 1)].concat();
            let mut sent = 0;
            for piece in all.chunks(64 * KB) {
                if sock.write_all(piece).await.is_err() {
                    log.lock()
                        .unwrap()
                        .events
                        .push(format!("download aborted after {sent} bytes"));
                    return false;
                }
                sent += piece.len();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            log.lock().unwrap().events.push("download completed".into());
            return true;
        }
        _ => w(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()),
    };
    sock.write_all(&resp).await.is_ok()
}

// ---------- test client ----------

struct Resp {
    status: u16,
    head: String,
    /// Head and body exactly as received.
    raw: Vec<u8>,
    /// Body with chunked framing removed.
    body: Vec<u8>,
    interim: Vec<String>,
}

struct Client {
    sock: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(port: u16) -> Client {
        Client {
            sock: TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, data: &[u8]) {
        self.sock.write_all(data).await.unwrap();
    }

    async fn more(&mut self) -> usize {
        tokio::time::timeout(Duration::from_secs(20), fill(&mut self.sock, &mut self.buf))
            .await
            .expect("timed out waiting for the proxy")
    }

    async fn head(&mut self) -> Vec<u8> {
        loop {
            if let Some(p) = find(&self.buf, b"\r\n\r\n") {
                return self.buf.drain(..p + 4).collect();
            }
            assert!(
                self.more().await > 0,
                "connection closed before a response head"
            );
        }
    }

    async fn take_line(&mut self) -> Vec<u8> {
        loop {
            if let Some(p) = find(&self.buf, b"\r\n") {
                return self.buf.drain(..p + 2).collect();
            }
            assert!(self.more().await > 0, "connection closed mid-chunk");
        }
    }

    async fn take(&mut self, n: usize) -> Vec<u8> {
        while self.buf.len() < n {
            assert!(self.more().await > 0, "connection closed mid-body");
        }
        self.buf.drain(..n).collect()
    }

    async fn response(&mut self, is_head: bool) -> Resp {
        let mut interim = Vec::new();
        loop {
            let head = self.head().await;
            let text = String::from_utf8_lossy(&head).to_string();
            let status: u16 = text[9..12].parse().unwrap();
            if (100..200).contains(&status) && status != 101 {
                interim.push(text);
                continue;
            }
            let (_, _, headers) = head_fields(&head);
            let mut raw = head.clone();
            let mut body = Vec::new();
            if is_head || status == 204 || status == 304 || status == 101 {
            } else if header(&headers, "transfer-encoding").is_some_and(|v| v.contains("chunked")) {
                loop {
                    let l = self.take_line().await;
                    raw.extend(&l);
                    let size_text = String::from_utf8_lossy(&l[..l.len() - 2]).to_string();
                    let size =
                        usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16)
                            .unwrap();
                    if size == 0 {
                        loop {
                            let t = self.take_line().await;
                            raw.extend(&t);
                            if t == b"\r\n" {
                                break;
                            }
                        }
                        break;
                    }
                    let data = self.take(size + 2).await;
                    raw.extend(&data);
                    body.extend(&data[..size]);
                }
            } else if let Some(cl) = header(&headers, "content-length") {
                body = self.take(cl.parse().unwrap()).await;
                raw.extend(&body);
            } else {
                while self.more().await > 0 {}
                body = std::mem::take(&mut self.buf);
                raw.extend(&body);
            }
            return Resp {
                status,
                head: text,
                raw,
                body,
                interim,
            };
        }
    }

    /// True when the proxy closes the connection (EOF or reset) with nothing more to read.
    async fn closed(&mut self) -> bool {
        let mut tmp = [0u8; 1024];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.sock.read(&mut tmp)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }
}

// ---------- environment ----------

struct Env {
    proxy: ProxyEngine,
    port: u16,
    storage: StorageManager,
    db: PathBuf,
    up: Upstream,
}

impl Env {
    async fn new(tag: &str) -> Env {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let db = std::env::temp_dir().join(format!(
            "dropsuite-p18-{tag}-{:x}{t:x}.db",
            std::process::id()
        ));
        let storage = StorageManager::new(&db).unwrap();
        let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
        proxy.start().await.unwrap();
        let port = proxy.status().port;
        Env {
            proxy,
            port,
            storage,
            db,
            up: Upstream::start().await,
        }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.up.port)
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.host())
    }

    /// An absolute-form proxy request, as curl -x sends it.
    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut s = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\n",
            self.url(path),
            self.host()
        );
        for (k, v) in headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            s.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        s.push_str("\r\n");
        [s.into_bytes(), body.to_vec()].concat()
    }

    /// What the origin must receive for [`Env::request`] (headers without hop-by-hop fields):
    /// the origin-form target, the same fields, `Connection: close`, and the body unchanged.
    fn forwarded(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut s = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host());
        for (k, v) in headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            s.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        s.push_str("Connection: close\r\n\r\n");
        [s.into_bytes(), body.to_vec()].concat()
    }

    async fn client(&self) -> Client {
        Client::connect(self.port).await
    }

    /// The stored record whose path contains `needle` (capture happens just after the
    /// response is forwarded, so wait briefly for it).
    async fn record(&self, needle: &str) -> TransactionRecord {
        for _ in 0..100 {
            let found = self
                .storage
                .list_summaries(&HistoryFilter::default())
                .unwrap()
                .into_iter()
                .find(|s| s.path.contains(needle));
            if let Some(s) = found {
                return self.storage.get_transaction_by_id(s.id).unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no record for {needle}");
    }

    fn sqlite_bytes(&self) -> Vec<u8> {
        ["", "-wal", "-shm"]
            .iter()
            .filter_map(|s| std::fs::read(format!("{}{s}", self.db.display())).ok())
            .collect::<Vec<_>>()
            .concat()
    }

    async fn finish(mut self) {
        self.proxy.shutdown().await;
        drop(self.storage);
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{s}", self.db.display()));
        }
    }
}

/// The body part of a stored raw message.
fn stored_body(raw: &[u8]) -> &[u8] {
    let p = find(raw, b"\r\n\r\n").expect("stored message has a head");
    &raw[p + 4..]
}

fn assert_stored(raw: &[u8], payload: &[u8], what: &str) {
    let body = stored_body(raw);
    if payload.len() <= CAPTURE_LIMIT {
        assert_eq!(
            body, payload,
            "{what}: body within the capture limit is stored whole"
        );
    } else {
        let text = String::from_utf8_lossy(body);
        assert!(
            text.starts_with(OMITTED_PREFIX),
            "{what}: omitted, got {:?}",
            &text[..text.len().min(80)]
        );
        assert!(
            text.contains("reason=body exceeds the 16 KB capture limit"),
            "{what}: {text}"
        );
        assert!(
            text.contains(&format!("length={} bytes", payload.len())),
            "{what}: {text}"
        );
        assert!(
            text.contains(&format!("sha256={}", sha(payload))),
            "{what}: {text}"
        );
        assert!(body.len() < 400, "{what}: no fragment of the body is kept");
    }
}

// ---------- tests ----------

#[tokio::test]
async fn request_bodies_are_forwarded_completely_at_every_size() {
    let env = Env::new("req").await;
    for (i, &n) in SIZES.iter().enumerate() {
        let payload = text_payload(n, 100 + i as u64);
        let path = format!("/echo-hash?req={n}&end");
        let req = env.request("POST", &path, &[("Content-Type", "text/plain")], &payload);
        let mut c = env.client().await;
        c.send(&req).await;
        let resp = c.response(false).await;
        assert_eq!(resp.status, 200, "request {n}");
        assert_eq!(
            String::from_utf8_lossy(&resp.body),
            format!("len={n} sha256={}", sha(&payload)),
            "request body of {n} bytes reached upstream intact"
        );
        let received = env
            .up
            .requests()
            .into_iter()
            .find(|r| contains(&r[..r.len().min(200)], path.as_bytes()))
            .unwrap();
        assert!(
            received == env.forwarded("POST", &path, &[("Content-Type", "text/plain")], &payload),
            "upstream received the origin-form head and the body byte for byte ({n})"
        );
        let rec = env.record(&format!("req={n}&")).await;
        assert_stored(&rec.request_body, &payload, &format!("request {n}"));
        println!(
            "request  {n:>8} bytes: length and SHA-256 match at upstream; stored {}",
            if n <= CAPTURE_LIMIT {
                "whole"
            } else {
                "as omission record"
            }
        );
    }
    env.finish().await;
}

#[tokio::test]
async fn response_bodies_are_received_completely_at_every_size() {
    let env = Env::new("resp").await;
    for &n in SIZES.iter() {
        let expected = text_payload(n, n as u64);
        let mut c = env.client().await;
        c.send(&env.request("GET", &format!("/bytes/{n}?r"), &[], b""))
            .await;
        let resp = c.response(false).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.len(), n, "response length {n}");
        assert_eq!(sha(&resp.body), sha(&expected), "response SHA-256 {n}");
        assert_eq!(
            resp.raw,
            [ok_head("text/plain", n).into_bytes(), expected.clone()].concat(),
            "response bytes unchanged ({n})"
        );
        let rec = env.record(&format!("/bytes/{n}?r")).await;
        assert_stored(&rec.response_body, &expected, &format!("response {n}"));
        assert_eq!(
            rec.content_length,
            resp.raw.len(),
            "observed length is recorded"
        );
        println!(
            "response {n:>8} bytes: length and SHA-256 match at client; stored {}",
            if n <= CAPTURE_LIMIT {
                "whole"
            } else {
                "as omission record"
            }
        );
    }
    env.finish().await;
}

#[tokio::test]
async fn chunked_requests_are_forwarded_byte_for_byte() {
    let env = Env::new("chunkreq").await;
    for (n, tag) in [(100usize, "small"), (MB + 5, "large")] {
        let payload = text_payload(n, 7);
        let path = format!("/echo-hash?chunked={tag}");
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
            env.url(&path),
            env.host()
        );
        let req = [head.into_bytes(), chunked_encode(&payload)].concat();
        let mut c = env.client().await;
        // Fragmented on purpose: boundaries fall inside sizes, data and CRLFs.
        for piece in req.chunks(65_521) {
            c.send(piece).await;
            tokio::task::yield_now().await;
        }
        let resp = c.response(false).await;
        assert_eq!(
            String::from_utf8_lossy(&resp.body),
            format!("len={n} sha256={}", sha(&payload))
        );
        let received = env
            .up
            .requests()
            .into_iter()
            .find(|r| contains(&r[..r.len().min(300)], path.as_bytes()))
            .unwrap();
        let expected = [
            format!("POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n", env.host()).into_bytes(),
            chunked_encode(&payload),
        ]
        .concat();
        assert!(
            received == expected,
            "origin-form head; chunk sizes, extension and trailer forwarded unchanged ({tag})"
        );
        let rec = env.record(&format!("chunked={tag}")).await;
        let body = stored_body(&rec.request_body);
        if n <= CAPTURE_LIMIT {
            assert!(
                contains(body, &payload),
                "small chunked body stored (as one chunk)"
            );
        } else {
            assert!(
                body.starts_with(OMITTED_PREFIX.as_bytes())
                    && contains(body, sha(&payload).as_bytes())
            );
        }
    }
    env.finish().await;
}

#[tokio::test]
async fn chunked_responses_are_forwarded_byte_for_byte() {
    let env = Env::new("chunkresp").await;
    for n in [10usize, 20 * KB, 5 * MB] {
        let payload = text_payload(n, n as u64);
        let expected_raw = [
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec(),
            chunked_encode(&payload),
        ]
        .concat();
        let mut c = env.client().await;
        c.send(&env.request("GET", &format!("/chunked/{n}"), &[], b""))
            .await;
        let resp = c.response(false).await;
        assert_eq!(resp.raw, expected_raw, "chunked response unchanged ({n})");
        assert_eq!(sha(&resp.body), sha(&payload));
        assert!(contains(
            &resp.raw[resp.raw.len() - 40..],
            b"X-Trailer: done"
        ));
        let rec = env.record(&format!("/chunked/{n}")).await;
        let body = stored_body(&rec.response_body);
        if n <= CAPTURE_LIMIT {
            assert_eq!(
                body,
                [
                    format!("{n:x}\r\n").into_bytes(),
                    payload.clone(),
                    b"\r\n0\r\n\r\n".to_vec()
                ]
                .concat()
            );
        } else {
            assert!(
                body.starts_with(OMITTED_PREFIX.as_bytes())
                    && contains(body, sha(&payload).as_bytes())
            );
        }
    }
    env.finish().await;
}

#[tokio::test]
async fn messages_split_across_reads_and_slow_delivery() {
    let env = Env::new("split").await;
    let payload = text_payload(20 * KB, 3);
    let req = env.request(
        "POST",
        "/echo-hash?split=1",
        &[("Content-Type", "text/plain")],
        &payload,
    );
    let mut c = env.client().await;
    // Head one byte at a time, then the body in uneven fragments.
    let head_len = find(&req, b"\r\n\r\n").unwrap() + 4;
    for b in &req[..head_len] {
        c.send(std::slice::from_ref(b)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let mut i = head_len;
    for (k, step) in [1usize, 2, 3, 4093, 5, 8191, 7].iter().cycle().enumerate() {
        if i >= req.len() || k > 10_000 {
            break;
        }
        let end = (i + step).min(req.len());
        c.send(&req[i..end]).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
        i = end;
    }
    let resp = c.response(false).await;
    assert_eq!(
        String::from_utf8_lossy(&resp.body),
        format!("len={} sha256={}", payload.len(), sha(&payload))
    );

    // Upstream delivers its head in three pieces and the body in small pieces with pauses.
    let n = 70_000;
    c.send(&env.request("GET", "/slow/70000", &[], b"")).await;
    let resp = c.response(false).await;
    assert_eq!(resp.body.len(), n);
    assert_eq!(sha(&resp.body), sha(&text_payload(n, n as u64)));
    env.finish().await;
}

#[tokio::test]
async fn persistent_connection_carries_sequential_and_pipelined_requests() {
    let env = Env::new("keepalive").await;
    let mut c = env.client().await;
    let small = text_payload(5000, 11);
    let big = text_payload(300 * KB, 12);

    c.send(&env.request("GET", "/bytes/100?seq=1", &[], b""))
        .await;
    assert_eq!(c.response(false).await.body, text_payload(100, 100));
    c.send(&env.request(
        "POST",
        "/echo-hash?seq=2",
        &[("Content-Type", "text/plain")],
        &big,
    ))
    .await;
    assert_eq!(
        String::from_utf8_lossy(&c.response(false).await.body),
        format!("len={} sha256={}", big.len(), sha(&big))
    );
    let chunked_req = [
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            env.url("/echo-hash?seq=3"),
            env.host()
        )
        .into_bytes(),
        chunked_encode(&small),
    ]
    .concat();
    c.send(&chunked_req).await;
    assert_eq!(
        String::from_utf8_lossy(&c.response(false).await.body),
        format!("len=5000 sha256={}", sha(&small))
    );
    c.send(&env.request("GET", "/chunked/30000?seq=4", &[], b""))
        .await;
    assert_eq!(c.response(false).await.body, text_payload(30000, 30000));

    // Pipelined: two requests in one write, two responses in order.
    let pipelined = [
        env.request("GET", "/bytes/7?seq=5", &[], b""),
        env.request("POST", "/echo-hash?seq=6", &[], b"abc"),
    ]
    .concat();
    c.send(&pipelined).await;
    assert_eq!(c.response(false).await.body, text_payload(7, 7));
    assert_eq!(
        String::from_utf8_lossy(&c.response(false).await.body),
        format!("len=3 sha256={}", sha(b"abc"))
    );
    for seq in 1..=6 {
        env.record(&format!("seq={seq}")).await;
    }
    env.finish().await;
}

#[tokio::test]
async fn head_204_and_304_responses_carry_no_body() {
    let env = Env::new("nobody").await;
    let mut c = env.client().await;
    // HEAD declares Content-Length: 1000 but sends no body; the proxy must not wait for one.
    c.send(&env.request("HEAD", "/head-len?nb=1", &[], b""))
        .await;
    let r = tokio::time::timeout(Duration::from_secs(5), c.response(true))
        .await
        .expect("HEAD answered");
    assert!(r.head.contains("Content-Length: 1000") && r.body.is_empty());
    c.send(&env.request("GET", "/204?nb=2", &[], b"")).await;
    assert_eq!(c.response(false).await.status, 204);
    c.send(&env.request("GET", "/304?nb=3", &[], b"")).await;
    let r = c.response(false).await;
    assert!(r.status == 304 && r.body.is_empty());
    // The same connection is still in sync.
    c.send(&env.request("GET", "/head-len?nb=4", &[], b""))
        .await;
    let r = c.response(false).await;
    assert_eq!(r.body, text_payload(1000, 9));
    let rec = env.record("nb=1").await;
    assert_eq!(rec.method, "HEAD");
    assert_eq!(stored_body(&rec.response_body), b"");
    env.finish().await;
}

#[tokio::test]
async fn interim_responses_and_protocol_switch() {
    let env = Env::new("interim").await;
    // Expect: 100-continue: the client sends its body only after the 100 arrives.
    let body = text_payload(64 * KB, 21);
    let req = env.request(
        "POST",
        "/continue?x=1",
        &[("Expect", "100-continue")],
        &body,
    );
    let head_len = find(&req, b"\r\n\r\n").unwrap() + 4;
    let mut c = env.client().await;
    c.send(&req[..head_len]).await;
    let interim = tokio::time::timeout(Duration::from_secs(3), c.head())
        .await
        .expect("100 Continue relayed before the body");
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    c.send(&req[head_len..]).await;
    let r = c.response(false).await;
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        format!("len={} sha256={}", body.len(), sha(&body))
    );

    // 103 Early Hints before the final response.
    c.send(&env.request("GET", "/early-hints", &[], b"")).await;
    let r = c.response(false).await;
    assert_eq!(r.interim.len(), 1);
    assert!(r.interim[0].starts_with("HTTP/1.1 103 Early Hints\r\nLink:"));
    assert_eq!((r.status, r.body.as_slice()), (200, b"ok".as_slice()));

    // 101 Switching Protocols: raw bytes relayed both ways afterwards.
    let mut c = env.client().await;
    c.send(&env.request(
        "GET",
        "/upgrade",
        &[("Connection", "Upgrade"), ("Upgrade", "echo")],
        b"",
    ))
    .await;
    let r = c.response(false).await;
    assert_eq!(r.status, 101);
    c.send(b"ping-after-upgrade").await;
    let echoed = c.take(18).await;
    assert_eq!(echoed, b"ping-after-upgrade");
    env.finish().await;
}

#[tokio::test]
async fn large_binary_transfers_in_both_directions() {
    let env = Env::new("binary").await;
    let upload = bin_payload(5 * MB, 42);
    let mut c = env.client().await;
    c.send(&env.request(
        "POST",
        "/echo-hash?bin=up",
        &[("Content-Type", "application/octet-stream")],
        &upload,
    ))
    .await;
    let r = c.response(false).await;
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        format!("len={} sha256={}", upload.len(), sha(&upload))
    );
    c.send(&env.request("GET", &format!("/bin/{}", 5 * MB), &[], b""))
        .await;
    let r = c.response(false).await;
    let expected = bin_payload(5 * MB, (5 * MB) as u64);
    assert_eq!(
        (r.body.len(), sha(&r.body)),
        (expected.len(), sha(&expected))
    );
    assert_stored(
        &env.record("bin=up").await.request_body,
        &upload,
        "binary upload",
    );
    assert_stored(
        &env.record(&format!("/bin/{}", 5 * MB)).await.response_body,
        &expected,
        "binary download",
    );
    env.finish().await;
}

#[tokio::test]
async fn compressed_responses_are_forwarded_unchanged_and_not_stored() {
    let env = Env::new("gzip").await;
    let mut c = env.client().await;
    c.send(&env.request("GET", "/gzip", &[], b"")).await;
    let r = c.response(false).await;
    let gz = gzip_stored(&text_payload(3000, 5));
    assert_eq!(r.body, gz, "gzip bytes forwarded unchanged");
    assert_eq!(&r.body[..2], &[0x1f, 0x8b]);
    let rec = env.record("/gzip").await;
    let stored = String::from_utf8_lossy(stored_body(&rec.response_body)).to_string();
    assert!(
        stored.starts_with(OMITTED_PREFIX)
            && stored.contains("content-encoding gzip is not decoded"),
        "{stored}"
    );
    assert!(
        !contains(&env.sqlite_bytes(), &gz[..64]),
        "no compressed bytes in SQLite"
    );
    env.finish().await;
}

#[tokio::test]
async fn interrupted_client_connections_are_cleaned_up() {
    let env = Env::new("interrupt").await;
    let before = env.storage.count_transactions().unwrap();

    // Upload abandoned after 1 MB of a declared 5 MB body: upstream sees the request end
    // short (it is never told the body was complete), and nothing is captured.
    let mut c = env.client().await;
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        env.url("/echo-hash?abandoned=1"),
        env.host(),
        5 * MB
    );
    c.send(head.as_bytes()).await;
    c.send(&text_payload(MB, 1)).await;
    drop(c);
    assert!(
        env.up.wait_event("incomplete body on /echo-hash").await,
        "upstream connection ended without a complete body: {:?}",
        env.up.events()
    );
    assert_eq!(
        env.storage.count_transactions().unwrap(),
        before,
        "an abandoned upload is not captured"
    );

    // Download abandoned after ~100 KB of 5 MB: the proxy stops pulling from upstream.
    let mut c = env.client().await;
    c.send(&env.request("GET", &format!("/drip/{}", 5 * MB), &[], b""))
        .await;
    while c.buf.len() < 100 * KB {
        c.more().await;
    }
    drop(c);
    assert!(
        env.up.wait_event("download aborted").await,
        "upstream transfer stopped: {:?}",
        env.up.events()
    );
    let rec = env.record("/drip/").await;
    let stored = String::from_utf8_lossy(stored_body(&rec.response_body)).to_string();
    assert!(
        stored.starts_with(OMITTED_PREFIX) && stored.contains("transfer interrupted"),
        "{stored}"
    );
    assert!(stored.len() < 400, "no partial body fragment stored");

    // The proxy keeps serving.
    let mut c = env.client().await;
    c.send(&env.request("GET", "/bytes/50", &[], b"")).await;
    assert_eq!(c.response(false).await.body, text_payload(50, 50));
    env.finish().await;
}

#[tokio::test]
async fn malformed_and_conflicting_framing_is_rejected() {
    let env = Env::new("malformed").await;
    let h = env.host();
    let u = env.url("/echo-hash?bad");
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("CL+TE smuggling attempt", format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {h}\r\n\r\n").into_bytes(), "400"),
        ("conflicting Content-Length", format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd").into_bytes(), "400"),
        ("invalid Content-Length", format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nContent-Length: +3\r\n\r\nabc").into_bytes(), "400"),
        ("Transfer-Encoding without chunked", format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: gzip\r\n\r\nabc").into_bytes(), "400"),
        ("chunked twice", format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n").into_bytes(), "400"),
        ("obsolete line folding", format!("GET {u} HTTP/1.1\r\nHost: {h}\r\nX-A: 1\r\n folded\r\n\r\n").into_bytes(), "400"),
        ("bare LF head", format!("GET {u} HTTP/1.1\nHost: {h}\n\n").into_bytes(), "400"),
        ("two Host headers", format!("GET /x HTTP/1.1\r\nHost: {h}\r\nHost: {h}\r\n\r\n").into_bytes(), "400"),
        ("head over 64 KB", format!("GET {u} HTTP/1.1\r\nHost: {h}\r\nX-Big: {}\r\n\r\n", "a".repeat(70 * KB)).into_bytes(), "431"),
        ("CONNECT (no HTTPS tunnelling)", format!("CONNECT {h} HTTP/1.1\r\nHost: {h}\r\n\r\n").into_bytes(), "501"),
    ];
    for (name, raw, expected) in &cases {
        let mut c = env.client().await;
        c.send(raw).await;
        let r = c.response(false).await;
        assert!(
            r.head.starts_with(&format!("HTTP/1.1 {expected}")),
            "{name}: got {}",
            r.head.lines().next().unwrap()
        );
        assert!(
            c.closed().await,
            "{name}: connection closed after the rejection"
        );
    }
    assert!(
        env.up.requests().is_empty(),
        "no rejected request reached upstream"
    );
    assert!(!env.up.requests().iter().any(|r| contains(r, b"/smuggled")));

    // Bad chunk framing inside a request body: rejected, connection closed, nothing completed upstream.
    let mut c = env.client().await;
    c.send(format!("POST {u} HTTP/1.1\r\nHost: {h}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZ\r\n").as_bytes()).await;
    let r = c.response(false).await;
    assert!(r.head.starts_with("HTTP/1.1 400"), "{}", r.head);
    assert!(c.closed().await);
    assert!(env.up.requests().is_empty());

    // Ambiguous or conflicting response framing from upstream: 502, never guessed.
    for path in ["/bad-te-cl", "/bad-cl"] {
        let mut c = env.client().await;
        c.send(&env.request("GET", path, &[], b"")).await;
        let r = c.response(false).await;
        assert!(r.head.starts_with("HTTP/1.1 502"), "{path}: {}", r.head);
    }
    // Bad chunk framing mid-response: the client gets the head and complete chunks only, and
    // the connection closes without a terminating chunk, so the body is visibly incomplete.
    let mut c = env.client().await;
    c.send(&env.request("GET", "/bad-chunk", &[], b"")).await;
    let head = c.head().await;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    while c.more().await > 0 {}
    assert_eq!(
        c.buf, b"5\r\nhello\r\n",
        "nothing past the bad chunk, no terminating chunk"
    );
    let rec = env.record("/bad-chunk").await;
    assert!(
        String::from_utf8_lossy(stored_body(&rec.response_body)).contains("transfer interrupted")
    );
    env.finish().await;
}

#[tokio::test]
async fn credentials_never_reach_storage_for_small_or_large_bodies() {
    let env = Env::new("markers").await;
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let m: Vec<String> = ["AUTH", "PWSMALL", "PWLARGE", "COOKIE"]
        .iter()
        .map(|k| format!("DSMARK{k}{t:x}"))
        .collect();
    let auth = format!("Bearer {}", m[0]);
    let cookie = format!("sid={}", m[3]);

    let small = format!("{{\"user\":\"synthetic\",\"password\":\"{}\"}}", m[1]);
    let large = format!(
        "{{\"password\":\"{}\",\"pad\":\"{}\"}}",
        m[2],
        "x".repeat(40 * KB)
    );
    let mut c = env.client().await;
    for (tag, body) in [("small", &small), ("large", &large)] {
        c.send(&env.request(
            "POST",
            &format!("/echo-hash?cred={tag}"),
            &[
                ("Authorization", &auth),
                ("Cookie", &cookie),
                ("Content-Type", "application/json"),
            ],
            body.as_bytes(),
        ))
        .await;
        let r = c.response(false).await;
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            format!("len={} sha256={}", body.len(), sha(body.as_bytes()))
        );
    }
    let upstream = env.up.requests().concat();
    assert!(
        m.iter().all(|k| contains(&upstream, k.as_bytes())),
        "markers reached upstream intact"
    );
    let small_rec = env.record("cred=small").await;
    assert!(contains(
        &small_rec.request_body,
        b"\"password\":\"[REDACTED]\""
    ));
    let large_rec = env.record("cred=large").await;
    assert!(stored_body(&large_rec.request_body).starts_with(OMITTED_PREFIX.as_bytes()));
    let db = env.sqlite_bytes();
    assert!(
        m.iter().all(|k| !contains(&db, k.as_bytes())),
        "no marker in the SQLite files"
    );
    env.finish().await;
}

#[tokio::test]
async fn response_delimited_by_close_and_loop_guard() {
    let env = Env::new("close").await;
    let n = 40 * KB;
    let mut c = env.client().await;
    c.send(&env.request("GET", &format!("/close/{n}"), &[], b""))
        .await;
    let r = c.response(false).await;
    assert_eq!(
        (r.body.len(), sha(&r.body)),
        (n, sha(&text_payload(n, n as u64)))
    );

    // A request to the proxy's own address on a kept-alive connection: one 508, no loop.
    let own = format!("127.0.0.1:{}", env.port);
    let mut c = env.client().await;
    c.send(&env.request("GET", "/bytes/3", &[], b"")).await;
    c.response(false).await;
    c.send(format!("GET http://{own}/ HTTP/1.1\r\nHost: {own}\r\n\r\n").as_bytes())
        .await;
    let r = c.response(false).await;
    assert!(r.head.starts_with("HTTP/1.1 508 Loop Detected"));
    assert!(c.closed().await);
    env.finish().await;
}

// ---------- P1.9: forward-proxy interoperability ----------

#[tokio::test]
async fn origin_receives_origin_form_without_proxy_or_hop_by_hop_fields() {
    let env = Env::new("interop").await;
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let proxy_secret = format!("DSMARKPROXYAUTH{t:x}");
    let url_secret = format!("DSMARKURLPW{t:x}");
    let body = text_payload(2 * MB, 31);
    // A spoofed Host, URL userinfo, proxy credentials, legacy and listed hop-by-hop fields, and
    // a Connection option naming Content-Length (which must not be honoured).
    let head = format!(
        "POST http://user:{url_secret}@{h}/echo-hash?interop=1#frag HTTP/1.1\r\n\
         Host: spoofed.example\r\n\
         Proxy-Authorization: Basic {proxy_secret}\r\n\
         Proxy-Connection: keep-alive\r\n\
         Connection: keep-alive, X-Hop, Content-Length\r\n\
         Keep-Alive: timeout=5\r\n\
         TE: trailers\r\n\
         X-Hop: drop-me\r\n\
         Upgrade: h2c\r\n\
         X-End-To-End: keep-me\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\r\n",
        body.len(),
        h = env.host()
    );
    let mut c = env.client().await;
    c.send(&[head.into_bytes(), body.clone()].concat()).await;
    let r = c.response(false).await;
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        format!("len={} sha256={}", body.len(), sha(&body)),
        "2 MB body intact"
    );

    let got = env.up.requests().pop().unwrap();
    let head_end = find(&got, b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        String::from_utf8_lossy(&got[..head_end]),
        format!(
            "POST /echo-hash?interop=1 HTTP/1.1\r\nHost: {}\r\nX-End-To-End: keep-me\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            env.host(),
            body.len()
        ),
        "exact head the origin receives"
    );
    assert_eq!(&got[head_end..], &body[..], "body unchanged");
    assert!(
        !contains(&got, proxy_secret.as_bytes()) && !contains(&got, url_secret.as_bytes()),
        "no proxy or URL credential reaches the origin"
    );

    // Captured copy: the request as the client sent it, with both secrets redacted.
    let rec = env.record("interop=1").await;
    let stored = [
        rec.request_body.clone(),
        rec.url.clone().into_bytes(),
        serde_json::to_vec(&rec.request_headers).unwrap(),
    ]
    .concat();
    assert!(
        !contains(&stored, proxy_secret.as_bytes()) && !contains(&stored, url_secret.as_bytes())
    );
    assert!(!contains(&env.sqlite_bytes(), proxy_secret.as_bytes()));
    assert_eq!(
        rec.host,
        env.host(),
        "history shows the host actually contacted, not the spoofed Host"
    );

    // The client connection stays usable after a keep-alive exchange.
    c.send(&env.request("GET", "/bytes/10", &[], b"")).await;
    assert_eq!(c.response(false).await.body, text_payload(10, 10));
    env.finish().await;
}

#[tokio::test]
async fn standard_requests_reach_the_origin_in_origin_form() {
    let env = Env::new("standard").await;
    let mut c = env.client().await;
    let cases: [(&str, &str, &str); 4] = [
        ("GET", "/bytes/5?q=1", "/bytes/5?q=1"),
        ("GET", "", "/"),
        ("OPTIONS", "", "*"),
        ("DELETE", "/x", "/x"),
    ];
    for (method, path, origin) in cases {
        let raw = format!(
            "{method} http://{}{path} HTTP/1.1\r\nHost: {}\r\n\r\n",
            env.host(),
            env.host()
        );
        c.send(raw.as_bytes()).await;
        c.response(false).await;
        let got = env.up.requests().pop().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&got),
            format!(
                "{method} {origin} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                env.host()
            ),
            "{method} {path}"
        );
    }
    // Origin-form requests (a client that does not know it talks to a proxy) still work.
    c.send(format!("GET /bytes/3 HTTP/1.1\r\nHost: {}\r\n\r\n", env.host()).as_bytes())
        .await;
    assert_eq!(c.response(false).await.body, text_payload(3, 3));
    env.finish().await;
}

#[tokio::test]
async fn server_hop_by_hop_fields_do_not_reach_the_client() {
    let env = Env::new("resphop").await;
    let mut c = env.client().await;
    c.send(&env.request("GET", "/hop-resp", &[], b"")).await;
    let r = c.response(false).await;
    assert_eq!(
        r.head,
        "HTTP/1.1 200 OK\r\nX-End: kept\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n",
        "server's Connection, its listed field, Keep-Alive and Proxy-Connection removed"
    );
    assert_eq!(r.body, b"pong");
    // The server said close for its own hop; the client connection stays open.
    c.send(&env.request("GET", "/bytes/4", &[], b"")).await;
    assert_eq!(c.response(false).await.body, text_payload(4, 4));
    // The capture keeps the server's original head for diagnostics.
    let rec = env.record("/hop-resp").await;
    assert!(contains(&rec.response_body, b"X-Srv-Hop: internal"));
    // A client that asks to close gets Connection: close and a closed connection.
    c.send(&env.request("GET", "/bytes/4", &[("Connection", "close")], b""))
        .await;
    let r = c.response(false).await;
    assert!(r.head.ends_with("Connection: close\r\n\r\n"), "{}", r.head);
    assert!(c.closed().await);
    env.finish().await;
}

#[tokio::test]
async fn upgrade_keeps_its_headers_and_unrequested_101_is_refused() {
    let env = Env::new("upgrade").await;
    let mut c = env.client().await;
    c.send(&env.request(
        "GET",
        "/upgrade",
        &[
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "echo"),
            ("Sec-Test", "1"),
        ],
        b"",
    ))
    .await;
    let r = c.response(false).await;
    assert_eq!(r.status, 101);
    assert!(
        r.head.contains("Upgrade: echo") && r.head.contains("Connection: Upgrade"),
        "101 head unchanged: {}",
        r.head
    );
    let got = env.up.requests().pop().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&got),
        format!("GET /upgrade HTTP/1.1\r\nHost: {}\r\nUpgrade: echo\r\nSec-Test: 1\r\nConnection: Upgrade\r\n\r\n", env.host())
    );
    let big = bin_payload(MB, 5);
    c.send(&big).await;
    assert_eq!(
        sha(&c.take(big.len()).await),
        sha(&big),
        "1 MB relayed after the switch"
    );
    drop(c);

    // Upgrade without the Connection option is not an upgrade: the field is dropped.
    let mut c = env.client().await;
    c.send(&env.request("GET", "/bytes/2?noup", &[("Upgrade", "echo")], b""))
        .await;
    assert_eq!(c.response(false).await.status, 200);
    assert!(!contains(&env.up.requests().pop().unwrap(), b"Upgrade"));
    // A 101 the client never asked for is a protocol error, not a tunnel.
    c.send(&env.request("GET", "/srv-101", &[], b"")).await;
    assert!(c.response(false).await.head.starts_with("HTTP/1.1 502"));
    env.finish().await;
}
