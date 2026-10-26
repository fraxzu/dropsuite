//! Regression: a request addressed to the proxy's own listener (a browser or curl pointed
//! straight at the proxy port) once looped back into the proxy, nesting connections until
//! Windows ran out of sockets (os error 10055) and every level stored a 502 record. It must be
//! refused at once with a single response and nothing captured, while normal forwarding still
//! returns exactly one response per request.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dropsuite_core::models::HistoryFilter;
use dropsuite_core::{ProxyEngine, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn temp_db(tag: &str) -> std::path::PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "dropsuite-loop-{tag}-{:x}{t:x}.db",
        std::process::id()
    ))
}

fn remove_db(db: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", db.display(), suffix));
    }
}

async fn send(proxy_port: u16, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("proxy answered and closed within 5 s")
        .unwrap();
    out
}

fn status_lines(resp: &[u8]) -> usize {
    resp.windows(9).filter(|w| w == b"HTTP/1.1 ").count()
}

fn stored(storage: &StorageManager) -> usize {
    storage
        .list_summaries(&HistoryFilter::default())
        .unwrap()
        .len()
}

#[tokio::test]
async fn request_to_own_listener_is_refused_without_looping() {
    let db = temp_db("self");
    let storage = StorageManager::new(&db).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let port = proxy.status().port;

    // Origin-form (browser opened http://127.0.0.1:<port>/) and absolute-form through the
    // proxy to its own address (curl -x proxy http://127.0.0.1:<port>/), plus "localhost".
    let requests = [
        format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
    ];
    for raw in &requests {
        let resp = send(port, raw.as_bytes()).await;
        assert!(
            resp.starts_with(b"HTTP/1.1 508 Loop Detected\r\n"),
            "loop refused with 508, got: {}",
            String::from_utf8_lossy(&resp)
        );
        assert_eq!(status_lines(&resp), 1, "exactly one response");
    }
    assert_eq!(stored(&storage), 0, "refused loops are not captured");

    proxy.shutdown().await;
    drop(storage);
    remove_db(&db);
}

#[tokio::test]
async fn forwarded_request_gets_exactly_one_response() {
    let upstream_resp: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"status\":\"healthy\"}";
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = upstream.accept().await {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(upstream_resp).await;
            let _ = sock.shutdown().await;
        }
    });

    let db = temp_db("fwd");
    let storage = StorageManager::new(&db).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let port = proxy.status().port;

    // The client asks to close, so the proxy answers and closes. The server's own
    // `Connection: close` concerns only the upstream hop and is not passed on (P1.9).
    let raw = format!(
        "GET http://127.0.0.1:{up_port}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nConnection: close\r\n\r\n"
    );
    let resp = send(port, raw.as_bytes()).await;
    assert_eq!(
        resp,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{\"status\":\"healthy\"}",
        "client receives the status line, end-to-end fields and body unchanged"
    );
    assert_eq!(status_lines(&resp), 1, "exactly one response");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(stored(&storage), 1, "one request, one capture");

    proxy.shutdown().await;
    drop(storage);
    remove_db(&db);
}
