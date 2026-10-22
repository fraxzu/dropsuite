//! P2 M2 regression: secrets hidden behind JSON escapes, nested JSON or percent-encoded URLs
//! never reach SQLite (db, WAL, shm) or the history API, while the traffic itself is
//! forwarded unchanged.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dropsuite_core::models::HistoryFilter;
use dropsuite_core::{ProxyEngine, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn escaped_and_nested_secrets_never_reach_storage() {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let marks: Vec<String> = ["ESCKEY", "ESCAMP", "STRJSON", "ENCURL", "REQENC", "REQJSON"]
        .iter()
        .map(|k| format!("DSMARK{k}{t:x}"))
        .collect();
    let response_body = format!(
        "{{\"p\\u0061ssword\":\"{}\",\"echo\":\"?a=1\\u0026Api_Key={}\",\"payload\":\"{{\\\"session\\\":\\\"{}\\\"}}\",\"next\":\"\\/cb?next=%2Fx%3Faccess_token%3D{}\",\"ok\":true}}",
        marks[0], marks[1], marks[2], marks[3]
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{response_body}",
        response_body.len()
    );

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let reply = response.clone();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = received.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = upstream.accept().await {
            let mut buf = vec![0u8; 65536];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            seen.lock().unwrap().extend_from_slice(&buf[..n]);
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    let db = std::env::temp_dir().join(format!("dropsuite-m2-escaped-{t:x}.db"));
    let storage = StorageManager::new(&db).unwrap();
    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let port = proxy.status().port;

    let req_body = format!(
        "user=synthetic&state=%7B%22password%22%3A%22{}%22%7D",
        marks[5]
    );
    let request = format!(
        "POST http://127.0.0.1:{up_port}/cb?next=%2Fhome%3Ftoken%3D{} HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{req_body}",
        marks[4],
        req_body.len()
    );
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut reply_bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut reply_bytes))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let contains = |hay: &[u8], m: &str| hay.windows(m.len()).any(|w| w == m.as_bytes());
    // Forwarding is untouched: every secret reached the origin and the client.
    let upstream_saw = received.lock().unwrap().clone();
    assert!(contains(&upstream_saw, &marks[4]) && contains(&upstream_saw, &marks[5]));
    assert!(
        marks[..4].iter().all(|m| contains(&reply_bytes, m)),
        "client got the original body"
    );

    // Nothing in what history serves...
    let summaries = storage.list_summaries(&HistoryFilter::default()).unwrap();
    assert_eq!(summaries.len(), 1);
    let record = storage
        .get_transaction_by_id(summaries[0].id)
        .unwrap()
        .unwrap();
    let served = [
        serde_json::to_vec(&summaries).unwrap(),
        serde_json::to_vec(&record).unwrap(),
        record.request_body.clone(),
        record.response_body.clone(),
    ]
    .concat();
    for m in &marks {
        assert!(!contains(&served, m), "{m} exposed through the history API");
    }
    // ...and nothing in the SQLite files, WAL and shared memory included.
    let files: Vec<u8> = ["", "-wal", "-shm"]
        .iter()
        .filter_map(|s| std::fs::read(format!("{}{s}", db.display())).ok())
        .collect::<Vec<_>>()
        .concat();
    for m in &marks {
        assert!(!contains(&files, m), "{m} found in SQLite files");
    }
    // Diagnostics stay useful: harmless fields are kept.
    assert!(contains(&record.response_body, "\"ok\":true"));
    assert!(record.path.contains("next=[REDACTED]"));

    proxy.shutdown().await;
    drop(storage);
    for s in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{s}", db.display()));
    }
}
