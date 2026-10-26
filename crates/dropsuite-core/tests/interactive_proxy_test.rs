use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dropsuite_core::interception::{
    HoldError, InterceptAction, InterceptEvent, InterceptManager, DEFAULT_INTERCEPT_TIMEOUT,
    MAX_INTERCEPT_BODY_SIZE, MAX_INTERCEPT_QUEUE_SIZE,
};
use dropsuite_core::{ProxyEngine, ScopeConfig, ScopeRule, ScopeRuleType, StorageManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("dropsuite-interactive-{tag}-{id}-{t:x}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Helper: start a recording mock server that captures full request details.
async fn start_recording_mock_server() -> (
    u16,
    Arc<Mutex<Vec<RecordedRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let records = Arc::new(Mutex::new(Vec::new()));
    let records_clone = records.clone();

    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let records = records_clone.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut total_read = 0;
                let mut body_start = None;
                let mut content_len = 0;

                loop {
                    match stream.read(&mut buf[total_read..]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            total_read += n;
                            if body_start.is_none() {
                                if let Some(idx) =
                                    buf[..total_read].windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    body_start = Some(idx + 4);
                                    let head_str = String::from_utf8_lossy(&buf[..idx]);
                                    for line in head_str.lines() {
                                        if let Some((k, v)) = line.split_once(':') {
                                            if k.trim().eq_ignore_ascii_case("content-length") {
                                                content_len =
                                                    v.trim().parse::<usize>().unwrap_or(0);
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(start) = body_start {
                                if total_read - start >= content_len {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                if total_read > 0 {
                    let head_end = body_start.map(|s| s - 4).unwrap_or(total_read);
                    let head_str = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let lines: Vec<&str> = head_str.lines().collect();
                    let first_line = lines.first().copied().unwrap_or("GET / HTTP/1.1");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("GET").to_string();
                    let path = parts.next().unwrap_or("/").to_string();

                    let mut headers = Vec::new();
                    for line in &lines[1..] {
                        if let Some((k, v)) = line.split_once(':') {
                            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                        }
                    }

                    let body = if let Some(start) = body_start {
                        buf[start..total_read].to_vec()
                    } else {
                        Vec::new()
                    };

                    records.lock().await.push(RecordedRequest {
                        method,
                        path: path.clone(),
                        headers,
                        body,
                    });

                    let resp_body = format!("{{\"echo\":\"{path}\"}}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });

    (port, records, handle)
}

/// Helper: start a test proxy engine.
/// A listener that counts every accepted TCP connection — used to prove an out-of-scope target
/// receives *no connection at all*, which is stronger than only checking that no request was recorded.
async fn start_counting_server() -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            c.fetch_add(1, Ordering::Relaxed);
            // Respond minimally so a real (buggy) connection wouldn't hang the client instead of failing loudly.
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });
    (port, count, handle)
}

async fn setup_proxy() -> (ProxyEngine, StorageManager, std::path::PathBuf, u16) {
    let dir = temp_dir("test");
    let db_path = dir.join("test.db");
    let storage = StorageManager::new(&db_path).unwrap();

    let mut proxy = ProxyEngine::new("127.0.0.1", 0, storage.clone());
    proxy.start().await.unwrap();
    let port = proxy.port();

    (proxy, storage, dir, port)
}

// ============================================================================
// 1. FORWARD REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_disabled_forwards_directly_without_holding() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    assert!(!proxy.intercept().is_enabled());

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("GET http://127.0.0.1:{server_port}/unintercepted HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = vec![0u8; 1024];
    let n = client.read(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp[..n]);

    assert!(text.contains("200 OK"));
    assert!(text.contains("/unintercepted"));
    assert_eq!(records.lock().await.len(), 1);
    assert_eq!(proxy.intercept().queue_len().await, 0);
}

#[tokio::test]
async fn intercept_forward_unmodified_reaches_origin() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    assert!(proxy.intercept().is_enabled());

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/held-req HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);
    assert_eq!(records.lock().await.len(), 0);

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(resolved);
    assert_eq!(proxy.intercept().queue_len().await, 0);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));
    assert!(client_resp.contains("/held-req"));
    assert_eq!(records.lock().await.len(), 1);
}

#[tokio::test]
async fn intercept_forward_post_with_body() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let payload = b"{\"username\":\"alice\",\"action\":\"login\"}";
    let payload_len = payload.len();

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!(
            "POST http://127.0.0.1:{server_port}/api/login HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nContent-Type: application/json\r\nContent-Length: {payload_len}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.write_all(payload).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            assert_eq!(list[0].method, "POST");
            assert_eq!(list[0].body_len, payload_len);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));

    let recs = records.lock().await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].method, "POST");
    assert_eq!(recs[0].path, "/api/login");
    assert_eq!(recs[0].body, payload);
}

#[tokio::test]
async fn intercept_forward_response_unmodified() {
    let (server_port, _records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    proxy.intercept().set_intercept_requests(false).await;
    proxy.intercept().set_intercept_responses(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/resp-test HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    // Wait until response is held (kind == "response")
    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if let Some(item) = list.iter().find(|i| i.kind == "response") {
            held_id = item.id;
            assert_eq!(item.status_code, Some(200));
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0, "Response should be held in intercept queue");

    // Forward unmodified response
    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));
    assert!(client_resp.contains("/resp-test"));
}

#[tokio::test]
async fn intercept_forward_all_held_requests() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let mut handles = Vec::new();
    for i in 1..=3 {
        let h = tokio::spawn(async move {
            let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            let req = format!("GET http://127.0.0.1:{server_port}/batch-{i} HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; 1024];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).to_string()
        });
        handles.push(h);
    }

    for _ in 0..50 {
        if proxy.intercept().queue_len().await == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(proxy.intercept().queue_len().await, 3);
    assert_eq!(records.lock().await.len(), 0);

    // Forward all with resolve_all
    proxy
        .intercept()
        .resolve_all(InterceptAction::Forward {
            modified_wire: None,
        })
        .await;
    assert_eq!(proxy.intercept().queue_len().await, 0);

    for h in handles {
        let resp = h.await.unwrap();
        assert!(resp.contains("200 OK"));
    }
    assert_eq!(records.lock().await.len(), 3);
}

#[tokio::test]
async fn turning_intercept_off_forwards_all_held_requests() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let mut handles = Vec::new();
    for i in 1..=2 {
        let h = tokio::spawn(async move {
            let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            let req = format!("GET http://127.0.0.1:{server_port}/item-{i} HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; 1024];
            let n = client.read(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp[..n]).to_string()
        });
        handles.push(h);
    }

    for _ in 0..50 {
        if proxy.intercept().queue_len().await == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(proxy.intercept().queue_len().await, 2);

    // Toggle intercept off: all held requests forwarded
    proxy.intercept().set_enabled(false).await;
    assert_eq!(proxy.intercept().queue_len().await, 0);

    for h in handles {
        let resp = h.await.unwrap();
        assert!(resp.contains("200 OK"));
    }
    assert_eq!(records.lock().await.len(), 2);
}

// ============================================================================
// 2. DROP REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_drop_request_terminates_connection_without_forwarding() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/should-be-dropped HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        n
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    let resolved = proxy
        .intercept()
        .resolve(held_id, InterceptAction::Drop)
        .await;
    assert!(resolved);
    assert_eq!(proxy.intercept().queue_len().await, 0);

    let bytes_read = client_task.await.unwrap();
    assert_eq!(
        bytes_read, 0,
        "Dropped request should close connection to client with 0 bytes"
    );
    assert_eq!(records.lock().await.len(), 0);
}

#[tokio::test]
async fn intercept_drop_response_terminates_client_connection() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    proxy.intercept().set_intercept_requests(false).await;
    proxy.intercept().set_intercept_responses(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/drop-resp HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        n
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if let Some(item) = list.iter().find(|i| i.kind == "response") {
            held_id = item.id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Drop the held response
    let resolved = proxy
        .intercept()
        .resolve(held_id, InterceptAction::Drop)
        .await;
    assert!(resolved);

    let bytes_read = client_task.await.unwrap();
    assert_eq!(
        bytes_read, 0,
        "Dropping response terminates connection to client"
    );
    assert_eq!(
        records.lock().await.len(),
        1,
        "Origin received request, but response was dropped"
    );
}

#[tokio::test]
async fn intercept_drop_all_held_requests() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let mut handles = Vec::new();
    for i in 1..=3 {
        let h = tokio::spawn(async move {
            let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            let req = format!("GET http://127.0.0.1:{server_port}/drop-all-{i} HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
            client.write_all(req.as_bytes()).await.unwrap();

            let mut resp = vec![0u8; 1024];
            let n = client.read(&mut resp).await.unwrap_or(0);
            n
        });
        handles.push(h);
    }

    for _ in 0..50 {
        if proxy.intercept().queue_len().await == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(proxy.intercept().queue_len().await, 3);

    // Drop all held requests
    proxy.intercept().resolve_all(InterceptAction::Drop).await;
    assert_eq!(proxy.intercept().queue_len().await, 0);

    for h in handles {
        let bytes_read = h.await.unwrap();
        assert_eq!(bytes_read, 0);
    }
    assert_eq!(records.lock().await.len(), 0);
}

// ============================================================================
// 3. EDIT REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_edit_request_before_forward() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/original-path HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    let edited_wire = format!(
        "GET /edited-by-user HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nX-DropSuite-Edited: true\r\nConnection: close\r\n\r\n"
    );

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: Some(edited_wire),
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));
    assert!(client_resp.contains("/edited-by-user"));

    let recs = records.lock().await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].path, "/edited-by-user");
    assert!(recs[0]
        .headers
        .iter()
        .any(|(k, v)| k == "x-dropsuite-edited" && v == "true"));
}

#[tokio::test]
async fn intercept_edit_request_headers_and_body() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let body = "{\"role\":\"guest\"}";
        let req = format!(
            "POST http://127.0.0.1:{server_port}/api/auth HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Edit both custom header and JSON body
    let edited_body = "{\"role\":\"administrator\",\"privilege\":\"root\"}";
    let edited_wire = format!(
        "POST /api/auth HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nContent-Type: application/json\r\nX-Privilege-Escalated: true\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        edited_body.len(),
        edited_body
    );

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: Some(edited_wire),
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));

    let recs = records.lock().await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].method, "POST");
    assert_eq!(recs[0].body, edited_body.as_bytes());
    assert!(recs[0]
        .headers
        .iter()
        .any(|(k, v)| k == "x-privilege-escalated" && v == "true"));
}

#[tokio::test]
async fn intercept_edit_request_invalid_syntax_returns_400() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/syntax-check HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Provide malformed wire string
    let bad_wire = "MALFORMED_GARBAGE_WITHOUT_HTTP_METHOD_AND_PATH\r\n\r\n";
    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: Some(bad_wire.to_string()),
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(
        client_resp.contains("400 Bad Request"),
        "Malformed edited request must produce 400 Bad Request to client, got: {client_resp}"
    );
    assert_eq!(
        records.lock().await.len(),
        0,
        "Malformed request must never be sent to origin server"
    );
}

#[tokio::test]
async fn intercept_edit_response_before_client_delivery() {
    let (server_port, _records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    proxy.intercept().set_intercept_requests(false).await;
    proxy.intercept().set_intercept_responses(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/teapot-test HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if let Some(item) = list.iter().find(|i| i.kind == "response") {
            held_id = item.id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Edit response to 418 I'm a teapot
    let teapot_body = "I am an intercepted teapot!";
    let edited_response = format!(
        "HTTP/1.1 418 I'm a teapot\r\nContent-Type: text/plain\r\nX-Intercepted-By: DropSuite\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        teapot_body.len(),
        teapot_body
    );

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: Some(edited_response),
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("418 I'm a teapot"));
    assert!(client_resp.contains("X-Intercepted-By: DropSuite"));
    assert!(client_resp.contains("I am an intercepted teapot!"));
}

// ============================================================================
// 4. CANCEL & DISCONNECT REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_cancel_held_request_via_remove_held() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/cancel-test HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        n
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Evict/cancel via remove_held without explicit user forward/drop
    let removed = proxy.intercept().remove_held(held_id).await;
    assert!(removed, "remove_held must return true for held item");
    assert_eq!(proxy.intercept().queue_len().await, 0);

    let bytes_read = client_task.await.unwrap();
    assert_eq!(bytes_read, 0, "Cancelled request closes client connection");
    assert_eq!(
        records.lock().await.len(),
        0,
        "Origin never sees cancelled request"
    );
}

#[tokio::test]
async fn intercept_client_disconnect_cancellation_handled_gracefully() {
    let (server_port, _records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("GET http://127.0.0.1:{server_port}/disconnect-test HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0);

    // Client abruptly closes connection before user makes decision
    drop(client);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Proxy handles forward on dead client socket gracefully without panic or hang
    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(resolved);
    assert_eq!(proxy.intercept().queue_len().await, 0);
}

#[tokio::test]
async fn duplicate_resolve_is_noop() {
    let mgr = InterceptManager::new();
    mgr.set_enabled(true).await;

    let (id, _rx) = mgr
        .hold_request(
            "GET".into(),
            "http://example.com/".into(),
            "example.com".into(),
            "/".into(),
            vec![],
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![],
        )
        .await
        .unwrap();

    let first = mgr
        .resolve(
            id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(first, "First resolve should succeed");

    let second = mgr.resolve(id, InterceptAction::Drop).await;
    assert!(
        !second,
        "Duplicate resolve must return false (cannot resolve twice)"
    );
}

// ============================================================================
// 5. TIMEOUT REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_request_timeout_returns_504() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    // Set short timeout of 100ms for test
    proxy.intercept().set_timeout(Duration::from_millis(100));

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/timeout-test HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    // Client is waiting, we take NO action.
    let client_resp = client_task.await.unwrap();

    assert!(
        client_resp.contains("504 Gateway Timeout"),
        "Timed-out request should yield 504 Gateway Timeout, got: {client_resp}"
    );
    assert!(client_resp.contains("intercepted request timed out"));
    assert_eq!(
        proxy.intercept().queue_len().await,
        0,
        "Evicted from queue on timeout"
    );
    assert_eq!(
        records.lock().await.len(),
        0,
        "Origin never contacted on timeout"
    );
}

#[tokio::test]
async fn intercept_response_timeout_auto_forwards() {
    let (server_port, _records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;
    proxy.intercept().set_intercept_requests(false).await;
    proxy.intercept().set_intercept_responses(true).await;
    proxy.intercept().set_timeout(Duration::from_millis(100));

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/resp-timeout HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    // Client waits, response times out and auto-forwards to avoid hanging client
    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));
    assert!(client_resp.contains("/resp-timeout"));
    assert_eq!(proxy.intercept().queue_len().await, 0);
}

// ============================================================================
// 6. CAPACITY & BACKPRESSURE REGRESSION TESTS
// ============================================================================

#[tokio::test]
async fn intercept_queue_capacity_limit_returns_503() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    // Fill queue to MAX_INTERCEPT_QUEUE_SIZE (100) using manager
    let mut receivers = Vec::new();
    for i in 0..MAX_INTERCEPT_QUEUE_SIZE {
        let (id, rx) = proxy
            .intercept()
            .hold_request(
                "GET".into(),
                format!("http://example.com/{i}"),
                "example.com".into(),
                format!("/{i}"),
                vec![],
                format!("GET /{i} HTTP/1.1\r\n\r\n").into_bytes(),
                vec![],
            )
            .await
            .unwrap();
        assert!(id > 0);
        receivers.push(rx);
    }
    assert_eq!(
        proxy.intercept().queue_len().await,
        MAX_INTERCEPT_QUEUE_SIZE
    );

    // 101st request through proxy gets rejected with 503 Service Unavailable
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let req = format!("GET http://127.0.0.1:{server_port}/overflow HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();

    let mut resp = vec![0u8; 1024];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);

    assert!(
        resp_str.contains("503 Service Unavailable"),
        "Overflow request must return 503 Service Unavailable, got: {resp_str}"
    );
    assert!(resp_str.contains("intercept queue capacity reached"));
    assert_eq!(records.lock().await.len(), 0);

    // Clean up queue
    proxy.intercept().resolve_all(InterceptAction::Drop).await;
    assert_eq!(proxy.intercept().queue_len().await, 0);
}

#[tokio::test]
async fn intercept_queue_recovery_after_drain() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    // Fill queue
    for i in 0..MAX_INTERCEPT_QUEUE_SIZE {
        let _ = proxy
            .intercept()
            .hold_request(
                "GET".into(),
                format!("http://example.com/{i}"),
                "example.com".into(),
                format!("/{i}"),
                vec![],
                format!("GET /{i} HTTP/1.1\r\n\r\n").into_bytes(),
                vec![],
            )
            .await
            .unwrap();
    }
    assert_eq!(
        proxy.intercept().queue_len().await,
        MAX_INTERCEPT_QUEUE_SIZE
    );

    // Drain queue completely
    proxy.intercept().resolve_all(InterceptAction::Drop).await;
    assert_eq!(proxy.intercept().queue_len().await, 0);

    // Now send a new request: it must be accepted and held normally!
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!("GET http://127.0.0.1:{server_port}/after-drain HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(held_id > 0, "Queue must accept new requests after drain");

    let resolved = proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: None,
            },
        )
        .await;
    assert!(resolved);

    let client_resp = client_task.await.unwrap();
    assert!(client_resp.contains("200 OK"));
    assert_eq!(records.lock().await.len(), 1);
}

#[tokio::test]
async fn intercept_large_body_limit_enforced() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.intercept().set_enabled(true).await;

    let oversized = MAX_INTERCEPT_BODY_SIZE + 1024; // 1 MB + 1 KB

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let head = format!(
            "POST http://127.0.0.1:{server_port}/oversized HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nContent-Length: {oversized}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(head.as_bytes()).await.unwrap();

        // Stream oversized body
        let chunk = vec![b'A'; 65536];
        let mut sent = 0;
        while sent < oversized {
            let to_send = (oversized - sent).min(chunk.len());
            if client.write_all(&chunk[..to_send]).await.is_err() {
                break;
            }
            sent += to_send;
        }

        let mut resp = vec![0u8; 1024];
        let n = client.read(&mut resp).await.unwrap_or(0);
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let client_resp = client_task.await.unwrap();
    assert!(
        client_resp.contains("413 Payload Too Large"),
        "Oversized request body must return 413 Payload Too Large, got: {client_resp}"
    );
    assert_eq!(proxy.intercept().queue_len().await, 0);
    assert_eq!(records.lock().await.len(), 0);
}

// ============================================================================
// SCOPE RE-VALIDATION AFTER EDIT (security regression)
// ============================================================================

/// An in-scope request that is intercepted and then edited to point at an OUT-OF-SCOPE host must be
/// refused before any upstream connection — scope has to be re-checked on the edited target, not
/// only on the original URL. Without the re-check the edited request would reach the out-of-scope
/// server, defeating the "Drop out-of-scope (Zero Egress)" guarantee.
#[tokio::test]
async fn scope_recheck_blocks_request_edited_out_of_scope() {
    // Two origins on 127.0.0.1; scope will include only the first one (by port).
    let (in_scope_port, in_records, _s1) = start_recording_mock_server().await;
    let (out_port, out_accepts, _s2) = start_counting_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;

    proxy.scope().set_config(ScopeConfig {
        enabled: true,
        drop_out_of_scope: true,
        rules: vec![ScopeRule {
            id: "in".into(),
            enabled: true,
            rule_type: ScopeRuleType::Include,
            protocol: None,
            host: "127.0.0.1".into(),
            port: Some(in_scope_port), // only the in-scope origin's port is allowed
            path_prefix: None,
        }],
    });
    proxy.intercept().set_enabled(true).await;

    // Client sends an IN-SCOPE request (so it passes the initial check and gets held).
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{in_scope_port}/legit HTTP/1.1\r\nHost: 127.0.0.1:{in_scope_port}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = vec![0u8; 2048];
        let n = client.read(&mut resp).await.unwrap_or(0);
        String::from_utf8_lossy(&resp[..n]).to_string()
    });

    let mut held_id = 0;
    for _ in 0..50 {
        let list = proxy.intercept().list_held().await;
        if !list.is_empty() {
            held_id = list[0].id;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        held_id > 0,
        "the in-scope request should have been held for interception"
    );

    // Edit it to target the OUT-OF-SCOPE origin, then forward.
    let edited = format!(
        "GET http://127.0.0.1:{out_port}/evil HTTP/1.1\r\nHost: 127.0.0.1:{out_port}\r\nConnection: close\r\n\r\n"
    );
    proxy
        .intercept()
        .resolve(
            held_id,
            InterceptAction::Forward {
                modified_wire: Some(edited),
            },
        )
        .await;

    let client_resp = client_task.await.unwrap();
    assert!(
        client_resp.contains("403") && client_resp.to_lowercase().contains("out of scope"),
        "edited out-of-scope request must be refused with 403, got: {client_resp}"
    );
    // The decisive proof: the out-of-scope origin got NO TCP connection at all (not merely "no
    // recorded request"), and the original in-scope origin was not hit either.
    assert_eq!(
        out_accepts.load(Ordering::Relaxed),
        0,
        "out-of-scope origin must receive no TCP connection"
    );
    assert_eq!(
        in_records.lock().await.len(),
        0,
        "the original in-scope origin must not be hit either"
    );
}

// ============================================================================
// 7. STATE, TIMEOUT EDGE CASES, BACKPRESSURE RECOVERY & CONCURRENCY
// ============================================================================

/// Sends one GET through the proxy and returns everything the client receives
/// ("" when the proxy closes the connection without replying, e.g. on Drop).
fn spawn_get(proxy_port: u16, server_port: u16, path: String) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{server_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        // A reset (Windows) after Drop is an expected outcome, so read errors are ignored.
        let _ = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut resp))
            .await
            .expect("client read hung for 10s");
        String::from_utf8_lossy(&resp).to_string()
    })
}

async fn wait_for_queue(mgr: &InterceptManager, n: usize) {
    for _ in 0..250 {
        if mgr.queue_len().await == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("queue never reached {n} (now {})", mgr.queue_len().await);
}

async fn wait_for_held(mgr: &InterceptManager, kind: &str, path: &str) -> u64 {
    for _ in 0..250 {
        if let Some(item) = mgr
            .list_held()
            .await
            .into_iter()
            // `path` holds the raw request target, which is a full URL for plain-HTTP proxy
            // requests, so match on the end of `url` instead.
            .find(|i| i.kind == kind && i.url.ends_with(path))
        {
            return item.id;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let queued: Vec<_> = mgr
        .list_held()
        .await
        .into_iter()
        .map(|i| format!("{}:{}:{}", i.kind, i.path, i.url))
        .collect();
    panic!("no held {kind} for {path}; queue holds {queued:?}");
}

async fn hold_synthetic(
    mgr: &InterceptManager,
    i: usize,
) -> (u64, tokio::sync::oneshot::Receiver<InterceptAction>) {
    mgr.hold_request(
        "GET".into(),
        format!("http://example.com/{i}"),
        "example.com".into(),
        format!("/synthetic-{i}"),
        vec![],
        format!("GET /synthetic-{i} HTTP/1.1\r\n\r\n").into_bytes(),
        vec![],
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn intercept_status_reports_defaults_and_tracks_changes() {
    let mgr = InterceptManager::new();

    // Defaults: master switch off, request sub-toggle on, response sub-toggle off, 60s timeout.
    let st = mgr.status().await;
    assert!(!st.enabled);
    assert!(st.intercept_requests);
    assert!(!st.intercept_responses);
    assert_eq!(st.queue_len, 0);
    assert_eq!(mgr.timeout(), DEFAULT_INTERCEPT_TIMEOUT);

    // The master switch overrides the request sub-toggle.
    assert!(!mgr.is_intercept_requests_enabled());
    let res = mgr
        .hold_request(
            "GET".into(),
            "u".into(),
            "h".into(),
            "/".into(),
            vec![],
            vec![],
            vec![],
        )
        .await;
    assert!(matches!(res, Err(HoldError::Disabled)));

    let st = mgr.set_enabled(true).await;
    assert!(st.enabled && st.intercept_requests && !st.intercept_responses);
    let st = mgr.set_intercept_responses(true).await;
    assert!(st.intercept_requests && st.intercept_responses);

    let (_req_id, req_rx) = hold_synthetic(&mgr, 1).await;
    assert_eq!(mgr.status().await.queue_len, 1);

    // Turning off request interception stops new holds but does not release the held item.
    let st = mgr.set_intercept_requests(false).await;
    assert!(!st.intercept_requests && st.intercept_responses);
    assert_eq!(st.queue_len, 1);
    let res = mgr
        .hold_request(
            "GET".into(),
            "u".into(),
            "h".into(),
            "/".into(),
            vec![],
            vec![],
            vec![],
        )
        .await;
    assert!(matches!(res, Err(HoldError::Disabled)));

    // Responses can still be held on their own.
    let (_resp_id, _resp_rx) = mgr
        .hold_response(
            "GET".into(),
            "u".into(),
            200,
            "h".into(),
            "/r".into(),
            vec![],
            vec![],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(mgr.status().await.queue_len, 2);

    // Master switch off releases everything as an unmodified forward.
    let st = mgr.set_enabled(false).await;
    assert!(!st.enabled);
    assert_eq!(st.queue_len, 0);
    assert_eq!(
        req_rx.await.unwrap(),
        InterceptAction::Forward {
            modified_wire: None
        }
    );

    // A zero timeout is clamped to 1ms instead of disabling the wait.
    mgr.set_timeout(Duration::ZERO);
    assert_eq!(mgr.timeout(), Duration::from_millis(1));
}

#[tokio::test]
async fn intercept_request_and_response_toggles_are_independent() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;
    let mgr = proxy.intercept();

    // Master on, both sub-toggles off: traffic passes straight through.
    mgr.set_enabled(true).await;
    mgr.set_intercept_requests(false).await;
    mgr.set_intercept_responses(false).await;
    let resp = spawn_get(proxy_port, server_port, "/both-off".into())
        .await
        .unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("/both-off"),
        "got: {resp}"
    );
    assert_eq!(mgr.queue_len().await, 0);
    assert_eq!(records.lock().await.len(), 1);

    // Both on: the same exchange is held twice — first the request, then the response.
    mgr.set_intercept_requests(true).await;
    mgr.set_intercept_responses(true).await;
    let client = spawn_get(proxy_port, server_port, "/both-on".into());

    let req_id = wait_for_held(&mgr, "request", "/both-on").await;
    assert_eq!(
        records.lock().await.len(),
        1,
        "origin must not be hit while the request is held"
    );
    assert!(
        mgr.resolve(
            req_id,
            InterceptAction::Forward {
                modified_wire: None
            }
        )
        .await
    );

    let resp_id = wait_for_held(&mgr, "response", "/both-on").await;
    assert_ne!(resp_id, req_id);
    assert_eq!(
        records.lock().await.len(),
        2,
        "origin is hit once the request is forwarded"
    );
    assert_eq!(mgr.get_held(resp_id).await.unwrap().status_code, Some(200));
    assert!(
        mgr.resolve(
            resp_id,
            InterceptAction::Forward {
                modified_wire: None
            }
        )
        .await
    );

    let resp = client.await.unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("/both-on"),
        "got: {resp}"
    );
    assert_eq!(mgr.queue_len().await, 0);
}

#[tokio::test]
async fn intercept_timeout_evicts_only_the_unanswered_request() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;
    let mgr = proxy.intercept();

    let timeout = Duration::from_millis(600);
    mgr.set_enabled(true).await;
    mgr.set_timeout(timeout);

    let started = std::time::Instant::now();
    let answered = spawn_get(proxy_port, server_port, "/answered".into());
    let ignored = spawn_get(proxy_port, server_port, "/ignored".into());
    wait_for_queue(&mgr, 2).await;

    let answered_id = wait_for_held(&mgr, "request", "/answered").await;
    let ignored_id = wait_for_held(&mgr, "request", "/ignored").await;
    assert!(
        mgr.resolve(
            answered_id,
            InterceptAction::Forward {
                modified_wire: None
            }
        )
        .await
    );

    // The custom timeout is honoured: the ignored request is not evicted early.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        started.elapsed() < timeout,
        "test setup took longer than the timeout"
    );
    assert!(
        mgr.get_held(ignored_id).await.is_some(),
        "evicted before its timeout"
    );

    let answered_resp = answered.await.unwrap();
    assert!(answered_resp.contains("200 OK") && answered_resp.contains("/answered"));

    let ignored_resp = ignored.await.unwrap();
    assert!(
        ignored_resp.contains("504 Gateway Timeout"),
        "got: {ignored_resp}"
    );
    assert!(started.elapsed() >= timeout - Duration::from_millis(50));

    assert_eq!(mgr.queue_len().await, 0);
    let recs = records.lock().await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].path, "/answered");
}

#[tokio::test]
async fn intercept_queue_full_then_drop_one_resumes_normal_operation() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;
    let mgr = proxy.intercept();
    mgr.set_enabled(true).await;

    let mut held = Vec::new();
    for i in 0..MAX_INTERCEPT_QUEUE_SIZE {
        held.push(hold_synthetic(&mgr, i).await);
    }
    assert_eq!(mgr.queue_len().await, MAX_INTERCEPT_QUEUE_SIZE);

    // Full: the next real request is refused and never queued or sent.
    let overflow = spawn_get(proxy_port, server_port, "/overflow".into())
        .await
        .unwrap();
    assert!(
        overflow.contains("503 Service Unavailable"),
        "got: {overflow}"
    );
    assert!(!mgr
        .list_held()
        .await
        .iter()
        .any(|i| i.url.ends_with("/overflow")));

    // Drop a single held item to free one slot.
    let (first_id, first_rx) = held.remove(0);
    assert!(mgr.resolve(first_id, InterceptAction::Drop).await);
    assert_eq!(first_rx.await.unwrap(), InterceptAction::Drop);
    assert_eq!(mgr.queue_len().await, MAX_INTERCEPT_QUEUE_SIZE - 1);

    // The freed slot is usable by a real request again.
    let client = spawn_get(proxy_port, server_port, "/after-free".into());
    let id = wait_for_held(&mgr, "request", "/after-free").await;
    assert_eq!(mgr.queue_len().await, MAX_INTERCEPT_QUEUE_SIZE);
    assert!(
        mgr.resolve(
            id,
            InterceptAction::Forward {
                modified_wire: None
            }
        )
        .await
    );

    let resp = client.await.unwrap();
    assert!(
        resp.contains("200 OK") && resp.contains("/after-free"),
        "got: {resp}"
    );
    {
        let recs = records.lock().await;
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].path, "/after-free");
    }

    mgr.resolve_all(InterceptAction::Drop).await;
    assert_eq!(mgr.queue_len().await, 0);
}

#[tokio::test]
async fn intercept_ten_concurrent_requests_resolved_individually() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;
    let mgr = proxy.intercept();
    mgr.set_enabled(true).await;

    let paths: Vec<String> = (1..=10).map(|i| format!("/conc-{i:02}")).collect();
    let clients: Vec<_> = paths
        .iter()
        .map(|p| spawn_get(proxy_port, server_port, p.clone()))
        .collect();
    wait_for_queue(&mgr, 10).await;
    assert_eq!(records.lock().await.len(), 0);

    let mut ids = Vec::new();
    for p in &paths {
        ids.push(wait_for_held(&mgr, "request", p).await);
    }
    let unique: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), 10, "every held request needs its own id");

    // Resolve all ten at the same time, each through its own task.
    let resolvers: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let mgr = mgr.clone();
            tokio::spawn(async move {
                mgr.resolve(
                    id,
                    InterceptAction::Forward {
                        modified_wire: None,
                    },
                )
                .await
            })
        })
        .collect();
    for r in resolvers {
        assert!(r.await.unwrap());
    }

    // Each client gets its own response, not another client's.
    for (client, p) in clients.into_iter().zip(&paths) {
        let resp = client.await.unwrap();
        assert!(resp.contains("200 OK"), "{p}: {resp}");
        assert!(
            resp.contains(&format!("{{\"echo\":\"{p}\"}}")),
            "{p} got someone else's response: {resp}"
        );
    }
    assert_eq!(mgr.queue_len().await, 0);

    let mut seen: Vec<String> = records
        .lock()
        .await
        .iter()
        .map(|r| r.path.clone())
        .collect();
    seen.sort();
    assert_eq!(seen, paths);
}

#[tokio::test]
async fn intercept_mixed_resolve_actions_concurrently() {
    let (server_port, records, _server) = start_recording_mock_server().await;
    let (proxy, _storage, _dir, proxy_port) = setup_proxy().await;
    let mgr = proxy.intercept();
    mgr.set_enabled(true).await;

    let paths: Vec<String> = (0..6).map(|i| format!("/mix-{i}")).collect();
    let clients: Vec<_> = paths
        .iter()
        .map(|p| spawn_get(proxy_port, server_port, p.clone()))
        .collect();
    wait_for_queue(&mgr, 6).await;

    // 0-1 forward as-is, 2-3 forward edited, 4-5 drop — all at once.
    let mut resolvers = Vec::new();
    for (i, p) in paths.iter().enumerate() {
        let id = wait_for_held(&mgr, "request", p).await;
        let action = match i {
            0 | 1 => InterceptAction::Forward { modified_wire: None },
            2 | 3 => InterceptAction::Forward {
                modified_wire: Some(format!(
                    "GET {p}-edited HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nConnection: close\r\n\r\n"
                )),
            },
            _ => InterceptAction::Drop,
        };
        let mgr = mgr.clone();
        resolvers.push(tokio::spawn(async move { mgr.resolve(id, action).await }));
    }
    for r in resolvers {
        assert!(r.await.unwrap());
    }

    for (i, client) in clients.into_iter().enumerate() {
        let resp = client.await.unwrap();
        let p = &paths[i];
        match i {
            0 | 1 => assert!(
                resp.contains("200 OK") && resp.contains(&format!("\"{p}\"")),
                "{p}: {resp}"
            ),
            2 | 3 => assert!(
                resp.contains("200 OK") && resp.contains(&format!("\"{p}-edited\"")),
                "{p}: {resp}"
            ),
            _ => assert!(
                resp.is_empty(),
                "dropped {p} must get no bytes, got: {resp}"
            ),
        }
    }
    assert_eq!(mgr.queue_len().await, 0);

    let mut seen: Vec<String> = records
        .lock()
        .await
        .iter()
        .map(|r| r.path.clone())
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec!["/mix-0", "/mix-1", "/mix-2-edited", "/mix-3-edited"]
    );
}

#[tokio::test]
async fn intercept_events_report_hold_and_resolution() {
    let mgr = InterceptManager::new();
    let mut events = mgr.subscribe();
    mgr.set_enabled(true).await;

    let (edited_id, _rx1) = hold_synthetic(&mgr, 1).await;
    let (evicted_id, _rx2) = hold_synthetic(&mgr, 2).await;
    assert!(
        mgr.resolve(
            edited_id,
            InterceptAction::Forward {
                modified_wire: Some("GET / HTTP/1.1\r\n\r\n".into())
            }
        )
        .await
    );
    assert!(mgr.remove_held(evicted_id).await);

    let mut held_ids = Vec::new();
    let mut resolved = Vec::new();
    let mut last_queue_len = None;
    while let Ok(ev) = events.try_recv() {
        match ev {
            InterceptEvent::MessageHeld(s) => held_ids.push(s.id),
            InterceptEvent::MessageResolved { id, action } => resolved.push((id, action)),
            InterceptEvent::StateChanged(st) => last_queue_len = Some(st.queue_len),
        }
    }
    assert_eq!(held_ids, vec![edited_id, evicted_id]);
    assert_eq!(
        resolved,
        vec![
            (edited_id, "forward_modified".to_string()),
            (evicted_id, "evicted".to_string())
        ]
    );
    assert_eq!(
        last_queue_len,
        Some(0),
        "the UI's last state update must show an empty queue"
    );
}
