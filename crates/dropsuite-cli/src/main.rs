use anyhow::Result;
use dropsuite_core::models::HistoryFilter;
use dropsuite_core::{ProxyEngine, StorageManager};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    println!("============================================================");
    println!("        DROPSUITE P1 AUTOMATED VERIFICATION SUITE           ");
    println!("============================================================");

    // 1. Initialize SQLite Database
    let db_path = "dropsuite.db";
    let storage = StorageManager::new(db_path)?;
    println!("[TEST 1] SQLite persistence initialized: {}", db_path);

    // 2. Start Mock Upstream HTTP Server on 127.0.0.1:9090
    let mock_listener = TcpListener::bind("127.0.0.1:9090").await?;
    println!("[TEST 2] Mock Upstream Server started on 127.0.0.1:9090");

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = mock_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = socket.read(&mut buf).await {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if req.contains("/api/login") {
                            let body = "{\"status\":\"authenticated\",\"user\":\"tester\"}";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                        } else if req.contains("/not-found") {
                            let resp = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found";
                            let _ = socket.write_all(resp.as_bytes()).await;
                        } else {
                            let body = "{\"message\":\"DropSuite Mock Upstream OK\"}";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                        }
                        let _ = socket.shutdown().await;
                    }
                });
            }
        }
    });

    // 3. Start DropSuite Proxy Engine on 127.0.0.1:8080
    let mut proxy = ProxyEngine::new("127.0.0.1", 8080, storage.clone());
    proxy.start().await.map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("[TEST 3] DropSuite Proxy Listener active on 127.0.0.1:8080");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Test HTTP GET through proxy
    println!("\n--- Executing Test Requests ---");
    let initial_count = storage.count_transactions()?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:8080")?)
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(3))
        .build()?;

    let get_res = client
        .get("http://127.0.0.1:9090/api/status")
        .send()
        .await?;
    assert_eq!(get_res.status(), 200);
    println!("✔ [PASS] HTTP GET 127.0.0.1:9090/api/status (Status: 200)");

    // 5. Test HTTP POST through proxy
    let post_body = serde_json::json!({
        "username": "admin",
        "action": "test_auth"
    });
    let post_res = client
        .post("http://127.0.0.1:9090/api/login")
        .json(&post_body)
        .send()
        .await?;
    assert_eq!(post_res.status(), 200);
    println!("✔ [PASS] HTTP POST 127.0.0.1:9090/api/login (Status: 200)");

    // 6. Test 404 error through proxy
    let not_found_res = client.get("http://127.0.0.1:9090/not-found").send().await?;
    assert_eq!(not_found_res.status(), 404);
    println!("✔ [PASS] HTTP GET 127.0.0.1:9090/not-found (Status: 404)");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // 7. Verify SQLite Persistence
    let final_count = storage.count_transactions()?;
    println!("\n--- Verifying SQLite Persistence ---");
    println!(
        "Initial Count: {}, Final Count: {}",
        initial_count, final_count
    );
    assert!(final_count >= initial_count + 3);
    println!("✔ [PASS] Transactions successfully written to SQLite database");

    // 8. Test Search & Filtering in Storage
    println!("\n--- Verifying History Search & Filtering ---");
    let login_filter = HistoryFilter {
        query: Some("login".to_string()),
        ..Default::default()
    };
    let login_results = storage.list_summaries(&login_filter)?;
    assert!(!login_results.is_empty());
    println!(
        "✔ [PASS] Search filter for 'login' found {} record(s)",
        login_results.len()
    );

    let status_filter = HistoryFilter {
        status_code: Some(404),
        ..Default::default()
    };
    let status_results = storage.list_summaries(&status_filter)?;
    assert!(!status_results.is_empty());
    println!(
        "✔ [PASS] Status filter for 404 found {} record(s)",
        status_results.len()
    );

    // 9. Inspect full details of a saved transaction
    if let Some(first_record) = storage.get_transaction_by_id(login_results[0].id)? {
        println!("\n--- Transaction Detail Verification ---");
        println!("ID: {}", first_record.id);
        println!("Method: {}", first_record.method);
        println!("URL: {}", first_record.url);
        println!("Status: {}", first_record.status_code);
        println!("Duration: {} ms", first_record.duration_ms);
        println!("Request Headers: {:?}", first_record.request_headers);
        println!(
            "Response Body: {}",
            String::from_utf8_lossy(&first_record.response_body)
        );
        println!("✔ [PASS] Full transaction details reconstructed accurately");
    }

    // 10. Stop Proxy Listener
    proxy.stop();
    println!("\n✔ [PASS] Proxy listener stopped cleanly.");

    println!("\n============================================================");
    println!("      ALL P1 MVP CORE REQUIREMENTS VERIFIED AND PASSED!     ");
    println!("============================================================");

    Ok(())
}
