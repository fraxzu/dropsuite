use dropsuite_core::models::HistoryFilter;
use dropsuite_core::{ProxyEngine, StorageManager};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    println!("============================================================");
    println!("          DROPSUITE DESKTOP BACKEND DAEMON                  ");
    println!("============================================================");

    // Overrides exist for isolated test runs; the defaults are the shipping configuration.
    let db_path = std::env::var("DROPSUITE_DB_PATH").unwrap_or_else(|_| "dropsuite.db".to_string());
    let port_var = |name: &str, default: u16| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let proxy_port = port_var("DROPSUITE_PROXY_PORT", 8080);
    let api_port = port_var("DROPSUITE_API_PORT", 8081);

    let storage = StorageManager::new(&db_path)?;
    println!("[STORAGE] Connected to SQLite database: {}", db_path);

    let data_dir = std::env::var("DROPSUITE_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut proxy_engine = ProxyEngine::new("127.0.0.1", proxy_port, storage.clone());
    let https_cfg = dropsuite_core::HttpsInterceptConfig {
        ca_dir: data_dir.join("ca"),
        allowlist: dropsuite_core::InterceptAllowlist::loopback_default(),
        upstream_roots: Vec::new(),
    };
    proxy_engine.set_https_interception(https_cfg);
    let proxy = Arc::new(Mutex::new(proxy_engine));

    // Auto-start proxy by default
    {
        let mut p = proxy.lock().await;
        if let Err(e) = p.start().await {
            eprintln!("Failed to auto-start proxy: {}", e);
        } else {
            println!("[PROXY] Listening on http://127.0.0.1:{}", proxy_port);
        }
    }

    // Start local API server for the frontend UI.
    let api_addr = format!("127.0.0.1:{}", api_port);
    let api_listener = TcpListener::bind(&api_addr).await?;
    println!(
        "[API] DropSuite Desktop Bridge running on http://{}",
        api_addr
    );

    let storage_clone = storage.clone();
    let proxy_clone = proxy.clone();

    loop {
        if let Ok((mut stream, _)) = api_listener.accept().await {
            let storage = storage_clone.clone();
            let proxy = proxy_clone.clone();

            tokio::spawn(async move {
                let mut buffer = [0u8; 8192];
                if let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buffer[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    let parts: Vec<&str> = first_line.split_whitespace().collect();

                    if parts.len() < 2 {
                        return;
                    }

                    let method = parts[0];
                    let raw_path = parts[1];
                    let (path, query_str) = if let Some(idx) = raw_path.find('?') {
                        (&raw_path[..idx], &raw_path[idx + 1..])
                    } else {
                        (raw_path, "")
                    };

                    // Origin validation: only allow local origins (localhost / 127.0.0.1 / tauri)
                    let origin_line = req_str
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("origin:"));
                    let req_origin = origin_line
                        .map(|l| l["origin:".len()..].trim())
                        .unwrap_or("");

                    let allowed_origin = if req_origin.is_empty() {
                        "http://localhost:3000"
                    } else if req_origin.starts_with("http://localhost:")
                        || req_origin.starts_with("http://127.0.0.1:")
                        || req_origin.starts_with("http://tauri.localhost")
                        || req_origin.starts_with("tauri://")
                    {
                        req_origin
                    } else {
                        let forbidden = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 19\r\n\r\nForbidden (Origin)";
                        let _ = stream.write_all(forbidden.as_bytes()).await;
                        return;
                    };

                    let cors = format!(
                        "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n",
                        allowed_origin
                    );

                    if method == "OPTIONS" {
                        let resp = format!("HTTP/1.1 204 No Content\r\n{}\r\n", cors);
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }

                    if path == "/api/status" {
                        let status = {
                            let p = proxy.lock().await;
                            p.status()
                        };
                        let json = serde_json::to_string(&status).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/proxy/start" && method == "POST" {
                        let mut p = proxy.lock().await;
                        let _ = p.start().await;
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: 15\r\n\r\n{{\"status\":\"ok\"}}", cors);
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/proxy/stop" && method == "POST" {
                        let mut p = proxy.lock().await;
                        p.stop();
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: 15\r\n\r\n{{\"status\":\"ok\"}}", cors);
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/history" {
                        let mut filter = HistoryFilter::default();
                        for param in query_str.split('&') {
                            let kv: Vec<&str> = param.split('=').collect();
                            if kv.len() == 2 {
                                if kv[0] == "q" && !kv[1].is_empty() {
                                    filter.query = Some(kv[1].to_string());
                                } else if kv[0] == "method" && !kv[1].is_empty() {
                                    filter.method = Some(kv[1].to_string());
                                } else if kv[0] == "status" {
                                    filter.status_code = kv[1].parse().ok();
                                }
                            }
                        }

                        let summaries = storage.list_summaries(&filter).unwrap_or_default();
                        let json = serde_json::to_string(&summaries).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/intercept/status" {
                        let st = {
                            let p = proxy.lock().await;
                            p.intercept().status().await
                        };
                        let json = serde_json::to_string(&st).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/intercept/enabled" && method == "POST" {
                        let enabled = !query_str.contains("enabled=false");
                        let st = {
                            let p = proxy.lock().await;
                            p.intercept().set_enabled(enabled).await
                        };
                        let json = serde_json::to_string(&st).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/intercept/messages" {
                        let list = {
                            let p = proxy.lock().await;
                            p.intercept().list_held().await
                        };
                        let json = serde_json::to_string(&list).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if let Some(id_str) = path.strip_prefix("/api/intercept/forward/") {
                        if let Ok(id) = id_str.parse::<u64>() {
                            let p = proxy.lock().await;
                            let ok = p
                                .intercept()
                                .resolve(
                                    id,
                                    dropsuite_core::interception::InterceptAction::Forward {
                                        modified_wire: None,
                                    },
                                )
                                .await;
                            let json = format!("{{\"ok\":{ok}}}");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if let Some(id_str) = path.strip_prefix("/api/intercept/drop/") {
                        if let Ok(id) = id_str.parse::<u64>() {
                            let p = proxy.lock().await;
                            let ok = p
                                .intercept()
                                .resolve(id, dropsuite_core::interception::InterceptAction::Drop)
                                .await;
                            let json = format!("{{\"ok\":{ok}}}");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if let Some(id_str) = path.strip_prefix("/api/history/") {
                        if let Ok(id) = id_str.parse::<i64>() {
                            if let Ok(Some(record)) = storage.get_transaction_by_id(id) {
                                let json = serde_json::to_string(&record).unwrap_or_default();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                    cors, json.len(), json
                                );
                                let _ = stream.write_all(resp.as_bytes()).await;
                                return;
                            }
                        }
                        let not_found = "{\"error\":\"Transaction not found\"}";
                        let resp = format!("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}", cors, not_found.len(), not_found);
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/repeater/tabs" && method == "GET" {
                        let tabs = storage.list_repeater_tabs().unwrap_or_default();
                        let json = serde_json::to_string(&tabs).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/repeater/tabs" && method == "POST" {
                        let body_str = req_str
                            .find("\r\n\r\n")
                            .map(|i| &req_str[i + 4..])
                            .unwrap_or("");
                        if let Ok(tab) =
                            serde_json::from_str::<dropsuite_core::RepeaterTabRecord>(body_str)
                        {
                            let id = storage.save_repeater_tab(&tab).unwrap_or(-1);
                            let json = format!("{{\"id\":{id}}}");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\n{}Content-Length: 0\r\n\r\n",
                                cors
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if let Some(id_str) = path.strip_prefix("/api/repeater/tabs/") {
                        if method == "DELETE" {
                            if let Ok(id) = id_str.parse::<i64>() {
                                let _ = storage.delete_repeater_tab(id);
                                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: 15\r\n\r\n{{\"status\":\"ok\"}}", cors);
                                let _ = stream.write_all(resp.as_bytes()).await;
                            }
                        }
                    } else if path == "/api/repeater/attempts" && method == "GET" {
                        let mut tab_id = 0i64;
                        for param in query_str.split('&') {
                            let kv: Vec<&str> = param.split('=').collect();
                            if kv.len() == 2 && kv[0] == "tab_id" {
                                tab_id = kv[1].parse().unwrap_or(0);
                            }
                        }
                        let attempts = storage
                            .list_repeater_attempts(tab_id, None)
                            .unwrap_or_default();
                        let json = serde_json::to_string(&attempts).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/repeater/attempts" && method == "POST" {
                        let body_str = req_str
                            .find("\r\n\r\n")
                            .map(|i| &req_str[i + 4..])
                            .unwrap_or("");
                        if let Ok(attempt) =
                            serde_json::from_str::<dropsuite_core::RepeaterAttemptRecord>(body_str)
                        {
                            let id = storage.save_repeater_attempt(&attempt).unwrap_or(-1);
                            let json = format!("{{\"id\":{id}}}");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\n{}Content-Length: 0\r\n\r\n",
                                cors
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if path == "/api/repeater/attempts" && method == "DELETE" {
                        let mut tab_id = 0i64;
                        for param in query_str.split('&') {
                            let kv: Vec<&str> = param.split('=').collect();
                            if kv.len() == 2 && kv[0] == "tab_id" {
                                tab_id = kv[1].parse().unwrap_or(0);
                            }
                        }
                        let _ = storage.clear_repeater_attempts(tab_id);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: 15\r\n\r\n{{\"status\":\"ok\"}}", cors);
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/history/export/har" && method == "POST" {
                        let body_str = req_str
                            .find("\r\n\r\n")
                            .map(|i| &req_str[i + 4..])
                            .unwrap_or("");
                        let ids: Vec<i64> = serde_json::from_str(body_str).unwrap_or_default();
                        let har = storage
                            .export_har(&ids)
                            .unwrap_or_else(|_| "{}".to_string());
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, har.len(), har
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/history/clear" && method == "POST" {
                        let removed = storage.clear_transactions().unwrap_or(0);
                        let json = format!("{{\"removed\":{removed}}}");
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/scope" && method == "GET" {
                        let p = proxy.lock().await;
                        let cfg = p.scope().get_config();
                        let json = serde_json::to_string(&cfg).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/scope" && method == "POST" {
                        let body_str = req_str
                            .find("\r\n\r\n")
                            .map(|i| &req_str[i + 4..])
                            .unwrap_or("");
                        if let Ok(cfg) =
                            serde_json::from_str::<dropsuite_core::ScopeConfig>(body_str)
                        {
                            let p = proxy.lock().await;
                            p.scope().set_config(cfg.clone());
                            let json = serde_json::to_string(&cfg).unwrap_or_default();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\n{}Content-Length: 0\r\n\r\n",
                                cors
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if path == "/api/match-replace" && method == "GET" {
                        let p = proxy.lock().await;
                        let cfg = p.match_replace().get_config();
                        let json = serde_json::to_string(&cfg).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else if path == "/api/match-replace" && method == "POST" {
                        let body_str = req_str
                            .find("\r\n\r\n")
                            .map(|i| &req_str[i + 4..])
                            .unwrap_or("");
                        if let Ok(cfg) =
                            serde_json::from_str::<dropsuite_core::MatchReplaceConfig>(body_str)
                        {
                            let p = proxy.lock().await;
                            p.match_replace().set_config(cfg.clone());
                            let json = serde_json::to_string(&cfg).unwrap_or_default();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                                cors, json.len(), json
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        } else {
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\n{}Content-Length: 0\r\n\r\n",
                                cors
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    } else if path == "/api/sitemap" && method == "GET" {
                        let summaries = storage
                            .list_summaries(&HistoryFilter {
                                limit: Some(2000),
                                ..Default::default()
                            })
                            .unwrap_or_default();
                        let p = proxy.lock().await;
                        let tree = dropsuite_core::build_sitemap(&summaries, &p.scope());
                        let json = serde_json::to_string(&tree).unwrap_or_default();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}",
                            cors, json.len(), json
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    } else {
                        let msg = "{\"status\":\"DropSuite Backend Running\"}";
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\n\r\n{}", cors, msg.len(), msg);
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                }
            });
        }
    }
}
