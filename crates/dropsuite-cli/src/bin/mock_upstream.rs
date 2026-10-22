use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:9090";
    let listener = TcpListener::bind(addr).await?;
    println!("DropSuite Mock Upstream Server running on http://{}", addr);

    loop {
        let (mut socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            match socket.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    println!("[MOCK UPSTREAM] Request from {}: {}", peer, first_line);

                    let (status_line, content_type, body) = if req.contains("/api/login") {
                        ("HTTP/1.1 200 OK", "application/json", "{\"status\":\"authenticated\",\"user\":\"admin\",\"token\":\"secret_jwt_token_12345\"}")
                    } else if req.contains("/not-found") {
                        ("HTTP/1.1 404 Not Found", "text/plain", "Resource Not Found")
                    } else if req.contains("/api/status") {
                        (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            "{\"status\":\"healthy\",\"server\":\"DropSuite-Mock-v1\"}",
                        )
                    } else {
                        (
                            "HTTP/1.1 200 OK",
                            "application/json",
                            "{\"message\":\"DropSuite Mock Upstream Default Response\"}",
                        )
                    };

                    let resp = format!(
                        "{}\r\nConnection: close\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
                        status_line,
                        content_type,
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    let _ = socket.shutdown().await;
                }
                Err(_) => {}
            }
        });
    }
}
