//! Probe a URL through the real Replay path and report the status, challenge signal and the
//! headers that identify a bot-protection layer. Run with:
//!
//! ```text
//! cargo run -p dropsuite-core --example probe_challenge -- https://example.com
//! ```

use std::time::Duration;

use dropsuite_core::header_preset::BrowserPreset;
use dropsuite_core::replay::{send, ApplyConfig, ReplayOptions, ReplayRequest};

#[tokio::main]
async fn main() {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: probe_challenge <url> [preset]");
        std::process::exit(2);
    };
    let preset = match std::env::args().nth(2).as_deref() {
        Some("chrome") => BrowserPreset::Chrome,
        Some("firefox") => BrowserPreset::Firefox,
        Some("safari") => BrowserPreset::Safari,
        _ => BrowserPreset::Off,
    };

    let request = ReplayRequest {
        method: "GET".into(),
        url: url.clone(),
        headers: Vec::new(),
        body: String::new(),
    };
    let options = ReplayOptions {
        connect_timeout: Duration::from_secs(15),
        response_timeout: Duration::from_secs(25),
        own_listener: None,
        tls_roots: Vec::new(),
        apply: ApplyConfig {
            preset,
            ..Default::default()
        },
    };

    match send(&request, &options).await {
        Ok(r) => {
            println!("url          {url}");
            println!("preset       {preset:?}");
            println!("status       {}", r.status);
            println!("reason       {}", r.reason);
            println!("bytes        {} (kept {})", r.total_bytes, r.message.len());
            println!("duration_ms  {}", r.duration_ms);
            println!("content_type {:?}", r.content_type);
            for name in [
                "server",
                "cf-ray",
                "cf-mitigated",
                "cf-cache-status",
                "x-datadome",
                "x-iinfo",
            ] {
                if let Some((_, value)) =
                    r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))
                {
                    println!("{name:<12} {value}");
                }
            }
            match &r.challenge {
                Some(sig) => println!(
                    "challenge    {} / {} ({})",
                    sig.vendor.label(),
                    sig.kind.label(),
                    sig.evidence
                ),
                None => println!("challenge    none"),
            }
        }
        Err(e) => {
            println!("url          {url}");
            println!("error        {} ({})", e.kind, e.message);
        }
    }
}
