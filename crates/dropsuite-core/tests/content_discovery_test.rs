//! End-to-end test for the Scanner's Content discovery flow, exercised through the *real* engine.
//!
//! Content discovery in the UI is just an Intruder sniper run over `BASE/{{}}` with the payload
//! list = [two random sentinels] + [common paths], then a client-side filter that keeps only paths
//! whose response differs from the sentinel "baseline". This test stands up a local HTTP server
//! with a known layout and drives `intruder::run` exactly as the desktop command does, then applies
//! the same filter the frontend applies — so a regression in sending, status reporting, or the
//! baseline logic fails here instead of silently showing an empty table.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use dropsuite_core::intruder::{run, Attack, Guards, PayloadSet};
use dropsuite_core::replay::{ReplayOptions, ReplayRequest};
use dropsuite_core::scope::ScopeEngine;
use tokio::sync::mpsc;

/// Paths this fake target serves with 200; everything else is a real 404.
const EXISTS: &[&str] = &["admin", ".git/config", "robots.txt"];

/// A throwaway HTTP/1.1 server on 127.0.0.1 that answers 200 for `EXISTS` and 404 otherwise.
/// Returns the bound port; the accept loop runs on a detached thread for the test's lifetime.
fn start_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                // Read the request line; we only need the target path.
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                // Drain the rest of the headers so the client's write completes cleanly.
                let mut header = String::new();
                while reader.read_line(&mut header).map(|n| n > 0).unwrap_or(false) {
                    if header == "\r\n" || header == "\n" {
                        break;
                    }
                    header.clear();
                }
                let target = line.split_whitespace().nth(1).unwrap_or("/");
                let path = target.trim_start_matches('/');
                let (status, reason, body) = if EXISTS.contains(&path) {
                    (200, "OK", "exists")
                } else {
                    (404, "Not Found", "nope")
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                // Let the client read before the socket drops.
                let mut sink = Vec::new();
                let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                let _ = stream.read_to_end(&mut sink);
            });
        }
    });
    port
}

#[tokio::test]
async fn content_discovery_surfaces_real_paths_against_a_404_baseline() {
    let port = start_target();
    let base_url = format!("http://127.0.0.1:{port}/{{{{}}}}"); // BASE/{{}} — the discovery template

    // Two random sentinels (must 404) followed by the wordlist, exactly like the UI builds it.
    let sentinels = ["zzsentinel-404-aaa", "zzsentinel-404-bbb"];
    let wordlist = ["admin", ".git/config", "robots.txt", "wp-admin", "secret"];
    let values: Vec<String> = sentinels
        .iter()
        .chain(wordlist.iter())
        .map(|s| s.to_string())
        .collect();
    let planned = values.len();

    let base = ReplayRequest {
        method: "GET".into(),
        url: base_url,
        headers: Vec::new(),
        body: String::new(),
    };
    let attack = Attack::Sniper {
        payloads: PayloadSet::List { values },
    };
    let opts = ReplayOptions {
        connect_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        own_listener: None,
        tls_roots: Vec::new(),
        apply: dropsuite_core::replay::ApplyConfig::default(),
    };
    let scope = ScopeEngine::new(); // empty => everything in scope, the discovery default
    let guards = Guards::default();

    let (tx, mut rx) = mpsc::channel(64);
    let collector = async {
        let mut out = Vec::new();
        while let Some(o) = rx.recv().await {
            out.push(o);
        }
        out
    };
    let runner = run(
        &base,
        &attack,
        opts,
        &scope,
        &guards,
        Arc::new(AtomicBool::new(false)),
        tx,
    );
    let (stats, outcomes) = tokio::join!(runner, collector);

    // Every probe was actually dispatched and answered — nothing skipped or blocked.
    let stats = stats.expect("run completed");
    assert_eq!(stats.dispatched, planned, "all probes should be sent");
    assert_eq!(stats.scope_skipped, 0, "nothing should be scope-skipped");
    assert_eq!(outcomes.len(), planned, "one outcome per probe");

    // Reproduce the frontend filter (ScannerWorkspace.tsx): collect ok rows, derive the baseline
    // from the sentinels, keep only non-sentinel, non-404 rows that differ from the baseline.
    let sentinel_set: HashSet<&str> = sentinels.iter().copied().collect();
    let rows: Vec<(String, u16)> = outcomes
        .iter()
        .filter_map(|o| o.result.as_ref().ok().map(|s| (o.replacements.join(""), s.status)))
        .collect();
    assert_eq!(rows.len(), planned, "every probe returned a status (none errored)");

    let baseline = rows
        .iter()
        .find(|(p, _)| sentinel_set.contains(p.as_str()))
        .map(|(_, st)| *st);
    assert_eq!(baseline, Some(404), "random sentinel paths must be a real 404 baseline");

    let distinct: HashSet<String> = rows
        .iter()
        .filter(|(p, st)| {
            !sentinel_set.contains(p.as_str()) && *st != 404 && baseline != Some(*st)
        })
        .map(|(p, _)| p.clone())
        .collect();

    let expected: HashSet<String> = EXISTS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        distinct, expected,
        "discovery should surface exactly the paths that exist (200), and hide the 404s"
    );
}
