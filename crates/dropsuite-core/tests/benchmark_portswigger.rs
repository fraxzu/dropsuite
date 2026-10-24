//! PortSwigger Web Security Academy Benchmark Harness
//!
//! Evaluates active scanner accuracy (precision, recall, F1) against known vulnerable PortSwigger labs.
//! Ignored by default so local offline tests are completely deterministic.
//!
//! Run with:
//! ```text
//! cargo test --test benchmark_portswigger -- --ignored --nocapture
//! ```

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use dropsuite_core::active_scan::{scan, CheckKind, Confidence, ScanOptions};
use dropsuite_core::replay::{ApplyConfig, ReplayOptions, ReplayRequest};

#[derive(Debug, Clone)]
struct LabCase {
    name: &'static str,
    url_env_var: &'static str,
    default_url: &'static str,
    target_param: &'static str,
    expected_kind: CheckKind,
}

#[derive(Default, Debug)]
struct Metrics {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
}

impl Metrics {
    fn precision(&self) -> f64 {
        if self.true_positives + self.false_positives == 0 {
            0.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_positives) as f64
        }
    }

    fn recall(&self) -> f64 {
        if self.true_positives + self.false_negatives == 0 {
            0.0
        } else {
            self.true_positives as f64 / (self.true_positives + self.false_negatives) as f64
        }
    }

    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * (p * r) / (p + r)
        }
    }
}

fn labs() -> Vec<LabCase> {
    vec![
        LabCase {
            name: "Reflected XSS into HTML context with nothing encoded",
            url_env_var: "PORTSWIGGER_LAB_XSS_HTML",
            default_url: "https://example.web-security-academy.net/?search=test",
            target_param: "search",
            expected_kind: CheckKind::ReflectedXss,
        },
        LabCase {
            name: "Reflected XSS into attribute with angle brackets HTML-encoded",
            url_env_var: "PORTSWIGGER_LAB_XSS_ATTR",
            default_url: "https://example.web-security-academy.net/?search=test",
            target_param: "search",
            expected_kind: CheckKind::ReflectedXss,
        },
        LabCase {
            name: "SQL injection vulnerability in WHERE clause allowing retrieval of hidden data",
            url_env_var: "PORTSWIGGER_LAB_SQLI_WHERE",
            default_url: "https://example.web-security-academy.net/filter?category=Gifts",
            target_param: "category",
            expected_kind: CheckKind::SqlBoolean,
        },
        LabCase {
            name: "File path traversal, simple case",
            url_env_var: "PORTSWIGGER_LAB_TRAVERSAL_SIMPLE",
            default_url: "https://example.web-security-academy.net/image?filename=1.jpg",
            target_param: "filename",
            expected_kind: CheckKind::PathTraversal,
        },
    ]
}

#[tokio::test]
#[ignore]
async fn run_portswigger_benchmark_suite() {
    let _user = env::var("PORTSWIGGER_USER").unwrap_or_default();
    let _pass = env::var("PORTSWIGGER_PASS").unwrap_or_default();

    let mut category_metrics: HashMap<&'static str, Metrics> = HashMap::new();
    let scan_opts = ScanOptions {
        delay: Duration::from_millis(300),
        max_requests: 100,
        stop_after_blocks: 4,
        backoff: true,
    };

    println!("\n==========================================================================");
    println!("     DROPSUITE ACTIVE SCANNER BENCHMARK — PORTSWIGGER LABS               ");
    println!("==========================================================================");

    for lab in labs() {
        let url = env::var(lab.url_env_var).unwrap_or_else(|_| lab.default_url.to_string());
        if url.contains("example.web-security-academy.net") {
            println!(
                "[-] Skipping unconfigured lab: {} (Set {})",
                lab.name, lab.url_env_var
            );
            continue;
        }

        let req = ReplayRequest {
            method: "GET".into(),
            url: url.clone(),
            headers: vec![("User-Agent".into(), "DropSuite/0.1.0 Benchmark".into())],
            body: String::new(),
        };

        let replay_opts = ReplayOptions {
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(15),
            own_listener: None,
            tls_roots: Vec::new(),
            apply: ApplyConfig::default(),
        };

        let report = scan(&req, &ApplyConfig::default(), &replay_opts, &scan_opts).await;

        let cat_name = match lab.expected_kind {
            CheckKind::ReflectedXss => "XSS Reflected",
            CheckKind::SqlError | CheckKind::SqlBoolean | CheckKind::SqlTime => "SQL Injection",
            CheckKind::PathTraversal => "Path Traversal",
            CheckKind::OpenRedirect | CheckKind::OpenRedirectXss => "Open Redirect",
            _ => "Other",
        };

        let metrics = category_metrics.entry(cat_name).or_default();

        let matched = report.findings.iter().any(|f| {
            f.kind == lab.expected_kind
                && f.point.contains(lab.target_param)
                && f.confidence >= Confidence::Medium
        });

        if matched {
            metrics.true_positives += 1;
            println!("[+] PASS: {} -> Found {:?}", lab.name, lab.expected_kind);
        } else {
            metrics.false_negatives += 1;
            println!(
                "[-] FAIL: {} -> Expected {:?} on param '{}'",
                lab.name, lab.expected_kind, lab.target_param
            );
        }

        let non_target_findings = report
            .findings
            .iter()
            .filter(|f| !f.point.contains(lab.target_param))
            .count();
        metrics.false_positives += non_target_findings;
    }

    println!("\n--------------------------------------------------------------------------");
    println!(
        "{:<20} | {:<10} | {:<10} | {:<10}",
        "Vulnerability Class", "Precision", "Recall", "F1 Score"
    );
    println!("--------------------------------------------------------------------------");
    for (cat, m) in &category_metrics {
        println!(
            "{:<20} | {:<10.2} | {:<10.2} | {:<10.2}",
            cat,
            m.precision(),
            m.recall(),
            m.f1()
        );
    }
    println!("==========================================================================\n");
}
