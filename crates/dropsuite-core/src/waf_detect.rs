//! Recognise an edge block or challenge page before scanning it.
//!
//! Scanning a challenge page produces findings about Cloudflare, not about the application, and
//! hammering a blocked host gets the tester banned. Detection is vendor-marker based so a plain
//! application 403 is not mistaken for an edge block.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafVendor {
    Cloudflare,
    Akamai,
    Imperva,
    AwsWaf,
    F5,
    ModSecurity,
}

impl WafVendor {
    pub fn label(self) -> &'static str {
        match self {
            WafVendor::Cloudflare => "Cloudflare",
            WafVendor::Akamai => "Akamai",
            WafVendor::Imperva => "Imperva",
            WafVendor::AwsWaf => "AWS WAF",
            WafVendor::F5 => "F5 BIG-IP",
            WafVendor::ModSecurity => "ModSecurity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafSignal {
    None,
    /// A solvable/JS challenge: the request never reached the application.
    Challenge(WafVendor),
    /// A hard refusal.
    Block(WafVendor),
}

impl WafSignal {
    pub fn is_interference(self) -> bool {
        !matches!(self, WafSignal::None)
    }

    pub fn vendor(self) -> Option<WafVendor> {
        match self {
            WafSignal::None => None,
            WafSignal::Challenge(v) | WafSignal::Block(v) => Some(v),
        }
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    header(headers, name).is_some()
}

/// Classify a response as edge interference. `status` gates the block rules so a healthy page
/// served through a CDN is not flagged.
pub fn detect(headers: &[(String, String)], body: &str, status: u16) -> WafSignal {
    let lower = body.to_ascii_lowercase();
    let refusal = matches!(status, 401 | 403 | 406 | 429 | 503);

    // Cloudflare: the header is authoritative; the body marker alone needs a refusal.
    if let Some(v) = header(headers, "cf-mitigated") {
        return if v.eq_ignore_ascii_case("challenge") {
            WafSignal::Challenge(WafVendor::Cloudflare)
        } else {
            WafSignal::Block(WafVendor::Cloudflare)
        };
    }
    if refusal && (lower.contains("challenges.cloudflare.com") || lower.contains("cf-chl")) {
        return WafSignal::Challenge(WafVendor::Cloudflare);
    }
    if refusal
        && header(headers, "server").is_some_and(|s| s.to_ascii_lowercase().contains("cloudflare"))
    {
        return WafSignal::Block(WafVendor::Cloudflare);
    }

    // Akamai: reference page or its diagnostic headers.
    if lower.contains("errors.edgesuite.net")
        || lower.contains("reference #18.")
        || has_header(headers, "akamai-grn")
    {
        return WafSignal::Block(WafVendor::Akamai);
    }
    if refusal
        && header(headers, "server").is_some_and(|s| s.to_ascii_lowercase().contains("akamaighost"))
    {
        return WafSignal::Block(WafVendor::Akamai);
    }

    // Imperva / Incapsula.
    if has_header(headers, "x-iinfo") || lower.contains("_incapsula_resource") {
        return WafSignal::Block(WafVendor::Imperva);
    }

    // AWS WAF: its own request id plus a refusal.
    if refusal && has_header(headers, "x-amzn-requestid") && lower.contains("request blocked") {
        return WafSignal::Block(WafVendor::AwsWaf);
    }

    // F5 BIG-IP: the rejection page or its support-id cookie.
    if lower.contains("the requested url was rejected") || has_header(headers, "x-wa-info") {
        return WafSignal::Block(WafVendor::F5);
    }
    if refusal && header(headers, "set-cookie").is_some_and(|c| c.starts_with("TS")) {
        return WafSignal::Block(WafVendor::F5);
    }

    // ModSecurity: its own marker, or Apache's 406 with a rule id.
    if lower.contains("modsecurity") || (status == 406 && lower.contains("not acceptable")) {
        return WafSignal::Block(WafVendor::ModSecurity);
    }

    WafSignal::None
}

/// Paths served by the edge rather than the application.
pub fn is_infrastructure_path(url: &str) -> bool {
    let path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .split_once('/')
        .map(|(_, p)| p)
        .unwrap_or("");
    let lower = format!("/{path}").to_ascii_lowercase();
    [
        "/cdn-cgi/",
        "/tspd/",
        "/challenge-platform/",
        "/__cf",
        "/akamai/",
        "/imperva/",
    ]
    .iter()
    .any(|p| lower.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_healthy_page_is_not_interference() {
        assert_eq!(
            detect(&h(&[("server", "cloudflare")]), "<html>ok</html>", 200),
            WafSignal::None
        );
    }

    #[test]
    fn cloudflare_challenge_header_wins() {
        assert_eq!(
            detect(&h(&[("cf-mitigated", "challenge")]), "", 403),
            WafSignal::Challenge(WafVendor::Cloudflare)
        );
    }

    #[test]
    fn cloudflare_js_page_is_a_challenge() {
        assert_eq!(
            detect(
                &h(&[("server", "cloudflare")]),
                "challenges.cloudflare.com",
                503
            ),
            WafSignal::Challenge(WafVendor::Cloudflare)
        );
    }

    #[test]
    fn akamai_reference_page_is_a_block() {
        assert_eq!(
            detect(&h(&[]), "Reference #18.abc", 403),
            WafSignal::Block(WafVendor::Akamai)
        );
    }

    #[test]
    fn imperva_header_is_a_block() {
        assert_eq!(
            detect(&h(&[("x-iinfo", "1-2-3")]), "", 403),
            WafSignal::Block(WafVendor::Imperva)
        );
    }

    #[test]
    fn f5_rejection_page_is_a_block() {
        assert_eq!(
            detect(&h(&[]), "The requested URL was rejected", 403),
            WafSignal::Block(WafVendor::F5)
        );
    }

    #[test]
    fn modsecurity_marker_is_a_block() {
        assert_eq!(
            detect(&h(&[]), "ModSecurity: Access denied", 403),
            WafSignal::Block(WafVendor::ModSecurity)
        );
    }

    #[test]
    fn plain_application_403_is_not_attributed() {
        assert_eq!(
            detect(&h(&[("server", "nginx")]), "forbidden", 403),
            WafSignal::None
        );
    }

    #[test]
    fn infrastructure_paths_are_recognised() {
        assert!(is_infrastructure_path(
            "https://a.test/cdn-cgi/challenge-platform/h/b"
        ));
        assert!(is_infrastructure_path("https://a.test/TSPD/123?type=11"));
        assert!(!is_infrastructure_path("https://a.test/blog/post"));
        assert!(!is_infrastructure_path("https://a.test/"));
    }
}
