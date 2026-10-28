//! Bot-challenge detection.
//!
//! A block page is not a normal error: the request never reached the application, so a scanner
//! or fuzzer that treats it as "404/403 for this path" draws the wrong conclusion. Detecting the
//! vendor and the kind lets the interface say *why* a response is useless and what would help
//! (a browser session, a cookie, or backing off).
//!
//! Detection is deliberately conservative: a vendor needs a vendor marker, not just a 403, so an
//! application's own 403 is never mislabelled.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeVendor {
    Cloudflare,
    Akamai,
    DataDome,
    Imperva,
    Sucuri,
    /// A block page with no vendor marker; the edge is identifiable but not the product.
    Edge,
}

impl ChallengeVendor {
    pub fn label(self) -> &'static str {
        match self {
            ChallengeVendor::Cloudflare => "Cloudflare",
            ChallengeVendor::Akamai => "Akamai",
            ChallengeVendor::DataDome => "DataDome",
            ChallengeVendor::Imperva => "Imperva",
            ChallengeVendor::Sucuri => "Sucuri",
            ChallengeVendor::Edge => "Edge",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// A JavaScript challenge the browser must run.
    Js,
    /// An interactive check (Turnstile, captcha, managed challenge).
    Interactive,
    /// A plain block; the request was refused outright.
    Blocked,
    /// Rate limiting rather than a bot check.
    RateLimited,
}

impl ChallengeKind {
    pub fn label(self) -> &'static str {
        match self {
            ChallengeKind::Js => "JavaScript challenge",
            ChallengeKind::Interactive => "interactive challenge",
            ChallengeKind::Blocked => "blocked",
            ChallengeKind::RateLimited => "rate limited",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSignal {
    pub vendor: ChallengeVendor,
    pub kind: ChallengeKind,
    /// Lowercased marker that produced the detection, for the UI to show the evidence.
    pub evidence: String,
}

impl ChallengeSignal {
    pub fn summary(&self) -> String {
        format!("{} {}", self.vendor.label(), self.kind.label())
    }
}

/// Body markers, checked only on the first slice of the body.
const JS_MARKERS: &[&str] = &[
    "just a moment",
    "checking your browser",
    "/cdn-cgi/challenge-platform",
    "cf-chl",
    "challenge-platform/h/",
    "_abck",
    "sec-if-cpt",
    "datadome captcha",
];

const BLOCK_MARKERS: &[&str] = &[
    "attention required! | cloudflare",
    "access denied",
    "you have been blocked",
    "request unsuccessful",
    "incapsula incident id",
];

/// How much of the body is inspected. Challenge pages are small; this bounds the cost on a
/// large real response.
pub const BODY_SCAN_LIMIT: usize = 8192;

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn vendor_from(headers: &[(String, String)], body: &str) -> Option<(ChallengeVendor, String)> {
    if let Some(v) = header(headers, "cf-mitigated") {
        return Some((ChallengeVendor::Cloudflare, format!("cf-mitigated: {v}")));
    }
    if let Some(v) = header(headers, "server") {
        let lower = v.to_ascii_lowercase();
        if lower.contains("cloudflare") {
            return Some((ChallengeVendor::Cloudflare, format!("server: {v}")));
        }
        if lower.contains("akamaighost") {
            return Some((ChallengeVendor::Akamai, format!("server: {v}")));
        }
    }
    for name in ["akamai-grn", "akamai-request-bc", "akamai-cache-status"] {
        if header(headers, name).is_some() {
            return Some((ChallengeVendor::Akamai, format!("{name} present")));
        }
    }
    for name in ["cf-ray", "cf-cache-status"] {
        if header(headers, name).is_some() {
            return Some((ChallengeVendor::Cloudflare, format!("{name} present")));
        }
    }
    for name in ["x-datadome", "x-dd-b"] {
        if header(headers, name).is_some() {
            return Some((ChallengeVendor::DataDome, format!("{name} present")));
        }
    }
    for name in ["x-iinfo", "x-cdn"] {
        if let Some(v) = header(headers, name) {
            if name == "x-iinfo" || v.to_ascii_lowercase().contains("incapsula") {
                return Some((ChallengeVendor::Imperva, format!("{name}: {v}")));
            }
        }
    }
    for name in ["x-sucuri-id", "x-sucuri-cache"] {
        if header(headers, name).is_some() {
            return Some((ChallengeVendor::Sucuri, format!("{name} present")));
        }
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains("errors.edgesuite.net") || lower.contains("reference #18.") {
        return Some((
            ChallengeVendor::Akamai,
            "body: Akamai reference page".into(),
        ));
    }
    if lower.contains("datadome captcha") {
        return Some((ChallengeVendor::DataDome, "body: datadome captcha".into()));
    }
    if lower.contains("incapsula incident id") {
        return Some((ChallengeVendor::Imperva, "body: incapsula incident".into()));
    }
    if lower.contains("sucuri_cloudproxy") {
        return Some((ChallengeVendor::Sucuri, "body: sucuri_cloudproxy".into()));
    }
    None
}

fn kind_from(status: u16, headers: &[(String, String)], body: &str) -> ChallengeKind {
    if status == 429 {
        return ChallengeKind::RateLimited;
    }
    if let Some(v) = header(headers, "cf-mitigated") {
        if v.eq_ignore_ascii_case("challenge") {
            return ChallengeKind::Interactive;
        }
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains("turnstile") || lower.contains("captcha") || lower.contains("hcaptcha") {
        return ChallengeKind::Interactive;
    }
    if JS_MARKERS.iter().any(|m| lower.contains(m)) {
        return ChallengeKind::Js;
    }
    ChallengeKind::Blocked
}

/// Detect a bot challenge in a response. Returns `None` for ordinary responses.
///
/// A detection always needs a vendor marker; the body is scanned only up to
/// [`BODY_SCAN_LIMIT`] and only when the status suggests a refusal or a vendor was already seen.
pub fn detect(status: u16, headers: &[(String, String)], body: &[u8]) -> Option<ChallengeSignal> {
    let scan = &body[..body.len().min(BODY_SCAN_LIMIT)];
    let body = String::from_utf8_lossy(scan);
    let vendor = vendor_from(headers, &body);
    let refusal = matches!(status, 401 | 403 | 429 | 503);
    let lower_body = body.to_ascii_lowercase();
    let body_challenge = JS_MARKERS.iter().any(|m| lower_body.contains(m))
        || lower_body.contains("turnstile")
        || lower_body.contains("captcha");
    let mitigated = header(headers, "cf-mitigated").is_some();
    // A healthy page served by Cloudflare is not a challenge: `Server: cloudflare` alone is far
    // too common. Outside a refusal, demand a challenge body or `cf-mitigated`.
    if !refusal && !body_challenge && !mitigated {
        return None;
    }
    let (vendor, evidence) = match vendor {
        Some(v) if refusal || body_challenge || mitigated => {
            // `server:` and `cf-ray`/`cf-cache-status` are on every response that merely passes
            // through a CDN. On a refusal they alone do not prove edge interference: the
            // application's own 403 (a WordPress REST JSON error, for example) looks the same.
            // Demand a body marker, or an undecoded HTML error page.
            let weak = v.1.starts_with("server: ")
                || v.1 == "cf-ray present"
                || v.1 == "cf-cache-status present";
            if weak && !body_challenge && !mitigated {
                let json = header(headers, "content-type")
                    .is_some_and(|c| c.to_ascii_lowercase().contains("json"));
                let marked = BLOCK_MARKERS.iter().any(|m| lower_body.contains(m));
                if json && !marked {
                    return None;
                }
            }
            v
        }
        Some(_) => return None,
        None if refusal => {
            // No vendor: only the strong shared markers count, so an app's own 403 stays clean.
            let lower = body.to_ascii_lowercase();
            if JS_MARKERS.iter().any(|m| lower.contains(m)) {
                (
                    ChallengeVendor::Cloudflare,
                    "body: browser-check marker".into(),
                )
            } else if BLOCK_MARKERS.iter().any(|m| lower.contains(m)) {
                (ChallengeVendor::Edge, "body: block-page marker".into())
            } else {
                return None;
            }
        }
        None => return None,
    };
    let kind = kind_from(status, headers, &body);
    Some(ChallengeSignal {
        vendor,
        kind,
        evidence,
    })
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
    fn ordinary_responses_are_not_challenges() {
        assert!(detect(200, &h(&[("server", "nginx")]), b"<html>hello</html>").is_none());
        assert!(detect(403, &h(&[("server", "nginx")]), b"forbidden").is_none());
    }

    #[test]
    fn cloudflare_challenge_is_interactive() {
        let sig = detect(403, &h(&[("cf-mitigated", "challenge")]), b"").unwrap();
        assert_eq!(sig.vendor, ChallengeVendor::Cloudflare);
        assert_eq!(sig.kind, ChallengeKind::Interactive);
    }

    #[test]
    fn cloudflare_js_page_is_js() {
        let sig = detect(
            503,
            &h(&[("server", "cloudflare")]),
            b"<title>Just a moment...</title><script src=\"/cdn-cgi/challenge-platform/h/b\"></script>",
        )
        .unwrap();
        assert_eq!(sig.kind, ChallengeKind::Js);
        assert!(sig.evidence.contains("cloudflare"));
    }

    #[test]
    fn turnstile_wins_over_js() {
        let sig = detect(
            403,
            &h(&[("server", "cloudflare")]),
            b"<div class=\"cf-turnstile\">",
        )
        .unwrap();
        assert_eq!(sig.kind, ChallengeKind::Interactive);
    }

    #[test]
    fn rate_limit_is_its_own_kind() {
        let sig = detect(429, &h(&[("server", "cloudflare")]), b"").unwrap();
        assert_eq!(sig.kind, ChallengeKind::RateLimited);
    }

    #[test]
    fn other_vendors_are_recognised() {
        assert_eq!(
            detect(403, &h(&[("x-datadome", "protected")]), b"")
                .unwrap()
                .vendor,
            ChallengeVendor::DataDome
        );
        assert_eq!(
            detect(403, &h(&[("x-iinfo", "1-2-3")]), b"")
                .unwrap()
                .vendor,
            ChallengeVendor::Imperva
        );
        assert_eq!(
            detect(403, &h(&[("x-sucuri-id", "1")]), b"")
                .unwrap()
                .vendor,
            ChallengeVendor::Sucuri
        );
        assert_eq!(
            detect(503, &h(&[("server", "AkamaiGHost")]), b"")
                .unwrap()
                .vendor,
            ChallengeVendor::Akamai
        );
    }

    #[test]
    fn only_the_head_of_the_body_is_scanned() {
        let mut body = vec![b'a'; BODY_SCAN_LIMIT];
        body.extend_from_slice(b"Just a moment...");
        assert!(
            detect(403, &h(&[]), &body).is_none(),
            "marker past the limit is missed"
        );
        let mut short = b"Just a moment...".to_vec();
        short.extend(std::iter::repeat_n(b'a', BODY_SCAN_LIMIT));
        assert!(detect(403, &h(&[]), &short).is_some());
    }

    #[test]
    fn summary_is_readable() {
        let sig = detect(403, &h(&[("cf-mitigated", "challenge")]), b"").unwrap();
        assert_eq!(sig.summary(), "Cloudflare interactive challenge");
    }
}

#[cfg(test)]
mod healthy_tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_healthy_cloudflare_page_is_not_a_challenge() {
        let sig = detect(
            200,
            &h(&[("server", "cloudflare"), ("cf-ray", "a4e76ec11a948234-SIN")]),
            b"<html><title>Beranda</title><body>hello</body></html>",
        );
        assert!(sig.is_none(), "{sig:?}");
    }

    #[test]
    fn a_healthy_page_with_a_challenge_script_is_still_detected() {
        let sig = detect(
            200,
            &h(&[("server", "cloudflare")]),
            b"<script src=\"/cdn-cgi/challenge-platform/h/b\"></script>",
        );
        assert!(sig.is_some());
    }

    #[test]
    fn cf_mitigated_on_a_200_is_detected() {
        assert!(detect(200, &h(&[("cf-mitigated", "challenge")]), b"").is_some());
    }

    #[test]
    fn a_refusal_from_cloudflare_is_still_reported() {
        assert!(detect(403, &h(&[("server", "cloudflare")]), b"nope").is_some());
    }

    #[test]
    fn an_application_json_403_behind_cloudflare_is_not_a_challenge() {
        let headers = h(&[
            ("server", "cloudflare"),
            ("content-type", "application/json; charset=UTF-8"),
            ("cf-ray", "a517647ebe3a5fe5-SIN"),
        ]);
        let body = br#"{"code":"rest_forbidden","message":"Sorry.","data":{"status":403}}"#;
        assert!(detect(403, &headers, body).is_none());
    }
}

#[cfg(test)]
mod vendor_tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn akamai_headers_are_akamai_not_cloudflare() {
        let sig = detect(
            403,
            &h(&[("akamai-grn", "0.bd5f.1792.8d45")]),
            b"Access Denied",
        )
        .unwrap();
        assert_eq!(sig.vendor, ChallengeVendor::Akamai);
        assert_eq!(sig.kind, ChallengeKind::Blocked);
    }

    #[test]
    fn akamai_reference_page_is_akamai() {
        let body = b"Access Denied\nReference #18.b65f6276.1792797616.b05a4cce\nhttps://errors.edgesuite.net/18.b65f";
        assert_eq!(
            detect(403, &h(&[]), body).unwrap().vendor,
            ChallengeVendor::Akamai
        );
    }

    #[test]
    fn an_unmarked_block_page_is_edge_not_cloudflare() {
        let sig = detect(
            403,
            &h(&[]),
            b"Access Denied: you may not access this server",
        )
        .unwrap();
        assert_eq!(sig.vendor, ChallengeVendor::Edge);
    }

    #[test]
    fn a_healthy_akamai_page_is_not_a_challenge() {
        assert!(detect(200, &h(&[("akamai-grn", "x")]), b"<html>ok</html>").is_none());
    }
}
