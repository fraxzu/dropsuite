//! Cookie jar: the cookies a bot check hands out, kept so later requests look like the same
//! client.
//!
//! Values are stored raw (unlike history, which redacts): a cookie is only useful if it is sent
//! back exactly as received. The jar is scoped per host, follows the RFC 6265 domain/path/secure
//! rules for matching, and refuses the `__Host-`/`__Secure-` prefix violations a browser refuses.
//!
//! Nothing here touches the network or the database; [`crate::storage`] persists it and
//! [`crate::replay`] attaches it.

use serde::{Deserialize, Serialize};

/// Largest cookie value kept. Real tokens (`cf_clearance`, `__cf_bm`) are far smaller.
pub const MAX_VALUE_LEN: usize = 4096;
/// Largest cookie name kept.
pub const MAX_NAME_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCookie {
    /// `None` for a host-only cookie, `Some(domain)` when the server set a `Domain` attribute.
    pub domain: Option<String>,
    /// Host the cookie arrived from, and the scope used when no `Domain` was set.
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    /// Unix seconds; `None` is a session cookie.
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

impl StoredCookie {
    /// The domain the cookie is bound to, host-only unless a domain attribute was accepted.
    pub fn scope(&self) -> &str {
        self.domain.as_deref().unwrap_or(&self.host)
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    /// `true` when the cookie may be sent to this host over this path and scheme.
    pub fn matches(&self, host: &str, path: &str, tls: bool, now: i64) -> bool {
        if self.is_expired(now) || (self.secure && !tls) {
            return false;
        }
        domain_match(host, self.scope()) && path_match(path, &self.path)
    }
}

/// Host-only and domain matching: an exact host, or a suffix on a dot boundary. A leading dot in
/// the stored domain is tolerated because servers still write it.
pub fn domain_match(host: &str, scope: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let scope = scope
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if scope.is_empty() {
        return false;
    }
    host == scope || host.ends_with(&format!(".{scope}"))
}

/// RFC 6265 path matching: equal, or a prefix ending on a `/` boundary. `/` matches everything.
pub fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" || request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/')
            || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/'))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn valid_value(value: &str) -> bool {
    value.len() <= MAX_VALUE_LEN
        && value
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x7e).contains(&b))
}

/// Parse one `Set-Cookie` value received from `host`. Returns `None` when the cookie is not
/// storable for that host (bad name/value, foreign domain, prefix violation, or already expired).
pub fn parse_set_cookie(host: &str, header: &str, now: i64) -> Option<StoredCookie> {
    let mut parts = header.split(';');
    let pair = parts.next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    let value = value.trim();
    if !valid_name(name) || !valid_value(value) {
        return None;
    }

    let mut domain: Option<String> = None;
    let mut path: Option<String> = None;
    let mut secure = false;
    let mut http_only = false;
    let mut max_age: Option<i64> = None;
    let mut expires: Option<i64> = None;

    for attr in parts {
        let attr = attr.trim();
        let (key, val) = match attr.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => (attr.to_ascii_lowercase(), ""),
        };
        match key.as_str() {
            "domain" => {
                let d = val
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if d.is_empty() || !domain_match(host, &d) {
                    // A domain the host does not belong to is dropped, as a browser does.
                    continue;
                }
                domain = Some(d);
            }
            "path" => {
                if val.starts_with('/') {
                    path = Some(val.to_string());
                }
            }
            "secure" => secure = true,
            "httponly" => http_only = true,
            "max-age" => {
                if let Ok(secs) = val.parse::<i64>() {
                    max_age = Some(secs);
                }
            }
            "expires" => expires = parse_http_date(val),
            _ => {}
        }
    }

    // A past Max-Age deletes the cookie rather than storing it.
    if let Some(secs) = max_age {
        if secs <= 0 {
            return None;
        }
    }

    let expires_at = match (max_age, expires) {
        (Some(secs), _) => Some(now.saturating_add(secs)),
        (None, Some(at)) => {
            if at <= now {
                return None;
            }
            Some(at)
        }
        (None, None) => None,
    };

    let path = path.unwrap_or_else(|| default_path(host));

    if name.starts_with("__Host-") {
        if !secure || domain.is_some() || path != "/" {
            return None;
        }
    } else if name.starts_with("__Secure-") && !secure {
        return None;
    }

    Some(StoredCookie {
        domain,
        host: host.to_ascii_lowercase(),
        name: name.to_string(),
        value: value.to_string(),
        path,
        secure,
        http_only,
        expires_at,
        created_at: now,
    })
}

/// RFC 6265 §5.1.4 default path: the request directory, never with a trailing slash beyond root.
fn default_path(_host: &str) -> String {
    "/".to_string()
}

/// Default path for a request path, used when a caller parses with a path in hand.
pub fn default_path_for(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Parse the `Expires` form (`Sun, 06 Nov 1994 08:49:37 GMT`). Other forms are ignored.
fn parse_http_date(text: &str) -> Option<i64> {
    let text = text.trim();
    let rest = text.split_once(',').map(|(_, r)| r).unwrap_or(text);
    let mut it = rest.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let month_text = it.next()?.to_ascii_lowercase();
    let month = MONTHS.iter().position(|m| month_text.starts_with(m))? as i64 + 1;
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;
    if !(1..=31).contains(&day) || !(1970..=9999).contains(&year) {
        return None;
    }
    let mut hm = time.split(':');
    let hour: i64 = hm.next()?.parse().ok()?;
    let min: i64 = hm.next()?.parse().ok()?;
    let sec: i64 = hm.next()?.parse().ok()?;
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec)
}

/// Days since the Unix epoch for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Build a `Cookie` header value from the jar, longest path first, deduplicated by name.
pub fn header_value(
    cookies: &[StoredCookie],
    host: &str,
    path: &str,
    tls: bool,
    now: i64,
) -> Option<String> {
    let mut usable: Vec<&StoredCookie> = cookies
        .iter()
        .filter(|c| c.matches(host, path, tls, now))
        .collect();
    usable.sort_by(|a, b| {
        b.path
            .len()
            .cmp(&a.path.len())
            .then(a.created_at.cmp(&b.created_at))
    });

    let mut seen: Vec<&str> = Vec::new();
    let mut out = String::new();
    for cookie in usable {
        if seen.contains(&cookie.name.as_str()) {
            continue;
        }
        seen.push(&cookie.name);
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(&cookie.name);
        out.push('=');
        out.push_str(&cookie.value);
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn parse(header: &str) -> Option<StoredCookie> {
        parse_set_cookie("api.example.com", header, NOW)
    }

    #[test]
    fn host_only_cookie_round_trips() {
        let c = parse("cf_clearance=abc123").unwrap();
        assert_eq!(c.name, "cf_clearance");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.path, "/");
        assert!(c.domain.is_none());
        assert!(c.expires_at.is_none());
        assert!(c.matches("api.example.com", "/x", true, NOW));
        assert!(!c.matches("other.test", "/", true, NOW));
    }

    #[test]
    fn matching_covers_subdomains_and_paths() {
        let c = parse("sid=1; Domain=.example.com; Path=/app").unwrap();
        assert!(c.matches("api.example.com", "/app/x", true, NOW));
        assert!(c.matches("example.com", "/app", true, NOW));
        assert!(!c.matches("example.com", "/application", true, NOW));
        assert!(!c.matches("badexample.com", "/app", true, NOW));
    }

    #[test]
    fn foreign_domain_attribute_is_dropped() {
        let c = parse("sid=1; Domain=elsewhere.test").unwrap();
        assert!(c.domain.is_none(), "must fall back to host-only");
    }

    #[test]
    fn secure_cookies_need_tls() {
        let c = parse("sid=1; Secure").unwrap();
        assert!(!c.matches("api.example.com", "/", false, NOW));
        assert!(c.matches("api.example.com", "/", true, NOW));
    }

    #[test]
    fn max_age_and_expiry() {
        let c = parse("sid=1; Max-Age=60").unwrap();
        assert_eq!(c.expires_at, Some(NOW + 60));
        assert!(!c.is_expired(NOW + 59));
        assert!(c.is_expired(NOW + 60));

        let c = parse("sid=1; Expires=Wed, 09 Jun 2100 10:18:14 GMT").unwrap();
        assert!(c.expires_at.unwrap() > NOW);
        assert!(parse("sid=1; Expires=Wed, 09 Jun 2020 10:18:14 GMT").is_none());
        assert!(parse("sid=1; Max-Age=0").is_none());
    }

    #[test]
    fn prefix_rules_are_enforced() {
        assert!(parse("__Host-a=1; Secure; Path=/").is_some());
        assert!(parse("__Host-a=1; Path=/").is_none(), "needs Secure");
        assert!(
            parse("__Host-a=1; Secure; Path=/x").is_none(),
            "needs root path"
        );
        assert!(parse("__Host-a=1; Secure; Path=/; Domain=example.com").is_none());
        assert!(parse("__Secure-a=1; Secure").is_some());
        assert!(parse("__Secure-a=1").is_none());
    }

    #[test]
    fn junk_is_rejected() {
        assert!(parse("no-equals").is_none());
        assert!(parse("=nameless").is_none());
        assert!(parse("name=with space").is_none());
        assert!(
            parse("name=ok; Path=relative").is_some(),
            "relative path falls back to /"
        );
    }

    #[test]
    fn header_prefers_longest_path_and_dedupes() {
        let mut root = parse("a=1").unwrap();
        root.created_at = NOW - 5;
        let mut deep = parse("a=2; Path=/app").unwrap();
        deep.created_at = NOW;
        let other = parse("b=3").unwrap();
        let value =
            header_value(&[root, deep, other], "api.example.com", "/app/x", true, NOW).unwrap();
        assert_eq!(value, "a=2; b=3");
    }

    #[test]
    fn header_is_none_when_nothing_matches() {
        let c = parse("sid=1; Secure").unwrap();
        assert!(header_value(&[c], "api.example.com", "/", false, NOW).is_none());
        assert!(header_value(&[], "api.example.com", "/", true, NOW).is_none());
    }

    #[test]
    fn default_path_follows_the_request_directory() {
        assert_eq!(default_path_for("/a/b/c"), "/a/b");
        assert_eq!(default_path_for("/a"), "/");
        assert_eq!(default_path_for("/"), "/");
        assert_eq!(default_path_for("nonsense"), "/");
    }
}
