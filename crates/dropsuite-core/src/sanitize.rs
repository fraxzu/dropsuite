//! Persistence-boundary redaction for captured HTTP traffic.
//!
//! Every captured representation that DropSuite stores, logs, broadcasts or serves to the
//! interface passes through [`sanitize_record`]. Forwarded traffic is never touched: the proxy
//! forwards the original bytes, and only the captured copy is sanitized.
//!
//! The policy is mostly name-based. It redacts credential-bearing headers, cookie values,
//! secret-looking query/fragment parameters (in targets, URL-bearing headers, and URLs written
//! in plain-text, HTML and other readable bodies), and secret-looking fields in JSON and
//! form-urlencoded bodies, while keeping header names, auth schemes, cookie names and cookie
//! attributes for diagnostics. Headers with unrecognised names are also checked for a small set
//! of credential formats with distinctive shapes (JWTs, provider-prefixed API tokens, values
//! written as `Bearer …`). It cannot recognise secrets under arbitrary names in arbitrary
//! formats, or inside unsupported encodings; see `docs/SECURITY.md` for the residual risks.

use crate::models::TransactionRecord;

/// Replacement for every redacted value.
pub const REDACTED: &str = "[REDACTED]";
/// Replacement for a head line that cannot be parsed as a header, which could carry a secret.
pub const UNPARSED_LINE: &str = "[REDACTED: unparsed header line]";

/// Fragments that mark a header, parameter or field name as credential-bearing,
/// matched against the lowercased name with punctuation removed.
const SENSITIVE_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "authorization",
    "authentication",
    "cookie",
    "session",
    "csrf",
    "xsrf",
    "privatekey",
    "credential",
    "signature",
    "jwt",
    "bearer",
];

/// Short names that are only sensitive as a whole word.
const SENSITIVE_EXACT: &[&str] = &["auth", "pass", "pwd", "pin", "otp", "key", "sid", "sig"];

/// Authorization schemes kept in front of a redacted credential.
const AUTH_SCHEMES: &[&str] = &[
    "basic",
    "bearer",
    "digest",
    "negotiate",
    "ntlm",
    "hoba",
    "mutual",
    "dpop",
    "gnap",
    "token",
    "aws4-hmac-sha256",
];

fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True when a parameter or field name suggests the value is a credential.
pub fn is_sensitive_name(name: &str) -> bool {
    let n = normalize(name);
    !n.is_empty()
        && (SENSITIVE_EXACT.contains(&n.as_str())
            || SENSITIVE_FRAGMENTS.iter().any(|f| n.contains(f)))
}

/// True when a header's value must not be persisted. Case-insensitive.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    // CORS metadata such as Access-Control-Allow-Credentials carries no secret.
    if lower.starts_with("access-control-") {
        return false;
    }
    is_sensitive_name(&lower)
}

/// Redacted form of one header value. Non-sensitive values are returned unchanged,
/// except URL-bearing headers whose query parameters are sanitized.
pub fn redact_header_value(name: &str, value: &str) -> String {
    // A value that is already a redaction placeholder (including the pre-P1.6
    // "[REDACTED_COOKIE]") holds no secret; leave it as stored.
    let trimmed = value.trim();
    if trimmed.starts_with("[REDACTED") && trimmed.ends_with(']') && !trimmed[1..].contains('[') {
        return value.to_string();
    }
    let lower = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        "authorization" | "proxy-authorization" => redact_auth_value(value),
        "cookie" => redact_cookie_header(value),
        "set-cookie" | "set-cookie2" => redact_set_cookie(value),
        "referer" | "location" | "content-location" => sanitize_target(value),
        _ if is_sensitive_header(&lower) => REDACTED.to_string(),
        _ => redact_unnamed_header_value(value),
    }
}

/// A header value whose name gives no hint: URLs in it get the query rules, and recognisable
/// credential formats are redacted. Everything else keeps its bytes.
fn redact_unnamed_header_value(value: &str) -> String {
    let value = redact_urls_in_text(value, 0).unwrap_or_else(|| value.to_string());
    redact_known_credentials(&value).unwrap_or(value)
}

/// Authorization schemes recognised at the start of a header whose name gives no hint.
/// `Token` and the other generic words are left out: as plain words they are too common.
const CREDENTIAL_SCHEMES: &[&str] = &[
    "bearer",
    "basic",
    "digest",
    "negotiate",
    "ntlm",
    "dpop",
    "gnap",
    "aws4-hmac-sha256",
];

/// Redact credentials in a value whose header name is not recognised: a value written as an
/// authorization credential (`Bearer <token68>`, `Basic <base64 of user:pass>`, `Digest …=…`),
/// and tokens in the formats [`is_known_credential`] lists. `None` when nothing matched.
///
/// This is pattern recognition for documented formats only. An opaque random string under an
/// unknown name cannot be told apart from an ID or a hash, and is kept.
pub fn redact_known_credentials(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some((scheme, rest)) = trimmed.split_once(char::is_whitespace) {
        let lower = scheme.to_ascii_lowercase();
        let rest = rest.trim();
        let credential = match lower.as_str() {
            "basic" => is_token68(rest) && decodes_to_user_pass(rest),
            "digest" | "aws4-hmac-sha256" => rest.contains('=') && !rest.contains(REDACTED),
            _ => {
                CREDENTIAL_SCHEMES.contains(&lower.as_str()) && is_token68(rest) && rest.len() >= 8
            }
        };
        if credential {
            return Some(redact_auth_value(value));
        }
    }
    let mut out = String::with_capacity(value.len());
    let mut copied = 0;
    for (start, end) in token_runs(value, |c| c.is_ascii_alphanumeric() || b"_-.".contains(&c)) {
        // A sentence-ending full stop is not part of the token.
        let token = value[start..end].trim_end_matches('.');
        if is_known_credential(token) {
            out.push_str(&value[copied..start]);
            out.push_str(REDACTED);
            copied = start + token.len();
        }
    }
    if copied == 0 {
        return None;
    }
    out.push_str(&value[copied..]);
    Some(out)
}

/// Byte ranges of the maximal runs of ASCII bytes accepted by `keep`.
fn token_runs(s: &str, keep: impl Fn(u8) -> bool) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut runs = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !keep(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && keep(b[i]) {
            i += 1;
        }
        runs.push((start, i));
    }
    runs
}

/// RFC 9110 token68: `[A-Za-z0-9-._~+/]+ *"="`.
fn is_token68(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~+/".contains(&c))
}

/// True when `s` is standard base64 of UTF-8 text holding `user:password`.
fn decodes_to_user_pass(s: &str) -> bool {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let body = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        let Some(v) = val(c) else { return false };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    std::str::from_utf8(&out).is_ok_and(|t| t.contains(':') && !t.contains(char::is_control))
}

/// Credential formats recognised by shape alone: a provider prefix followed by a body of the
/// documented alphabet and minimum length, or a JWT (JWS/JWE compact serialization).
const CREDENTIAL_PREFIXES: &[(&str, usize, Alphabet)] = &[
    // GitHub personal, OAuth, user-to-server, server-to-server and refresh tokens.
    ("ghp_", 36, Alphabet::Alnum),
    ("gho_", 36, Alphabet::Alnum),
    ("ghu_", 36, Alphabet::Alnum),
    ("ghs_", 36, Alphabet::Alnum),
    ("ghr_", 36, Alphabet::Alnum),
    ("github_pat_", 40, Alphabet::Word),
    // GitLab personal access token.
    ("glpat-", 20, Alphabet::Url),
    // Slack bot, user, app-level, refresh and configuration tokens.
    ("xoxb-", 10, Alphabet::AlnumDash),
    ("xoxp-", 10, Alphabet::AlnumDash),
    ("xoxa-", 10, Alphabet::AlnumDash),
    ("xoxr-", 10, Alphabet::AlnumDash),
    ("xoxs-", 10, Alphabet::AlnumDash),
    ("xoxe-", 10, Alphabet::AlnumDash),
    ("xapp-", 10, Alphabet::AlnumDash),
    // Stripe secret and restricted keys, webhook signing secrets. Publishable keys are public.
    ("sk_live_", 16, Alphabet::Alnum),
    ("sk_test_", 16, Alphabet::Alnum),
    ("rk_live_", 16, Alphabet::Alnum),
    ("rk_test_", 16, Alphabet::Alnum),
    ("whsec_", 16, Alphabet::Alnum),
    // Google API key.
    ("AIza", 35, Alphabet::Url),
    // AWS access key IDs (long-term and temporary).
    ("AKIA", 16, Alphabet::Upper),
    ("ASIA", 16, Alphabet::Upper),
    // OpenAI- and Anthropic-style secret keys.
    ("sk-", 32, Alphabet::Url),
    // npm, Hugging Face, PyPI, DigitalOcean and Shopify tokens.
    ("npm_", 36, Alphabet::Alnum),
    ("hf_", 30, Alphabet::Alnum),
    ("pypi-AgEIcHlwaS5vcmc", 32, Alphabet::Url),
    ("dop_v1_", 64, Alphabet::Alnum),
    ("shpat_", 32, Alphabet::Alnum),
    ("shpss_", 32, Alphabet::Alnum),
];

#[derive(Clone, Copy)]
enum Alphabet {
    Alnum,
    AlnumDash,
    Upper,
    Word,
    Url,
}

impl Alphabet {
    fn allows(self, c: u8) -> bool {
        match self {
            Alphabet::Alnum => c.is_ascii_alphanumeric(),
            Alphabet::AlnumDash => c.is_ascii_alphanumeric() || c == b'-',
            Alphabet::Upper => c.is_ascii_uppercase() || c.is_ascii_digit(),
            Alphabet::Word => c.is_ascii_alphanumeric() || c == b'_',
            Alphabet::Url => c.is_ascii_alphanumeric() || c == b'_' || c == b'-',
        }
    }
}

/// True when `token` (a whole run of `[A-Za-z0-9_.-]`) has the shape of a known credential.
pub fn is_known_credential(token: &str) -> bool {
    if is_jwt(token) {
        return true;
    }
    if let Some(body) = token.strip_prefix("SG.") {
        // SendGrid: SG.<22>.<43>
        let mut parts = body.split('.');
        return matches!((parts.next(), parts.next(), parts.next()),
            (Some(a), Some(b), None) if a.len() == 22 && b.len() == 43
                && a.bytes().chain(b.bytes()).all(|c| Alphabet::Url.allows(c)));
    }
    CREDENTIAL_PREFIXES.iter().any(|(prefix, min, alphabet)| {
        token
            .strip_prefix(prefix)
            .is_some_and(|body| body.len() >= *min && body.bytes().all(|c| alphabet.allows(c)))
    })
}

/// A compact JWS (`header.payload.signature`) or JWE (five parts) whose header is base64url
/// JSON, i.e. starts with `eyJ` (`{"`).
fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    let b64url = |p: &str| p.bytes().all(|c| Alphabet::Url.allows(c));
    parts.len() >= 2
        && token.len() >= 30
        && parts[0].starts_with("eyJ")
        && parts[0].len() >= 10
        && parts.iter().all(|p| b64url(p))
        && match parts.len() {
            // `header.payload.` (unsigned) once the empty part is trimmed, or a JWS.
            2 | 3 => parts[1].starts_with("eyJ"),
            5 => true,
            _ => false,
        }
}

fn redact_auth_value(value: &str) -> String {
    let trimmed = value.trim();
    match trimmed.split_once(char::is_whitespace) {
        Some((scheme, _)) if AUTH_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) => {
            format!("{scheme} {REDACTED}")
        }
        _ => REDACTED.to_string(),
    }
}

fn redact_cookie_header(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) => format!("{}={REDACTED}", name.trim()),
            None => REDACTED.to_string(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn redact_set_cookie(value: &str) -> String {
    let mut parts = value.split(';');
    let first = parts.next().unwrap_or("");
    let mut out = match first.split_once('=') {
        Some((name, _)) => format!("{}={REDACTED}", name.trim()),
        None => REDACTED.to_string(),
    };
    // Attributes (Path, Domain, Expires, Secure, HttpOnly, SameSite) are kept for diagnostics.
    for attr in parts {
        out.push(';');
        out.push_str(attr);
    }
    out
}

/// Sanitize a request target or URL: userinfo, secret query parameters and
/// secret fragment parameters (implicit-grant tokens) are redacted.
pub fn sanitize_target(target: &str) -> String {
    sanitize_target_at(target, 0)
}

/// How deep URLs nested in parameters, and JSON nested in JSON strings, are followed.
const MAX_NESTING: usize = 4;

fn sanitize_target_at(target: &str, depth: usize) -> String {
    let (before_fragment, fragment) = match target.split_once('#') {
        Some((a, f)) => (a, Some(f)),
        None => (target, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (before_fragment, None),
    };
    let mut out = strip_userinfo(base);
    if let Some(q) = query {
        out.push('?');
        out.push_str(&sanitize_params_at(q, depth));
    }
    if let Some(f) = fragment {
        out.push('#');
        if f.contains('=') {
            // A hash route (`#/cb?token=…`) carries its parameters after its own `?`. A `?`
            // after a parameter (`#access_token=…&next=/x?y=1`) is part of a value instead.
            match f.split_once('?') {
                Some((route, params)) if !route.contains('=') => {
                    out.push_str(route);
                    out.push('?');
                    out.push_str(&sanitize_params_at(params, depth));
                }
                _ => out.push_str(&sanitize_params_at(f, depth)),
            }
        } else {
            out.push_str(f);
        }
    }
    out
}

fn strip_userinfo(base: &str) -> String {
    if let Some(idx) = base.find("://") {
        let authority_start = idx + 3;
        let rest = &base[authority_start..];
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if let Some(at) = authority.rfind('@') {
            return format!(
                "{}{REDACTED}@{}{}",
                &base[..authority_start],
                &authority[at + 1..],
                &rest[authority_end..]
            );
        }
    }
    base.to_string()
}

/// Sanitize `a=1&b=2` style parameters (query strings, fragments, form bodies).
pub fn sanitize_params(params: &str) -> String {
    sanitize_params_at(params, 0)
}

/// A parameter whose own name is harmless is still redacted when its (percent-decoded) value
/// carries a nested URL, query string or JSON with a secret, e.g. `next=%2Fcb%3Ftoken%3D…`.
/// The whole value is replaced: re-encoding a partially cleaned nested URL is not attempted.
fn sanitize_params_at(params: &str, depth: usize) -> String {
    params
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_key(key) => {
                format!("{key}={REDACTED}")
            }
            Some((key, value)) if depth < MAX_NESTING && nested_secret(value, depth + 1) => {
                format!("{key}={REDACTED}")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// True when a parameter name is sensitive as written or after percent-decoding, including
/// repeated (double) encoding such as `tok%2565n`, followed as deep as nested values are.
fn is_sensitive_key(key: &str) -> bool {
    let mut name = key.to_string();
    for _ in 0..=MAX_NESTING {
        if is_sensitive_name(&name) {
            return true;
        }
        if !name.contains(['%', '+']) {
            return false;
        }
        let decoded = percent_decode(&name);
        if decoded == name {
            return false;
        }
        name = decoded;
    }
    is_sensitive_name(&name)
}

/// True when a parameter value, percent-decoded, holds a URL, query string or JSON text that
/// the rules would change.
fn nested_secret(value: &str, depth: usize) -> bool {
    if !value.contains(['%', '=', '{', '[']) {
        return false;
    }
    let decoded = percent_decode(value);
    let trimmed = decoded.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return redact_json_at(&decoded, depth) != decoded;
    }
    sanitize_query_like(&decoded, depth).is_some()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One character of a URL written in free text, with the bytes it was written as. HTML
/// character references (`&amp;`, `&#x3f;`, `&quest;`) and script escapes (`&`, `\x26`,
/// `\/`) count as the character they encode, so `&amp;token=` splits like `&token=`.
#[derive(Clone, Copy)]
struct Unit {
    ch: char,
    start: usize,
    end: usize,
}

/// Named character references that can spell URL delimiters or quotes.
const NAMED_REFS: &[(&str, char)] = &[
    ("amp;", '&'),
    ("AMP;", '&'),
    ("quest;", '?'),
    ("equals;", '='),
    ("num;", '#'),
    ("sol;", '/'),
    ("colon;", ':'),
    ("commat;", '@'),
    ("percnt;", '%'),
    ("quot;", '"'),
    ("apos;", '\''),
    ("lt;", '<'),
    ("gt;", '>'),
];

fn decode_unit(s: &str, i: usize) -> Unit {
    let rest = &s[i..];
    let c = rest.chars().next().unwrap_or('\0');
    let unit = |ch: char, len: usize| Unit {
        ch,
        start: i,
        end: i + len,
    };
    let hex_char = |h: Option<&str>| {
        h.filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .and_then(char::from_u32)
    };
    if c == '&' {
        if let Some(num) = rest[1..].strip_prefix('#') {
            let (digits, radix, lead) = match num.strip_prefix(['x', 'X']) {
                Some(h) => (h, 16, 3),
                None => (num, 10, 2),
            };
            let n = digits
                .bytes()
                .take_while(|b| (*b as char).is_digit(radix))
                .count();
            if (1..=8).contains(&n) && digits.as_bytes().get(n) == Some(&b';') {
                if let Some(ch) = u32::from_str_radix(&digits[..n], radix)
                    .ok()
                    .and_then(char::from_u32)
                {
                    return unit(ch, lead + n + 1);
                }
            }
        }
        if let Some((name, ch)) = NAMED_REFS.iter().find(|(n, _)| rest[1..].starts_with(n)) {
            return unit(*ch, 1 + name.len());
        }
    } else if c == '\\' {
        let next = rest[1..].chars().next();
        if next == Some('/') {
            return unit('/', 2);
        }
        if next == Some('u') {
            if let Some(ch) = hex_char(rest.get(2..6)) {
                return unit(ch, 6);
            }
        }
        if next == Some('x') {
            if let Some(ch) = hex_char(rest.get(2..4)) {
                return unit(ch, 4);
            }
        }
    }
    unit(c, c.len_utf8())
}

fn decode_units(s: &str) -> Vec<Unit> {
    let mut units = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let u = decode_unit(s, i);
        i = u.end;
        units.push(u);
    }
    units
}

fn units_text(units: &[Unit]) -> String {
    units.iter().map(|u| u.ch).collect()
}

/// Characters that end a URL written in free text.
fn ends_url(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | '`')
}

/// Whether a name could be a query parameter. Script that merely contains `?`, `&` and `=`
/// (`a?b:c&&(x.token=y)`) yields names with code punctuation, which no URL parameter uses.
/// Anything else counts, malformed escapes included (`&#xZZ;token=`), so an ambiguous name
/// is judged by the name rules rather than skipped.
fn is_param_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(|c: char| c.is_whitespace() || "(){},:".contains(c))
}

/// Redact URL credentials written in free text: plain-text, HTML, XML and script bodies, and
/// header values. Each run of text delimited by whitespace, quotes or angle brackets is read
/// as a possible URL; its userinfo, and query or fragment parameters that the request-target
/// rules would redact, have their values replaced. Every other byte is kept as written.
/// `None` when nothing changed.
fn redact_urls_in_text(text: &str, depth: usize) -> Option<String> {
    let mut spans = Vec::new();
    let mut run_start = None;
    for (i, c) in text
        .char_indices()
        .chain(std::iter::once((text.len(), ' ')))
    {
        match (run_start, ends_url(c)) {
            (None, false) => run_start = Some(i),
            (Some(start), true) => {
                run_start = None;
                let run = &text[start..i];
                if run.contains(['=', '@', '&', '\\']) {
                    spans.extend(
                        url_secret_spans(&decode_units(run), depth)
                            .into_iter()
                            .map(|(a, b)| (start + a, start + b)),
                    );
                }
            }
            _ => {}
        }
    }
    if spans.is_empty() {
        return None;
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (a, b) in spans {
        if a < copied {
            continue;
        }
        out.push_str(&text[copied..a]);
        out.push_str(REDACTED);
        copied = b;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// Byte ranges, within one URL candidate, of values to redact: userinfo, and the values of
/// query or fragment parameters with a sensitive name or a nested secret.
fn url_secret_spans(units: &[Unit], depth: usize) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let chars: Vec<char> = units.iter().map(|u| u.ch).collect();
    if let Some(p) = chars.windows(3).position(|w| w == [':', '/', '/']) {
        let auth_start = p + 3;
        let auth_end = (auth_start..chars.len())
            .find(|&k| matches!(chars[k], '/' | '?' | '#'))
            .unwrap_or(chars.len());
        if let Some(at) = (auth_start..auth_end).rev().find(|&k| chars[k] == '@') {
            if at > auth_start && units_text(&units[auth_start..at]) != REDACTED {
                spans.push((units[auth_start].start, units[at - 1].end));
            }
        }
    }
    let q = chars.iter().position(|&c| c == '?');
    let h = chars.iter().position(|&c| c == '#');
    // A hash route (`#/cb?token=…`) carries its parameters after its own `?`. A `?` after a
    // parameter (`#access_token=…&next=/x?y=1`) is part of a value instead.
    let fragment = |h: usize| {
        let f = h + 1;
        let start = match chars[f..].iter().position(|&c| c == '?') {
            Some(p) if !chars[f..f + p].contains(&'=') => f + p + 1,
            _ => f,
        };
        start..chars.len()
    };
    let regions = match (q, h) {
        (Some(q), Some(h)) if q < h => [Some(q + 1..h), Some(fragment(h))],
        (Some(q), None) => [Some(q + 1..chars.len()), None],
        (_, Some(h)) => [None, Some(fragment(h))],
        (None, None) => [None, None],
    };
    for region in regions.into_iter().flatten() {
        for pair in units[region].split(|u| u.ch == '&') {
            let Some(eq) = pair.iter().position(|u| u.ch == '=') else {
                continue;
            };
            let key = units_text(&pair[..eq]);
            let value = &pair[eq + 1..];
            let (Some(first), Some(last)) = (value.first(), value.last()) else {
                continue;
            };
            let v = units_text(value);
            if v == REDACTED || !is_param_name(&key) {
                continue;
            }
            // `&ampkey=`: without its `;`, `&amp` may or may not be read as `&`. Either reading
            // that makes the name sensitive counts.
            let legacy_amp = key.strip_prefix("amp").is_some_and(is_sensitive_key);
            if is_sensitive_key(&key)
                || legacy_amp
                || (depth < MAX_NESTING && nested_secret(&v, depth + 1))
            {
                spans.push((first.start, last.end));
            }
        }
    }
    spans
}

/// Prefix of the text stored in place of a body DropSuite could not inspect.
pub const OMITTED_PREFIX: &str = "[DropSuite: body not stored]";
/// Bodies shorter than this get no hash: a hash of a short secret could be confirmed by guessing.
const MIN_HASHED_LEN: usize = 64;

/// The fail-closed record kept instead of a body that cannot be decoded and inspected:
/// why it was omitted, its declared type, its captured length and, for longer bodies, a SHA-256.
pub fn omitted_body(reason: &str, content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let hash = (body.len() >= MIN_HASHED_LEN).then(|| {
        Sha256::digest(body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    omission_record(reason, content_type, body.len() as u64, hash.as_deref())
}

/// The same record for a body that was streamed rather than held: its observed length and,
/// when known, the SHA-256 of the complete body. Bodies under 64 bytes never get a hash.
pub fn omission_record(
    reason: &str,
    content_type: Option<&str>,
    length: u64,
    sha256: Option<&str>,
) -> Vec<u8> {
    let hash = match sha256 {
        Some(h) if length >= MIN_HASHED_LEN as u64 => h,
        Some(_) => "not recorded (body under 64 bytes)",
        None if length < MIN_HASHED_LEN as u64 => "not recorded (body under 64 bytes)",
        None => "not recorded",
    };
    let ct = content_type
        .unwrap_or("none")
        .replace([';', '\r', '\n'], ",");
    let reason = reason.replace([';', '\r', '\n'], ",");
    format!(
        "{OMITTED_PREFIX} reason={reason}; content-type={ct}; length={length} bytes; sha256={hash}"
    )
    .into_bytes()
}

fn is_omission(body: &[u8]) -> bool {
    body.starts_with(OMITTED_PREFIX.as_bytes())
}

/// The body as text, tolerating a multi-byte character cut off by a truncated capture.
fn as_text(body: &[u8]) -> Option<&str> {
    match std::str::from_utf8(body) {
        Ok(text) => Some(text),
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&body[..e.valid_up_to()]).ok(),
        Err(_) => None,
    }
}

/// Sanitize a message body. Readable text is stored, with secret-looking JSON and form
/// fields redacted. Anything that cannot be decoded and inspected (non-UTF-8 or binary,
/// media included, and multipart) fails closed: only an [`omitted_body`] record is kept.
///
/// The declared content type is not trusted on its own: clients routinely mislabel bodies
/// (curl's `-d` sends JSON as `application/x-www-form-urlencoded`), so JSON is recognised by
/// its shape whatever the label says.
pub fn sanitize_body(content_type: Option<&str>, body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    if is_omission(body) {
        return body.to_vec();
    }
    let ct = content_type.unwrap_or("").to_ascii_lowercase();
    if ct.starts_with("multipart/") {
        return omitted_body("multipart body is not parsed", content_type, body);
    }
    let Some(text) = as_text(body) else {
        return omitted_body("binary or non-UTF-8 body", content_type, body);
    };
    let trimmed = text.trim_start();
    if ct.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('[') {
        return redact_json_text(text).into_bytes();
    }
    if ct.contains("x-www-form-urlencoded") {
        return sanitize_params(text).into_bytes();
    }
    // Plain text, HTML, XML, script and other readable formats: URLs written in them get the
    // query rules; every other byte is kept as captured.
    match redact_urls_in_text(text, 0) {
        Some(clean) => clean.into_bytes(),
        None => text.as_bytes().to_vec(),
    }
}

/// Replace the values of secret-looking keys in JSON text, at any depth, while keeping
/// every other byte (formatting, key order, unknown structure) exactly as captured.
/// Tolerant of malformed and truncated input: an unterminated sensitive value is
/// redacted through to the end of the text.
///
/// Keys are compared after JSON unescaping (`"password"` is `password`). String values
/// are unescaped too; a value holding a URL, a query string or JSON text (stringified JSON)
/// is sanitized by the same rules, and only a value that changed is re-encoded.
pub fn redact_json_text(text: &str) -> String {
    redact_json_at(text, 0)
}

fn redact_json_at(text: &str, depth: usize) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let s_end = json_string_end(b, i);
        let mut j = s_end;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b':' {
            let key_end = if s_end > i + 1 && b[s_end - 1] == b'"' {
                s_end - 1
            } else {
                s_end
            };
            let raw_key = &text[i + 1..key_end];
            let sensitive = is_sensitive_name(raw_key)
                || (raw_key.contains('\\')
                    // An undecodable key is treated as sensitive: fail closed.
                    && decode_json_string(raw_key).is_none_or(|k| is_sensitive_name(&k)));
            if sensitive {
                j += 1;
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                let v_end = json_value_end(b, j);
                out.push_str(&text[copied..j]);
                out.push('"');
                out.push_str(REDACTED);
                out.push('"');
                copied = v_end;
                i = v_end;
                continue;
            }
        } else if s_end > i + 1 && b[s_end - 1] == b'"' {
            // A string value shaped like a URL, a query string or JSON text (servers often
            // echo the request URL, or nest JSON in a string): same rules, after unescaping.
            let inner = &text[i + 1..s_end - 1];
            if let Some(clean) = sanitize_string_value(inner, depth) {
                out.push_str(&text[copied..i + 1]);
                out.push_str(&clean);
                copied = s_end - 1;
            }
        }
        i = s_end;
    }
    out.push_str(&text[copied..]);
    out
}

/// The re-encoded sanitized content of a JSON string value (without its quotes), or `None`
/// when nothing in it needed redacting.
fn sanitize_string_value(raw: &str, depth: usize) -> Option<String> {
    if depth >= MAX_NESTING {
        return None;
    }
    let decoded = if raw.contains('\\') {
        match decode_json_string(raw) {
            Some(d) => d,
            // An undecodable value that looks like it carries parameters: fail closed.
            None if raw.contains('=') => return Some(REDACTED.to_string()),
            None => return None,
        }
    } else {
        raw.to_string()
    };
    let trimmed = decoded.trim_start();
    let clean = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let redacted = redact_json_at(&decoded, depth + 1);
        (redacted != decoded).then_some(redacted)?
    } else {
        sanitize_query_like(&decoded, depth)?
    };
    Some(encode_json_string(&clean))
}

/// The sanitized form of text that holds URL query parameters, or `None` when it is not
/// query-shaped or nothing in it needed redacting. Free text with spaces is left alone.
fn sanitize_query_like(value: &str, depth: usize) -> Option<String> {
    if !value.contains('=') {
        return None;
    }
    let clean = if value.contains('?') || value.contains("://") {
        sanitize_target_at(value, depth)
    } else if value.contains('&') || !value.contains(char::is_whitespace) {
        sanitize_params_at(value, depth)
    } else {
        return None;
    };
    (clean != value).then_some(clean)
}

/// Decode the content of a JSON string literal (RFC 8259 §7), surrogate pairs included.
/// `None` for an invalid escape.
fn decode_json_string(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let hex = |chars: &mut std::str::Chars<'_>| -> Option<u32> {
                    let s: String = chars.by_ref().take(4).collect();
                    (s.len() == 4).then(|| u32::from_str_radix(&s, 16).ok())?
                };
                let first = hex(&mut chars)?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let second = hex(&mut chars)?;
                    if !(0xDC00..0xE000).contains(&second) {
                        return None;
                    }
                    0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                } else {
                    first
                };
                out.push(char::from_u32(code)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Encode text as the content of a JSON string literal.
fn encode_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_string_end(b: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

fn json_value_end(b: &[u8], start: usize) -> usize {
    if start >= b.len() {
        return b.len();
    }
    match b[start] {
        b'"' => json_string_end(b, start),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = start;
            while i < b.len() {
                match b[i] {
                    b'"' => {
                        i = json_string_end(b, i);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            b.len()
        }
        _ => {
            let mut i = start;
            while i < b.len() && !matches!(b[i], b',' | b'}' | b']') && !b[i].is_ascii_whitespace()
            {
                i += 1;
            }
            i
        }
    }
}

fn find_head_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((p, p + 4));
    }
    raw.windows(2)
        .position(|w| w == b"\n\n")
        .map(|p| (p, p + 2))
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

fn is_request_line(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    is_header_name(method) && !target.is_empty() && version.starts_with("HTTP/")
}

fn sanitize_start_line(line: &str) -> String {
    if line.starts_with("HTTP/") {
        return line.to_string();
    }
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    format!("{method} {} {version}", sanitize_target(target))
}

fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = body[i..].windows(2).position(|w| w == b"\r\n")? + i;
        let size_str = std::str::from_utf8(&body[i..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if i + size > body.len() {
            return None;
        }
        out.extend_from_slice(&body[i..i + size]);
        i += size + 2;
        if i > body.len() {
            return None;
        }
    }
}

fn sanitize_message_body(
    body: &[u8],
    content_type: Option<&str>,
    chunked: bool,
    encoding: Option<&str>,
) -> Vec<u8> {
    if body.is_empty() || is_omission(body) {
        return body.to_vec();
    }
    // Compressed bodies are not decoded in this phase, so they cannot be inspected: fail closed.
    if let Some(enc) = encoding {
        let reason = format!("content-encoding {} is not decoded", enc.replace(';', ","));
        return omitted_body(&reason, content_type, body);
    }
    if chunked {
        match dechunk(body) {
            Some(decoded) => {
                let sanitized = sanitize_body(content_type, &decoded);
                if sanitized == decoded {
                    return body.to_vec();
                }
                if is_omission(&sanitized) {
                    return sanitized;
                }
                let mut out = format!("{:x}\r\n", sanitized.len()).into_bytes();
                out.extend_from_slice(&sanitized);
                out.extend_from_slice(b"\r\n0\r\n\r\n");
                return out;
            }
            None if as_text(body).is_none() => {
                return omitted_body("malformed chunked framing", content_type, body);
            }
            None => {}
        }
    }
    sanitize_body(content_type, body)
}

/// Sanitize a captured HTTP message (start line, headers and body) for persistence.
///
/// Header lines are redacted individually, so duplicates and any letter case are covered.
/// Lines that cannot be parsed as headers are replaced, never stored as-is. A capture that
/// does not start with an HTTP start line is treated as a bare body.
pub fn sanitize_raw_message(raw: &[u8]) -> Vec<u8> {
    if raw.is_empty() {
        return Vec::new();
    }
    let split = find_head_end(raw);
    let head_bytes = match split {
        Some((head_end, _)) => &raw[..head_end],
        None => raw,
    };
    let head = String::from_utf8_lossy(head_bytes);
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines.next().unwrap_or("");
    if !(is_request_line(first) || first.starts_with("HTTP/")) {
        return sanitize_body(None, raw);
    }

    let mut out_lines = vec![sanitize_start_line(first)];
    let mut content_type: Option<String> = None;
    let mut chunked = false;
    let mut encoding: Option<String> = None;
    let mut prev_sensitive = false;
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding continues the previous header's value.
            out_lines.push(if prev_sensitive {
                format!(" {REDACTED}")
            } else {
                let content = line.trim_start();
                let indent = &line[..line.len() - content.len()];
                format!("{indent}{}", redact_unnamed_header_value(content))
            });
            continue;
        }
        match line.split_once(':') {
            Some((name, value)) if is_header_name(name) => {
                let value = value.trim_start();
                match name.to_ascii_lowercase().as_str() {
                    "content-type" => content_type = Some(value.to_string()),
                    "transfer-encoding" => {
                        chunked |= value.to_ascii_lowercase().contains("chunked")
                    }
                    "content-encoding" if !value.trim().eq_ignore_ascii_case("identity") => {
                        encoding = Some(value.trim().to_string())
                    }
                    _ => {}
                }
                prev_sensitive = is_sensitive_header(name);
                out_lines.push(format!("{name}: {}", redact_header_value(name, value)));
            }
            _ => {
                // A continuation of a line that was not stored is not stored either.
                prev_sensitive = true;
                out_lines.push(UNPARSED_LINE.to_string());
            }
        }
    }

    let mut out = out_lines.join("\r\n").into_bytes();
    if let Some((_, body_start)) = split {
        out.extend_from_slice(b"\r\n\r\n");
        out.extend_from_slice(&sanitize_message_body(
            &raw[body_start..],
            content_type.as_deref(),
            chunked,
            encoding.as_deref(),
        ));
    }
    out
}

/// Sanitize parsed `(name, value)` header pairs.
pub fn sanitize_header_pairs(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.clone(), redact_header_value(name, value)))
        .collect()
}

/// The persistence boundary: the only form of a transaction that may be stored, logged,
/// broadcast or returned to the interface. Idempotent.
pub fn sanitize_record(record: &TransactionRecord) -> TransactionRecord {
    TransactionRecord {
        url: sanitize_target(&record.url),
        path: sanitize_target(&record.path),
        host: match record.host.rsplit_once('@') {
            Some((_, host)) => host.to_string(),
            None => record.host.clone(),
        },
        request_headers: sanitize_header_pairs(&record.request_headers),
        request_body: sanitize_raw_message(&record.request_body),
        response_headers: sanitize_header_pairs(&record.response_headers),
        response_body: sanitize_raw_message(&record.response_body),
        ..record.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARK: &str = "DSMARK_unit_9f2c";

    fn s(raw: &str) -> String {
        String::from_utf8(sanitize_raw_message(raw.as_bytes())).unwrap()
    }

    #[test]
    fn authorization_keeps_scheme_only() {
        assert_eq!(
            redact_header_value("Authorization", &format!("Bearer {MARK}")),
            "Bearer [REDACTED]"
        );
        assert_eq!(
            redact_header_value("authorization", &format!("Basic {MARK}")),
            "Basic [REDACTED]"
        );
        assert_eq!(
            redact_header_value("PROXY-AUTHORIZATION", &format!("Digest u={MARK}")),
            "Digest [REDACTED]"
        );
        // An unknown first word may itself be the secret.
        assert_eq!(
            redact_header_value("Authorization", &format!("{MARK} extra")),
            REDACTED
        );
        assert_eq!(redact_header_value("Authorization", MARK), REDACTED);
    }

    #[test]
    fn cookies_keep_names_and_attributes() {
        assert_eq!(
            redact_header_value("Cookie", &format!("sid={MARK}; theme=dark")),
            "sid=[REDACTED]; theme=[REDACTED]"
        );
        assert_eq!(
            redact_header_value(
                "Set-Cookie",
                &format!("sid={MARK}; Path=/; HttpOnly; Secure")
            ),
            "sid=[REDACTED]; Path=/; HttpOnly; Secure"
        );
    }

    #[test]
    fn api_key_style_headers_and_safe_headers() {
        for name in [
            "X-API-Key",
            "x-auth-token",
            "X-Amz-Security-Token",
            "X-CSRF-Token",
            "X-Goog-Api-Key",
            "Session-Id",
        ] {
            assert_eq!(redact_header_value(name, MARK), REDACTED, "{name}");
        }
        for name in [
            "Content-Type",
            "User-Agent",
            "Access-Control-Allow-Credentials",
            "WWW-Authenticate",
            "Host",
        ] {
            assert_eq!(redact_header_value(name, "keep"), "keep", "{name}");
        }
    }

    #[test]
    fn raw_request_redacts_duplicates_mixed_case_and_targets() {
        let raw = format!(
            "POST http://user:{MARK}@example.test/p?api_key={MARK}&page=2#access_token={MARK} HTTP/1.1\r\n\
             Host: example.test\r\n\
             aUtHoRiZaTiOn: Bearer {MARK}\r\n\
             Cookie: a={MARK}\r\n\
             COOKIE: b={MARK}\r\n\
             X-Api-Key: {MARK}\r\n\
             x-api-key: {MARK}\r\n\
             Referer: http://example.test/?token={MARK}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\r\n\
             user=alice&password={MARK}&remember=1"
        );
        let out = s(&raw);
        assert!(!out.contains(MARK), "{out}");
        assert!(out.starts_with("POST http://[REDACTED]@example.test/p?api_key=[REDACTED]&page=2#access_token=[REDACTED] HTTP/1.1\r\n"));
        assert!(out.contains("aUtHoRiZaTiOn: Bearer [REDACTED]"));
        assert!(out.contains("Host: example.test"));
        assert!(out.ends_with("\r\n\r\nuser=alice&password=[REDACTED]&remember=1"));
    }

    #[test]
    fn raw_response_redacts_set_cookie_and_json() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nSet-Cookie: s={MARK}; HttpOnly\r\nset-cookie: t={MARK}\r\nContent-Type: application/json\r\n\r\n\
             {{\"user\":\"alice\",\"access_token\":\"{MARK}\",\"nested\":{{\"refreshToken\":\"{MARK}\",\"ok\":true}},\
             \"credentials\":{{\"a\":\"{MARK}\"}},\"apiKeys\":[\"{MARK}\"],\"note\":\"has \\\"password\\\": inside\"}}"
        );
        let out = s(&raw);
        assert!(!out.contains(MARK), "{out}");
        assert!(out.contains("\"user\":\"alice\""));
        assert!(out.contains("\"ok\":true"));
        assert!(out.contains("Set-Cookie: s=[REDACTED]; HttpOnly"));
    }

    #[test]
    fn chunked_json_is_decoded_and_redacted() {
        let body = format!("{{\"password\":\"{MARK}\"}}");
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        assert!(!s(&raw).contains(MARK));
    }

    #[test]
    fn malformed_and_truncated_input_is_conservative() {
        // Truncated head: no blank line, last header cut mid-value.
        let out = s(&format!(
            "GET / HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer {MARK}"
        ));
        assert!(!out.contains(MARK));
        // A line that is not a header is replaced, not stored.
        let out = s(&format!("GET / HTTP/1.1\r\nnot a header {MARK}\r\n\r\n"));
        assert!(!out.contains(MARK) && out.contains(UNPARSED_LINE));
        // Folded continuation of a sensitive header.
        let out = s(&format!("GET / HTTP/1.1\r\nCookie: a=1\r\n {MARK}\r\n\r\n"));
        assert!(!out.contains(MARK));
        // Truncated JSON with an unterminated secret.
        let out = String::from_utf8(sanitize_body(
            Some("application/json"),
            format!("{{\"token\":\"{MARK}").as_bytes(),
        ))
        .unwrap();
        assert!(!out.contains(MARK));
    }

    #[test]
    fn bare_bodies_and_plain_traffic_are_unchanged() {
        assert_eq!(
            sanitize_raw_message(b"{\"username\":\"admin\"}"),
            b"{\"username\":\"admin\"}"
        );
        assert_eq!(sanitize_raw_message(b"OK"), b"OK");
        let plain = "GET /api/users?page=2 HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n";
        assert_eq!(s(plain), plain);
    }

    fn head_and_body(raw: &[u8]) -> (String, Vec<u8>) {
        let out = sanitize_raw_message(raw);
        let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        (
            String::from_utf8_lossy(&out[..split]).into_owned(),
            out[split + 4..].to_vec(),
        )
    }

    #[test]
    fn compressed_bodies_fail_closed_with_metadata() {
        // A gzip-encoded body is opaque to the sanitizer; it must not be stored even though
        // the bytes here happen to contain the marker in clear.
        let body = format!(
            "{{\"access_token\":\"{MARK}\",\"padding\":\"{}\"}}",
            "x".repeat(80)
        );
        let raw = [
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nSet-Cookie: s={MARK}\r\n\r\n").as_bytes(),
            body.as_bytes(),
        ]
        .concat();
        let (head, stored) = head_and_body(&raw);
        let stored = String::from_utf8(stored).unwrap();
        assert!(!head.contains(MARK) && !stored.contains(MARK));
        assert!(stored.starts_with(OMITTED_PREFIX), "{stored}");
        assert!(stored.contains("reason=content-encoding gzip is not decoded"));
        assert!(stored.contains("content-type=application/json"));
        assert!(stored.contains(&format!("length={} bytes", body.len())));
        assert!(stored.contains("sha256=") && !stored.contains("not recorded"));
        assert!(
            head.contains("Content-Encoding: gzip"),
            "the head stays for diagnostics"
        );
    }

    #[test]
    fn binary_media_and_multipart_fail_closed() {
        let mut png = b"\x89PNG\r\n\x1a\n\x00\x00".to_vec();
        png.extend_from_slice(MARK.as_bytes());
        png.extend_from_slice(&[0xff, 0xfe, 0x00]);
        let raw = [
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".as_slice(),
            &png,
        ]
        .concat();
        let (_, stored) = head_and_body(&raw);
        let stored = String::from_utf8(stored).unwrap();
        assert!(!stored.contains(MARK) && stored.contains("reason=binary or non-UTF-8 body"));
        assert!(
            stored.contains("not recorded (body under 64 bytes)"),
            "short bodies get no hash"
        );

        let multipart = format!(
            "POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=x\r\n\r\n\
             --x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{MARK}\r\n--x--\r\n"
        );
        let (_, stored) = head_and_body(multipart.as_bytes());
        let stored = String::from_utf8(stored).unwrap();
        assert!(!stored.contains(MARK) && stored.contains("reason=multipart body is not parsed"));
        assert!(stored.contains("content-type=multipart/form-data, boundary=x"));
    }

    #[test]
    fn readable_text_is_kept_and_truncation_tolerated() {
        // A capture cut in the middle of a multi-byte character is still readable text.
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"note\":\"caf\u{e9} \",\"token\":\"{MARK}\",\"x\":\"\u{e9}")
            .into_bytes();
        raw.pop(); // cut the last character in half
        let (_, stored) = head_and_body(&raw);
        let stored = String::from_utf8(stored).unwrap();
        assert!(!stored.contains(MARK) && stored.contains("caf\u{e9}"));
        let html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hello</p>";
        assert_eq!(s(html), html);
    }

    #[test]
    fn omission_records_are_idempotent() {
        for raw in [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n{}",
                "y".repeat(100)
            )
            .into_bytes(),
            [
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                    .as_slice(),
                &[0x1f, 0x8b, 0x08, 0x00],
            ]
            .concat(),
        ] {
            let once = sanitize_raw_message(&raw);
            assert_eq!(sanitize_raw_message(&once), once);
        }
    }

    #[test]
    fn mislabelled_json_is_still_redacted() {
        // curl -d '{"password":...}' declares the JSON body as form-urlencoded.
        let raw = format!(
            "POST /api/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n\
             {{\"username\":\"alice\",\"password\":\"{MARK}\"}}"
        );
        let out = s(&raw);
        assert!(!out.contains(MARK), "{out}");
        assert!(out.contains("\"username\":\"alice\""));
        // Unlabelled and text/plain JSON too.
        for ct in [None, Some("text/plain")] {
            let body = sanitize_body(ct, format!("{{\"api_key\":\"{MARK}\"}}").as_bytes());
            assert!(!String::from_utf8(body).unwrap().contains(MARK));
        }
    }

    #[test]
    fn query_strings_echoed_inside_json_values_are_redacted() {
        let body = format!(
            "{{\"query\":\"?case=plain&api_key={MARK}\",\"url\":\"http://h.test/p?token={MARK}&page=2\",\"pairs\":\"a=1&password={MARK}\",\"note\":\"a=b means equal\",\"plain\":\"x?y\"}}"
        );
        let out = redact_json_text(&body);
        assert!(!out.contains(MARK), "{out}");
        assert!(out.contains("\"query\":\"?case=plain&api_key=[REDACTED]\""));
        assert!(out.contains("\"url\":\"http://h.test/p?token=[REDACTED]&page=2\""));
        assert!(out.contains("\"note\":\"a=b means equal\"") && out.contains("\"plain\":\"x?y\""));
        assert_eq!(redact_json_text(&out), out, "idempotent");
    }

    #[test]
    fn escaped_json_secrets_are_redacted() {
        let cases = [
            // Escaped key name.
            format!("{{\"p\\u0061ssword\":\"{MARK}\"}}"),
            format!("{{\"acc\\u0065ss_token\":\"{MARK}\"}}"),
            // Escaped delimiters inside a query-shaped value.
            format!("{{\"q\":\"?a=1\\u0026api_key={MARK}\"}}"),
            format!("{{\"q\":\"a=1\\u0026Api-Key={MARK}\"}}"),
            // Escaped slashes and mixed-case parameter names in a URL.
            format!("{{\"u\":\"https:\\/\\/h.test\\/p?ToKeN={MARK}\\u0026x=1\"}}"),
            // Nested arrays and objects.
            format!("{{\"a\":[1,{{\"b\":[{{\"c\":\"\\/cb?PASSWORD={MARK}\"}}]}}]}}"),
            // Stringified JSON inside a string.
            format!("{{\"payload\":\"{{\\\"session\\\":\\\"{MARK}\\\"}}\"}}"),
            // A URL percent-encoded inside a parameter, inside JSON.
            format!("{{\"next\":\"\\/login?next=%2Fcb%3Faccess_token%3D{MARK}\"}}"),
            // A single parameter with no ampersand.
            format!("{{\"v\":\"token={MARK}\"}}"),
            // A surrogate pair before the secret, and a unicode-escaped equals sign.
            format!("{{\"q\":\"\\ud83d\\ude00?secret\\u003d{MARK}\"}}"),
        ];
        for body in &cases {
            let out = redact_json_text(body);
            assert!(!out.contains(MARK), "{body}\n -> {out}");
            assert_eq!(redact_json_text(&out), out, "idempotent: {out}");
            // The result is still valid enough to round-trip through the decoder.
            assert!(out.contains("[REDACTED]"), "{out}");
        }
        // Harmless values, escaped or not, keep their exact bytes.
        for keep in [
            "{\"q\":\"?page=2\\u0026sort=asc\",\"t\":\"caf\\u00e9\",\"u\":\"https:\\/\\/h.test\\/p\"}",
            "{\"note\":\"a=b means equal\",\"plain\":\"x?y\",\"n\":3}",
        ] {
            assert_eq!(redact_json_text(keep), keep);
        }
        // A broken escape near parameters fails closed instead of passing through.
        let out = redact_json_text(&format!("{{\"q\":\"\\uZZZZ\\u0026token={MARK}\"}}"));
        assert!(!out.contains(MARK), "{out}");
    }

    #[test]
    fn nested_and_encoded_urls_in_targets_and_forms_are_redacted() {
        let target = format!("/login?next=%2Fcb%3Faccess_token%3D{MARK}&lang=en");
        let out = sanitize_target(&target);
        assert_eq!(out, "/login?next=[REDACTED]&lang=en");
        let out = sanitize_target(&format!("/r?to=/cb?TOKEN={MARK}"));
        assert!(!out.contains(MARK), "{out}");
        let form = format!("user=a&state=%7B%22password%22%3A%22{MARK}%22%7D");
        assert_eq!(sanitize_params(&form), "user=a&state=[REDACTED]");
        assert_eq!(
            sanitize_target("/p?page=2&q=hello%20world"),
            "/p?page=2&q=hello%20world"
        );
    }

    #[test]
    fn sanitization_is_idempotent() {
        let raw = format!("GET /?token={MARK} HTTP/1.1\r\nCookie: a={MARK}\r\nAuthorization: Basic {MARK}\r\n\r\n");
        let once = sanitize_raw_message(raw.as_bytes());
        assert_eq!(sanitize_raw_message(&once), once);
    }

    fn text_body(ct: &str, body: &str) -> String {
        String::from_utf8(sanitize_body(Some(ct), body.as_bytes())).unwrap()
    }

    /// Sanitizes once, checks the marker is gone, and checks a second pass changes nothing.
    fn clean_text(ct: &str, body: &str) -> String {
        let out = text_body(ct, body);
        assert!(!out.contains(MARK), "{body}\n -> {out}");
        assert_eq!(text_body(ct, &out), out, "idempotent: {out}");
        out
    }

    #[test]
    fn plain_text_urls_with_secret_parameters_are_redacted() {
        let body = format!(
            "See https://h.test/cb?page=2&access_token={MARK} for details.\n\
             Reset: /reset?lang=en&password={MARK}\n\
             Signed: https://b.test/o.bin?X-Amz-Expires=60&X-Amz-Signature={MARK}#top\n"
        );
        assert_eq!(
            clean_text("text/plain", &body),
            "See https://h.test/cb?page=2&access_token=[REDACTED] for details.\n\
             Reset: /reset?lang=en&password=[REDACTED]\n\
             Signed: https://b.test/o.bin?X-Amz-Expires=60&X-Amz-Signature=[REDACTED]#top\n"
        );
        // Fragment parameters, hash routes and userinfo.
        let body = format!(
            "https://app.test/cb#access_token={MARK}&state=s1 \
             https://app.test/#/cb?key={MARK}&tab=1 \
             git clone https://deploy:{MARK}@git.test/r.git"
        );
        assert_eq!(
            clean_text("text/plain", &body),
            "https://app.test/cb#access_token=[REDACTED]&state=s1 \
             https://app.test/#/cb?key=[REDACTED]&tab=1 \
             git clone https://[REDACTED]@git.test/r.git"
        );
        // Unlabelled readable text and bare non-HTTP captures get the same rules.
        let bare = sanitize_raw_message(format!("log: GET /x?token={MARK} 200").as_bytes());
        assert_eq!(bare, b"log: GET /x?token=[REDACTED] 200");
    }

    #[test]
    fn html_links_and_attributes_with_secret_parameters_are_redacted() {
        let html = format!(
            "<a href=\"/cb?id=7&amp;token={MARK}\">next</a>\n\
             <img src='https://cdn.test/i.png?w=10&#38;sig={MARK}' alt=\"\">\n\
             <a href=/u?x=1&amp;api_key={MARK}>u</a>\n\
             <meta http-equiv=\"refresh\" content=\"0;url=/cb?Session={MARK}\">\n\
             <a href=\"/cb&#x3F;secret&#61;{MARK}&amp;page=2\">enc</a>\n\
             <a href=\"/m?a=1&ampkey={MARK}\">legacy</a>\n\
             <script>fetch(\"https:\\/\\/h.test\\/cb?x=1\\u0026key={MARK}\")</script>\n\
             <p>Copy https://h.test/r?ref=mail&amp;otp={MARK} into the app.</p>"
        );
        assert_eq!(
            clean_text("text/html; charset=utf-8", &html),
            "<a href=\"/cb?id=7&amp;token=[REDACTED]\">next</a>\n\
             <img src='https://cdn.test/i.png?w=10&#38;sig=[REDACTED]' alt=\"\">\n\
             <a href=/u?x=1&amp;api_key=[REDACTED]>u</a>\n\
             <meta http-equiv=\"refresh\" content=\"0;url=/cb?Session=[REDACTED]\">\n\
             <a href=\"/cb&#x3F;secret&#61;[REDACTED]&amp;page=2\">enc</a>\n\
             <a href=\"/m?a=1&ampkey=[REDACTED]\">legacy</a>\n\
             <script>fetch(\"https:\\/\\/h.test\\/cb?x=1\\u0026key=[REDACTED]\")</script>\n\
             <p>Copy https://h.test/r?ref=mail&amp;otp=[REDACTED] into the app.</p>"
        );
    }

    #[test]
    fn encoded_and_nested_urls_in_text_are_redacted() {
        let body = format!(
            "Continue: https://h.test/login?next=%2Fcb%3Faccess_token%3D{MARK}&lang=en\n\
             Double: /p?tok%2565n={MARK}&v=1\n\
             Json: /cb?state=%7B%22password%22%3A%22{MARK}%22%7D\n\
             Malformed: /cb?a=1&#xZZ;token={MARK}"
        );
        assert_eq!(
            clean_text("text/plain", &body),
            "Continue: https://h.test/login?next=[REDACTED]&lang=en\n\
             Double: /p?tok%2565n=[REDACTED]&v=1\n\
             Json: /cb?state=[REDACTED]\n\
             Malformed: /cb?a=1&#xZZ;token=[REDACTED]"
        );
        // The same double-encoded name in a request target.
        assert_eq!(
            sanitize_target(&format!("/p?tok%2565n={MARK}&v=1")),
            "/p?tok%2565n=[REDACTED]&v=1"
        );
        assert_eq!(
            sanitize_target(&format!("/app#/cb?key={MARK}&tab=1")),
            "/app#/cb?key=[REDACTED]&tab=1"
        );
    }

    #[test]
    fn harmless_text_urls_and_markup_keep_their_bytes() {
        for (ct, body) in [
            (
                "text/plain",
                "Visit https://h.test/search?q=hello%20world&page=2&id=550e8400-e29b-41d4-a716-446655440000&hash=9f86d081884c7d65 now.",
            ),
            ("text/plain", "a=b means equal; x?y; 50% off & more?"),
            ("text/html", "<p>Tom &amp; Jerry? <a href=\"/p?page=2&amp;sort=asc#s\">2</a></p>"),
            ("text/html", "<a href=\"https://h.test/\">&quot;home&quot;</a> &#169; 2026"),
            // Minified script: ternaries and `&&` are not query strings.
            ("application/javascript", "n=t?e:r&&(i.token=o),s=a?{session:b}:c;"),
            ("application/xml", "<feed><link href=\"https://h.test/f?page=3&amp;per=50\"/></feed>"),
            ("text/plain", "ETag 9f86d081884c7d65 build 4bf92f3577b34da6a3ce929d0e0e4736"),
        ] {
            assert_eq!(text_body(ct, body), body, "{ct}");
        }
    }

    // Synthetic credential-format fixtures, assembled at run time.
    fn jwt() -> String {
        format!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.{MARK}xyz")
    }

    fn known_credentials() -> Vec<String> {
        let a = "A1b2".repeat(10);
        vec![
            jwt(),
            format!("ghp_{}", &a[..36]),
            format!("github_pat_{}_{}", &a[..22], "Z".repeat(30)),
            format!("glpat-{}", &a[..20]),
            format!("xoxb-1234567890-{}", &a[..24]),
            format!("sk_live_{}", &a[..24]),
            format!("AIza{}", &a[..35]),
            format!("AKIA{}", "Q7".repeat(8)),
            format!("sk-proj-{}", &a[..40]),
            format!("npm_{}", &a[..36]),
            format!("SG.{}.{}", &a[..22], "b".repeat(43)),
        ]
    }

    #[test]
    fn known_credential_formats_in_custom_headers_are_redacted() {
        for token in known_credentials() {
            assert!(is_known_credential(&token), "{token}");
            assert_eq!(
                redact_header_value("X-Client-Info", &token),
                REDACTED,
                "{token}"
            );
            assert_eq!(
                redact_header_value("X-Debug", &format!("build=7 via {token}.")),
                "build=7 via [REDACTED].",
                "{token}"
            );
        }
        // Values written as authorization credentials keep their scheme.
        let basic = "c3ludGhldGljOnN5bnRoZXRpYy1wYXNzd29yZA=="; // synthetic:synthetic-password
        for (value, want) in [
            (format!("Bearer {}", jwt()), "Bearer [REDACTED]"),
            (format!("bearer {MARK}"), "bearer [REDACTED]"),
            (format!("Basic {basic}"), "Basic [REDACTED]"),
            (
                format!("Digest username=\"u\", response=\"{MARK}\""),
                "Digest [REDACTED]",
            ),
        ] {
            assert_eq!(redact_header_value("X-Upstream", &value), want, "{value}");
        }
        // URLs in custom headers get the query rules.
        assert_eq!(
            redact_header_value(
                "X-Callback",
                &format!("https://h.test/cb?state=s1&access_token={MARK}")
            ),
            "https://h.test/cb?state=s1&access_token=[REDACTED]"
        );
        assert_eq!(
            redact_header_value(
                "Link",
                &format!("<https://h.test/p?page=2&api_key={MARK}>; rel=\"next\"")
            ),
            "<https://h.test/p?page=2&api_key=[REDACTED]>; rel=\"next\""
        );
    }

    #[test]
    fn harmless_custom_headers_keep_their_bytes() {
        for (name, value) in [
            ("X-Request-Id", "550e8400-e29b-41d4-a716-446655440000"),
            (
                "ETag",
                "\"9f86d081884c7d65a3b8c0e2f6d4a1b29f86d081884c7d65a3b8c0e2f6d4a1b2\"",
            ),
            (
                "traceparent",
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
            ("X-Plan", "Basic plan"),
            ("X-Motd", "Bearer of good news"),
            (
                "WWW-Authenticate",
                "Bearer realm=\"api\", error=\"invalid_token\"",
            ),
            ("WWW-Authenticate", "Basic realm=\"x\""),
            ("X-Short", "sk-short ghp_tooShort AKIAEXAMPLE eyJhbGciOi"),
            ("X-Base64", "aGVsbG8gd29ybGQ="),
            ("X-Next", "https://h.test/p?page=2&sort=asc#frag"),
            (
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
            ("Content-Type", "multipart/form-data; boundary=----x"),
            (
                "Content-Disposition",
                "attachment; filename=\"report?v=2.pdf\"",
            ),
        ] {
            assert_eq!(redact_header_value(name, value), value, "{name}");
        }
    }

    #[test]
    fn raw_messages_with_custom_headers_text_bodies_are_redacted_and_stable() {
        let token = &known_credentials()[1];
        let raw = format!(
            "HTTP/1.1 200 OK\r\nX-Ident: {}\r\nX-Multi: first\r\n  {token}\r\nX-Note: plain\r\n\
             Content-Type: text/html\r\n\r\n<a href=\"/cb?id=1&amp;token={MARK}\">x</a>",
            jwt()
        );
        let out = s(&raw);
        assert!(
            !out.contains(MARK) && !out.contains(token.as_str()),
            "{out}"
        );
        assert!(
            out.contains("X-Ident: [REDACTED]\r\nX-Multi: first\r\n  [REDACTED]\r\nX-Note: plain")
        );
        assert!(
            out.ends_with("<a href=\"/cb?id=1&amp;token=[REDACTED]\">x</a>"),
            "{out}"
        );
        assert_eq!(s(&out), out, "idempotent");
        // A folded continuation of a line that was not stored is not stored either.
        let out = s(&format!("GET / HTTP/1.1\r\nbroken line\r\n {MARK}\r\n\r\n"));
        assert!(!out.contains(MARK), "{out}");
    }

    #[test]
    fn fragment_parameters_before_a_later_question_mark_are_redacted() {
        // Regression (found after P2 M2 hardening): the hash-route rule skipped every fragment
        // parameter written before a later `?`, e.g. an implicit-grant redirect carrying a
        // return path. Each path that reads URLs must redact them.
        let frag = format!("#access_token={MARK}&next=/x?y=1");
        let clean_frag = "#access_token=[REDACTED]&next=/x?y=1";
        let url = format!("https://app.test/cb{frag}");
        let clean_url = format!("https://app.test/cb{clean_frag}");

        // Request URLs: target, stored url/path, raw start line.
        for (t, want) in [
            (format!("/cb{frag}"), format!("/cb{clean_frag}")),
            (
                format!("/cb?a=1#access_token={MARK}&state=s&return=/home?tab=2"),
                "/cb?a=1#access_token=[REDACTED]&state=s&return=/home?tab=2".to_string(),
            ),
            (
                format!("/cb#id_token={MARK}?x"),
                "/cb#id_token=[REDACTED]".to_string(),
            ),
            (url.clone(), clean_url.clone()),
        ] {
            assert_eq!(sanitize_target(&t), want, "{t}");
            assert_eq!(sanitize_target(&want), want, "idempotent");
        }
        let record = sanitize_record(&TransactionRecord {
            id: 1,
            timestamp: 0,
            duration_ms: 0,
            method: "GET".into(),
            url: url.clone(),
            host: "app.test".into(),
            path: format!("/cb{frag}"),
            request_headers: vec![("Referer".into(), url.clone())],
            request_body: Vec::new(),
            status_code: 302,
            response_headers: vec![
                ("Location".into(), url.clone()),
                ("Content-Location".into(), url.clone()),
            ],
            response_body: Vec::new(),
            content_type: None,
            content_length: 0,
        });
        assert_eq!(record.url, clean_url);
        assert_eq!(record.path, format!("/cb{clean_frag}"));
        for (_, v) in record
            .request_headers
            .iter()
            .chain(&record.response_headers)
        {
            assert_eq!(v, &clean_url);
        }

        // Headers: Location, Referer, Content-Location, and unrecognised names, parsed and raw.
        for name in [
            "Location",
            "Referer",
            "Content-Location",
            "X-Callback",
            "X-Return-To",
        ] {
            assert_eq!(redact_header_value(name, &url), clean_url, "{name}");
        }
        let req = s(&format!(
            "GET /cb{frag} HTTP/1.1\r\nHost: app.test\r\nReferer: {url}\r\n\r\n"
        ));
        assert_eq!(
            req,
            format!("GET /cb{clean_frag} HTTP/1.1\r\nHost: app.test\r\nReferer: {clean_url}")
                + "\r\n\r\n"
        );
        let res = s(&format!(
            "HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Location: {url}\r\nLink: <{url}>; rel=\"next\"\r\n\r\n"
        ));
        assert!(!res.contains(MARK), "{res}");
        assert_eq!(s(&res), res, "idempotent");

        // JSON string values, plain and escaped; form bodies with a percent-encoded URL.
        let json = redact_json_text(&format!("{{\"u\":\"{url}\",\"n\":1}}"));
        assert_eq!(json, format!("{{\"u\":\"{clean_url}\",\"n\":1}}"));
        let escaped = redact_json_text(&format!(
            "{{\"u\":\"https:\\/\\/app.test\\/cb#access_token={MARK}\\u0026next=\\/x?y=1\"}}"
        ));
        assert!(
            !escaped.contains(MARK) && escaped.contains("access_token=[REDACTED]"),
            "{escaped}"
        );
        assert_eq!(redact_json_text(&escaped), escaped, "idempotent");
        let form = format!(
            "next=https%3A%2F%2Fapp.test%2Fcb%23access_token%3D{MARK}%26n%3D%2Fx%3Fy%3D1&lang=en"
        );
        assert_eq!(sanitize_params(&form), "next=[REDACTED]&lang=en");

        // Plain text and HTML.
        assert_eq!(
            clean_text("text/plain", &format!("Open {url} now")),
            format!("Open {clean_url} now")
        );
        assert_eq!(
            clean_text(
                "text/html",
                &format!("<a href=\"/cb#access_token={MARK}&amp;next=/x?y=1\">x</a>")
            ),
            "<a href=\"/cb#access_token=[REDACTED]&amp;next=/x?y=1\">x</a>"
        );
    }

    #[test]
    fn harmless_and_ambiguous_fragments_after_the_hash_route_fix() {
        // Harmless fragments, including key-value data before a later `?`, keep every byte in
        // every path.
        for frag in [
            "#section-2",
            "#/route?page=2",
            "#/route?page=2&tab=1",
            "#a=1&b=2?c=3",
            "#page=2&tab=x?y",
            "#a=1&next=/x?y=1",
            "#?",
            "#=",
        ] {
            let target = format!("/doc{frag}");
            let url = format!("https://app.test/doc{frag}");
            assert_eq!(sanitize_target(&target), target);
            for name in ["Location", "Referer", "Content-Location", "X-Next"] {
                assert_eq!(redact_header_value(name, &url), url, "{name} {frag}");
            }
            assert_eq!(
                text_body("text/plain", &format!("see {url} now")),
                format!("see {url} now")
            );
            let html = format!("<a href=\"{}\">x</a>", url.replace('&', "&amp;"));
            assert_eq!(text_body("text/html", &html), html);
            let json = format!("{{\"u\":\"{url}\"}}");
            assert_eq!(redact_json_text(&json), json);
        }
        // Hash routes keep working.
        assert_eq!(
            sanitize_target(&format!("/app#/cb?key={MARK}&tab=1")),
            "/app#/cb?key=[REDACTED]&tab=1"
        );
        // Encoded delimiters, legacy `&amp`, double encoding and a route that itself holds `=`
        // are judged conservatively.
        assert_eq!(
            clean_text(
                "text/html",
                &format!("<a href=\"/cb#access_token&#61;{MARK}&amp;next=/x&#x3F;y=1\">x</a>")
            ),
            "<a href=\"/cb#access_token&#61;[REDACTED]&amp;next=/x&#x3F;y=1\">x</a>"
        );
        assert_eq!(
            clean_text(
                "text/html",
                &format!("<a href=\"/m#a=1&ampkey={MARK}&n=/x?y=1\">x</a>")
            ),
            "<a href=\"/m#a=1&ampkey=[REDACTED]&n=/x?y=1\">x</a>"
        );
        for (t, want) in [
            (
                format!("/cb#tok%2565n={MARK}&n=/x?y=1"),
                "/cb#tok%2565n=[REDACTED]&n=/x?y=1",
            ),
            (format!("/app#/cb=1?key={MARK}"), "/app#/cb=[REDACTED]"),
        ] {
            assert_eq!(sanitize_target(&t), want, "{t}");
            assert_eq!(clean_text("text/plain", &t), want, "{t}");
        }
    }
}
