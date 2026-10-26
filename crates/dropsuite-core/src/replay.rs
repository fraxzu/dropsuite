//! Replay: send one HTTP/1.1 request the user composed, only on an explicit action, and read
//! the complete response.
//!
//! - The request is validated first: method, `http://` URL, header names and values (no line
//!   breaks or control characters), and framing. Bodies always go with Content-Length.
//! - Redaction placeholders and omission summaries from history are refused, so a stand-in
//!   value is never sent as if it were real.
//! - The head is built with the proxy's own origin-request rules ([`http1::origin_request_head`]):
//!   origin-form target, Host from the URL, no hop-by-hop or proxy-only fields.
//! - The response is read to its end with the proxy's framing code, so large and chunked bodies
//!   transfer completely. What comes back to the interface is sanitized like history, and
//!   bodies over the capture limit become an omission record.
//! - The host is resolved once. Every address is checked against the proxy's destination policy
//!   (unspecified, multicast, link-local, cloud metadata, and their mapped/NAT64 forms) before
//!   connecting, and the connection goes only to those checked addresses.
//! - No redirect is followed and nothing is retried. Nothing is stored.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::http1::{self, BodyFraming, Capture, CopyError, FrameError, Reader};

use crate::challenge::{self, ChallengeSignal};
use crate::cookies::{self, StoredCookie};
use crate::header_preset::{self, BrowserPreset};
use crate::http2;

type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
use crate::proxy::{
    captured_message, header_pairs, is_own_listener, is_restricted_destination, resolve,
    ConnectGate, ResolverOverride,
};
use crate::sanitize::{
    omitted_body, sanitize_header_pairs, sanitize_raw_message, sanitize_target, OMITTED_PREFIX,
};

/// Methods Replay sends in this milestone.
pub const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
/// Largest request body Replay accepts from the editor.
pub const MAX_BODY: usize = 10 * 1024 * 1024;
/// How much of a Replay *response* body to keep for display/analysis. Larger than proxy history's
/// [`http1::CAPTURE_LIMIT`] because Replay responses live only in memory and are never stored.
pub const RESPONSE_CAPTURE_LIMIT: usize = 1024 * 1024;
/// Text that marks a value DropSuite removed before storage.
const PLACEHOLDER: &str = "[REDACTED";

#[derive(Debug, Clone, Deserialize)]
pub struct ReplayRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayResponse {
    pub status: u16,
    pub reason: String,
    /// Response headers, sanitized like history.
    pub headers: Vec<(String, String)>,
    /// Status line, headers and body (or an omission record), sanitized like history.
    pub message: Vec<u8>,
    pub content_type: Option<String>,
    /// Bytes received for the whole response, head included.
    pub total_bytes: u64,
    /// Bytes of the request as sent, head included.
    pub sent_bytes: u64,
    pub duration_ms: u64,
    /// `host:port` the request went to.
    pub destination: String,
    /// Request fields not sent because they only apply to one connection.
    pub dropped_headers: Vec<String>,
    /// What was sent, sanitized like history (secrets redacted, bodies over the capture
    /// limit replaced by an omission record), so attempts can be told apart without keeping
    /// the values the user typed.
    pub request_target: String,
    pub request_headers: Vec<(String, String)>,
    pub request_message: Vec<u8>,
    /// Set when the response is a bot challenge rather than the application's own answer.
    pub challenge: Option<ChallengeSignal>,
    /// Jar cookies that were attached to this request.
    pub cookies_attached: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplayError {
    /// `invalid`, `unsupported`, `loop`, `blocked`, `resolve`, `refused`, `connect`, `timeout`,
    /// `malformed`, `interrupted`, `cancelled` or `busy`.
    pub kind: &'static str,
    pub message: String,
}

impl ReplayError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        ReplayError {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn invalid(message: impl Into<String>) -> ReplayError {
    ReplayError::new("invalid", message)
}

#[derive(Clone)]
pub struct ReplayOptions {
    pub connect_timeout: Duration,
    /// How long to wait for the response head once the request is sent. The body then
    /// continues as long as data keeps arriving (see [`http1::IO_TIMEOUT`]).
    pub response_timeout: Duration,
    /// DropSuite's own listener while it runs; Replay never sends to it.
    pub own_listener: Option<SocketAddr>,
    /// Custom root certificates for upstream TLS verification. If empty, uses webpki-roots.
    pub tls_roots: Vec<CertificateDer<'static>>,
    /// Browser header preset and jar cookies to add before sending.
    pub apply: ApplyConfig,
}

/// What is added to a request before it goes out. Defaults to nothing.
#[derive(Debug, Clone, Default)]
pub struct ApplyConfig {
    /// Supplied only for header names the request does not already carry.
    pub preset: BrowserPreset,
    /// Jar cookies, already narrowed to hosts near the destination.
    pub cookies: Vec<StoredCookie>,
    /// Attach a `Cookie` header from `cookies` unless the request already has one.
    pub attach_cookies: bool,
    /// Replace the request's browser-looking headers with the preset instead of filling gaps.
    /// Used when a recorded fingerprint must match the window that solved a challenge.
    pub force_preset: bool,
    /// Exact User-Agent of that window, which Cloudflare binds the clearance cookie to.
    pub pin_user_agent: Option<String>,
    /// ClientHello shape sent to the destination.
    pub tls_profile: crate::tls_profile::TlsProfile,
}

/// Test seams for [`send_with`]. The default (what [`send`] uses) is system DNS and no gate.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct NetworkSeams {
    /// Answers name lookups before DNS.
    pub resolver: Option<ResolverOverride>,
    /// Deny-only check after the destination checks, before any socket is opened.
    pub connect_gate: Option<ConnectGate>,
}

/// A validated request, ready to send.
#[derive(Debug)]
pub struct Prepared {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub wire: Vec<u8>,
    /// Length of the body at the end of `wire`.
    pub body_len: usize,
    pub dropped_headers: Vec<String>,
    /// Whether the target uses HTTPS (TLS).
    pub tls: bool,
    /// Preset fields added because the request left them out.
    pub preset_fields: usize,
    /// Jar cookies attached to the request.
    pub cookies_attached: usize,
}

impl Prepared {
    /// The sent request as history would keep it: sanitized, body capped at the capture limit.
    pub fn snapshot(&self) -> (Vec<(String, String)>, Vec<u8>) {
        let head_len = self.wire.len() - self.body_len;
        let mut fields = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
        let mut parsed = httparse::Request::new(&mut fields);
        let _ = parsed.parse(&self.wire[..head_len]);
        let headers = header_pairs(parsed.headers);
        let raw = if self.body_len <= http1::CAPTURE_LIMIT {
            self.wire.clone()
        } else {
            let content_type = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str());
            [
                &self.wire[..head_len],
                &omitted_body(
                    &format!(
                        "body exceeds the {} KB capture limit",
                        http1::CAPTURE_LIMIT / 1024
                    ),
                    content_type,
                    &self.wire[head_len..],
                ),
            ]
            .concat()
        };
        (sanitize_header_pairs(&headers), sanitize_raw_message(&raw))
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// Validate the request and build its exact wire bytes, adding nothing.
pub fn prepare(req: &ReplayRequest) -> Result<Prepared, ReplayError> {
    prepare_with(req, &ApplyConfig::default())
}

/// [`prepare`] with a header preset and jar cookies applied first.
pub fn prepare_with(req: &ReplayRequest, apply: &ApplyConfig) -> Result<Prepared, ReplayError> {
    let method = req.method.trim();
    if !METHODS.contains(&method) {
        return Err(invalid(format!("Choose one of {}.", METHODS.join(", "))));
    }
    let url = req.url.trim();
    if url.contains(PLACEHOLDER) {
        return Err(invalid(
            "The URL still contains a [REDACTED] placeholder. Enter the real value or remove that parameter.",
        ));
    }
    let lower = url.to_ascii_lowercase();
    let tls = lower.starts_with("https://");
    if !lower.starts_with("http://") && !tls {
        return Err(invalid("The URL must start with http:// or https://."));
    }
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(invalid(
            "The URL contains spaces or control characters. Percent-encode them (a space is %20).",
        ));
    }
    let scheme_prefix = if tls { "https://" } else { "http://" };
    let rest = &url[scheme_prefix.len()..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@') {
        return Err(invalid(
            "Credentials in the URL (user:password@) are not sent. Use an Authorization header instead.",
        ));
    }
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = http1::split_authority(authority, default_port)
        .ok_or_else(|| invalid("The URL has no valid host and port."))?;
    // The proxy listener refuses SMTP because plain HTTP framing against it is useless; Replay
    // keeps the same rule so a captured request behaves the same here.
    if port == 25 {
        return Err(invalid(
            "Port 25 is SMTP. The proxy listener refuses it too; use 587 or 465 for mail endpoints."
                .to_string(),
        ));
    }
    let origin = http1::origin_form(method, url);

    let body = req.body.as_bytes();
    if body.len() > MAX_BODY {
        return Err(invalid(format!(
            "The body is larger than {} MB.",
            MAX_BODY / (1024 * 1024)
        )));
    }
    if req.body.contains(OMITTED_PREFIX) {
        return Err(invalid(
            "The body is DropSuite's summary of a body that was not stored, not the body itself. The original cannot be recovered: write a new body or clear it.",
        ));
    }
    if req.body.contains(PLACEHOLDER) {
        return Err(invalid(
            "The body still contains a [REDACTED] placeholder. Enter the real value or remove it.",
        ));
    }

    // A forced preset stands in for a recorded fingerprint, so its fields replace the request's
    // copies rather than only filling gaps.
    let forced = apply.force_preset && apply.preset != BrowserPreset::Off;
    let headers: Vec<&(String, String)> = req
        .headers
        .iter()
        .filter(|(n, _)| !(forced && header_preset::is_managed(n.trim())))
        .collect();

    let mut lines = String::new();
    let mut dropped = Vec::new();
    let mut existing_cookie: Option<String> = None;
    for (name, value) in headers.iter() {
        let name = name.trim();
        if !is_token(name) {
            return Err(invalid(format!(
                "\"{}\" is not a valid header name.",
                name.chars().take(40).collect::<String>()
            )));
        }
        if value.bytes().any(|b| (b < b' ' && b != b'\t') || b == 0x7f) {
            return Err(invalid(format!(
                "The {name} header contains a line break or control character."
            )));
        }
        if value.contains(PLACEHOLDER) {
            return Err(invalid(format!(
                "The {name} header still holds a [REDACTED] placeholder. Enter the real value or delete the header."
            )));
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            // Host always comes from the URL.
            "host" => continue,
            "transfer-encoding" => {
                return Err(invalid(
                    "Replay sends bodies with Content-Length. Remove the Transfer-Encoding header.",
                ))
            }
            "content-length" => {
                if value.trim() != body.len().to_string() {
                    return Err(invalid(format!(
                        "Content-Length says {} but the body is {} bytes. Correct it or delete the header and DropSuite will set it.",
                        value.trim(),
                        body.len()
                    )));
                }
                continue;
            }
            _ => {}
        }
        if lower == "cookie" {
            // Rebuilt below so jar cookies can replace stale captured values by name.
            existing_cookie = Some(value.trim().to_string());
            continue;
        }
        if HOP_BY_HOP.contains(&lower.as_str()) {
            dropped.push(name.to_string());
        }
        lines.push_str(&format!("{name}: {}\r\n", value.trim()));
    }

    // A preset only fills what the request left out. The jar is different: a captured Cookie
    // header is usually older than the jar, so jar names replace it and its other names survive.
    let present: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let preset_names = header_preset::fill(apply.preset, &present);
    let preset_fields = preset_names.len();
    let path = origin.split('?').next().unwrap_or("/");
    let jar_pairs = if apply.attach_cookies {
        cookies::pairs_for(
            &apply.cookies,
            &host,
            path,
            tls,
            chrono::Utc::now().timestamp(),
        )
    } else {
        Vec::new()
    };
    let cookies_attached = jar_pairs.len();
    let cookie_header = if jar_pairs.is_empty() {
        existing_cookie.clone()
    } else {
        Some(match &existing_cookie {
            Some(existing) => cookies::merge_cookie_header(existing, &jar_pairs),
            None => cookies::join_pairs(&jar_pairs),
        })
    };

    let pin_ua = apply.pin_user_agent.as_deref().filter(|ua| !ua.is_empty());
    let mut added = String::new();
    for (name, value) in preset_names {
        // The pinned User-Agent and its client-hint version must agree with each other and with
        // the window that earned the cookie, so both come from the recording.
        if pin_ua.is_some() && (name == "user-agent" || name == "sec-ch-ua") {
            continue;
        }
        added.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(ua) = pin_ua {
        added.push_str(&format!("user-agent: {ua}\r\n"));
        if apply.preset == BrowserPreset::Edge {
            if let Some(major) = ua
                .split("Edg/")
                .nth(1)
                .and_then(|v| v.split('.').next())
                .filter(|v| !v.is_empty())
            {
                added.push_str(&format!(
                    "sec-ch-ua: \"Microsoft Edge\";v=\"{major}\", \"Chromium\";v=\"{major}\", \"Not_A Brand\";v=\"24\"\r\n"
                ));
            }
        }
    }
    if let Some(value) = cookie_header {
        added.push_str(&format!("Cookie: {value}\r\n"));
    }
    lines = format!("{added}{lines}");

    let needs_length = !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH");
    let draft = format!(
        "{method} {origin} HTTP/1.1\r\nHost: {authority}\r\n{lines}{}\r\n",
        if needs_length {
            format!("Content-Length: {}\r\n", body.len())
        } else {
            String::new()
        }
    );
    let head =
        http1::origin_request_head(draft.as_bytes(), method, &origin, Some(authority), false);

    // The bytes about to go out must parse as exactly one well-formed head.
    let mut fields = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
    let mut check = httparse::Request::new(&mut fields);
    match check.parse(&head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        _ => return Err(invalid("The request head is not valid HTTP.")),
    }
    http1::inspect_headers(check.headers).map_err(|e| invalid(format!("{e}.")))?;

    let mut wire = head;
    wire.extend_from_slice(body);
    Ok(Prepared {
        host,
        port,
        method: method.to_string(),
        wire,
        body_len: body.len(),
        dropped_headers: dropped,
        tls,
        preset_fields,
        cookies_attached,
    })
}

/// Finish a request whose TLS handshake selected h2. Mirrors the tail of [`send_with`] so the
/// response is captured, sanitized and challenge-checked the same way.
async fn send_negotiated_h2<S>(
    io: S,
    prepared: &Prepared,
    req: &ReplayRequest,
    opts: &ReplayOptions,
    destination: String,
    started: std::time::Instant,
) -> Result<ReplayResponse, ReplayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let head_len = prepared.wire.len() - prepared.body_len;
    let mut capture = Capture::with_limit(RESPONSE_CAPTURE_LIMIT);
    let head = http2::exchange(
        io,
        &prepared.wire[..head_len],
        &prepared.wire[head_len..],
        &mut capture,
        opts.response_timeout,
    )
    .await
    .map_err(|e| {
        ReplayError::new(
            "malformed",
            format!("HTTP/2 response from {destination}: {e}."),
        )
    })?;

    let body_bytes = capture.len();
    let total_bytes = head
        .headers
        .iter()
        .map(|(n, v)| n.len() + v.len() + 4)
        .sum::<usize>() as u64
        + body_bytes
        + 16;
    let display_head = display_head(&head);
    let content_type = head
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    let raw = captured_message(
        display_head.as_bytes(),
        BodyFraming::Length(body_bytes),
        capture,
        true,
        content_type.as_deref(),
    );

    let (request_headers, request_message) = prepared.snapshot();
    let challenge = challenge::detect(head.status, &head.headers, &raw);
    Ok(ReplayResponse {
        status: head.status,
        reason: head.reason.clone(),
        headers: sanitize_header_pairs(&head.headers),
        message: sanitize_raw_message(&raw),
        content_type,
        total_bytes,
        sent_bytes: prepared.wire.len() as u64,
        duration_ms: started.elapsed().as_millis() as u64,
        destination,
        request_target: sanitize_target(req.url.trim()),
        request_headers,
        request_message,
        dropped_headers: prepared.dropped_headers.clone(),
        challenge,
        cookies_attached: prepared.cookies_attached,
    })
}

/// Status line and fields shaped like an HTTP/1.1 head, so the message pane can reuse the same
/// rendering and captured-message helper.
fn display_head(head: &http2::H2Head) -> String {
    let mut out = format!("HTTP/2 {} {}\r\n", head.status, head.reason);
    for (name, value) in &head.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out
}

/// Send the request once and read the whole response. Never follows redirects, never retries.
pub async fn send(
    req: &ReplayRequest,
    opts: &ReplayOptions,
) -> Result<ReplayResponse, ReplayError> {
    send_with(req, opts, &NetworkSeams::default()).await
}

/// [`send`] with test seams for resolution and connecting.
#[doc(hidden)]
pub async fn send_with(
    req: &ReplayRequest,
    opts: &ReplayOptions,
    net: &NetworkSeams,
) -> Result<ReplayResponse, ReplayError> {
    let prepared = prepare_with(req, &opts.apply)?;
    let destination = if prepared.host.contains(':') {
        format!("[{}]:{}", prepared.host, prepared.port)
    } else {
        format!("{}:{}", prepared.host, prepared.port)
    };
    let started = Instant::now();

    let targets: Vec<SocketAddr> = match tokio::time::timeout(
        opts.connect_timeout,
        resolve(&prepared.host, prepared.port, net.resolver.as_ref()),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(_)) => {
            return Err(ReplayError::new(
                "resolve",
                format!("Could not resolve {}.", prepared.host),
            ))
        }
        Err(_) => {
            return Err(ReplayError::new(
                "timeout",
                format!(
                    "Resolving {} took longer than {} s.",
                    prepared.host,
                    opts.connect_timeout.as_secs()
                ),
            ))
        }
    };
    if let Some(listen) = opts.own_listener {
        if targets.iter().any(|t| is_own_listener(*t, listen)) {
            return Err(ReplayError::new(
                "loop",
                format!("{destination} is DropSuite's own proxy listener. Replay sends straight to the target, never through the listener; enter the target's own address."),
            ));
        }
    }
    // The proxy's destination policy, on every resolved address before any connect: a URL
    // copied from history may name a host whose DNS now points somewhere restricted.
    // Loopback and private networks stay reachable for local API testing.
    for target in &targets {
        if let Some(reason) = is_restricted_destination(*target) {
            return Err(ReplayError::new(
                "blocked",
                format!("{destination} resolves to {}: {reason}", target.ip()),
            ));
        }
    }
    if let Some(gate) = &net.connect_gate {
        if !gate(&targets) {
            return Err(ReplayError::new(
                "connect",
                format!("Could not connect to {destination}: refused by the connect gate."),
            ));
        }
    }
    let stream =
        match tokio::time::timeout(opts.connect_timeout, TcpStream::connect(&targets[..])).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(ReplayError::new(
                    "refused",
                    format!("{destination} refused the connection. Nothing is listening there."),
                ))
            }
            Ok(Err(e)) => {
                return Err(ReplayError::new(
                    "connect",
                    format!("Could not connect to {destination}: {e}"),
                ))
            }
            Err(_) => {
                return Err(ReplayError::new(
                    "timeout",
                    format!(
                        "Connecting to {destination} took longer than {} s.",
                        opts.connect_timeout.as_secs()
                    ),
                ))
            }
        };

    let (reader_stream, mut writer_stream): (BoxedRead, BoxedWrite) = if prepared.tls {
        let mut root_store = rustls::RootCertStore::empty();
        if opts.tls_roots.is_empty() {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        } else {
            for root in &opts.tls_roots {
                let _ = root_store.add(root.clone());
            }
        }
        let mut client_config = ClientConfig::builder_with_provider(crate::tls_profile::provider(
            opts.apply.tls_profile,
        ))
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions are supported")
        .with_root_certificates(root_store)
        .with_no_client_auth();
        // Offer h2 first: bot protection notices a bare h1-only client. The branch below only
        // speaks h2 when the destination selects it, so a h1-only server is unaffected.
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name: ServerName<'static> = match prepared.host.clone().try_into() {
            Ok(name) => name,
            Err(_) => {
                return Err(ReplayError::new(
                    "invalid",
                    format!("invalid hostname for TLS: {}", prepared.host),
                ))
            }
        };
        let tls_stream = match tokio::time::timeout(
            opts.connect_timeout,
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(ReplayError::new(
                    "tls",
                    format!("TLS handshake with {destination} failed: {e}"),
                ))
            }
            Err(_) => {
                return Err(ReplayError::new(
                    "timeout",
                    format!("TLS handshake with {destination} timed out."),
                ))
            }
        };
        if tls_stream.get_ref().1.alpn_protocol() == Some(b"h2") {
            return send_negotiated_h2(tls_stream, &prepared, req, opts, destination, started)
                .await;
        }
        let (r, w) = tokio::io::split(tls_stream);
        (Box::new(r), Box::new(w))
    } else {
        let (r, w) = stream.into_split();
        (Box::new(r), Box::new(w))
    };

    match tokio::time::timeout(http1::IO_TIMEOUT, writer_stream.write_all(&prepared.wire)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(ReplayError::new(
                "interrupted",
                format!("Sending to {destination} failed: {e}"),
            ))
        }
        Err(_) => {
            return Err(ReplayError::new(
                "timeout",
                format!("Sending to {destination} stalled."),
            ))
        }
    }
    let sent_bytes = prepared.wire.len() as u64;

    let mut reader = Reader::new(reader_stream);
    let response_head = tokio::time::timeout(opts.response_timeout, async {
        loop {
            let head = match reader.read_head().await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return Err(ReplayError::new(
                        "malformed",
                        format!("{destination} closed the connection without a response."),
                    ))
                }
                Err(FrameError::Timeout) => {
                    return Err(ReplayError::new(
                        "timeout",
                        format!("{destination} sent no response."),
                    ))
                }
                Err(e) => {
                    return Err(ReplayError::new(
                        "malformed",
                        format!("The response head from {destination} is not valid: {e}."),
                    ))
                }
            };
            // Interim 1xx responses (100 Continue, 103 Early Hints) precede the real one.
            let status = head
                .get(9..12)
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| s.parse::<u16>().ok());
            if matches!(status, Some(100..=199)) && status != Some(101) {
                continue;
            }
            return Ok(head);
        }
    })
    .await
    .map_err(|_| {
        ReplayError::new(
            "timeout",
            format!(
                "{destination} did not answer within {} s.",
                opts.response_timeout.as_secs()
            ),
        )
    })??;

    let mut fields = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut fields);
    match parsed.parse(&response_head) {
        Ok(httparse::Status::Complete(n)) if n == response_head.len() => {}
        _ => {
            return Err(ReplayError::new(
                "malformed",
                format!("The response head from {destination} could not be parsed."),
            ))
        }
    }
    let status = parsed.code.unwrap_or(0);
    let reason = parsed.reason.unwrap_or("").to_string();
    let info = http1::inspect_headers(parsed.headers).map_err(|e| {
        ReplayError::new(
            "malformed",
            format!("The response from {destination} has {e}."),
        )
    })?;
    let headers = header_pairs(parsed.headers);
    let framing = if prepared.method == "HEAD" || status == 204 || status == 304 || status == 101 {
        BodyFraming::None
    } else {
        match (info.transfer_encoding, info.content_length) {
            (Some(true), _) => BodyFraming::Chunked,
            (Some(false), _) | (None, None) => BodyFraming::UntilClose,
            (None, Some(n)) => BodyFraming::Length(n),
        }
    };

    let mut capture = Capture::with_limit(RESPONSE_CAPTURE_LIMIT);
    let body = reader
        .copy_body(framing, &mut tokio::io::sink(), &mut capture)
        .await;
    let (complete, body_bytes) = match body {
        Ok(n) => (true, n),
        Err(CopyError::Read(FrameError::Malformed(why))) => {
            return Err(ReplayError::new(
                "malformed",
                format!("The response body from {destination} is malformed: {why}."),
            ))
        }
        Err(e) => {
            return Err(ReplayError::new(
                "interrupted",
                format!("The response from {destination} stopped before it was complete ({e})."),
            ))
        }
    };
    let raw = captured_message(
        &response_head,
        framing,
        capture,
        complete,
        info.content_type.as_deref(),
    );

    let (request_headers, request_message) = prepared.snapshot();
    let challenge = challenge::detect(status, &headers, &raw);
    Ok(ReplayResponse {
        status,
        reason,
        headers: sanitize_header_pairs(&headers),
        message: sanitize_raw_message(&raw),
        content_type: info.content_type,
        total_bytes: response_head.len() as u64 + body_bytes,
        sent_bytes,
        duration_ms: started.elapsed().as_millis() as u64,
        destination,
        request_target: sanitize_target(req.url.trim()),
        request_headers,
        request_message,
        dropped_headers: prepared.dropped_headers,
        challenge,
        cookies_attached: prepared.cookies_attached,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> ReplayRequest {
        ReplayRequest {
            method: method.into(),
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    fn wire(r: &ReplayRequest) -> String {
        String::from_utf8(prepare(r).unwrap().wire).unwrap()
    }

    #[test]
    fn builds_origin_form_with_content_length() {
        let w = wire(&req(
            "POST",
            "http://a.test:81/api/x?y=1#frag",
            &[
                ("Host", "other.test"),
                ("Content-Type", "application/json"),
                ("Connection", "keep-alive"),
                ("Content-Length", "7"),
            ],
            "{\"a\":1}",
        ));
        assert_eq!(
            w,
            "POST /api/x?y=1 HTTP/1.1\r\nHost: a.test:81\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"a\":1}"
        );
        assert_eq!(
            wire(&req("GET", "http://a.test", &[], "")),
            "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"
        );
        assert!(wire(&req("PUT", "http://a.test/x", &[], "")).contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn prepares_https_requests() {
        let p = prepare(&req("GET", "https://a.test/api/v1", &[], "")).unwrap();
        assert!(p.tls);
        assert_eq!(p.host, "a.test");
        assert_eq!(p.port, 443);
        assert_eq!(
            String::from_utf8(p.wire).unwrap(),
            "GET /api/v1 HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn refuses_unsafe_or_ambiguous_input() {
        let cases = [
            req("TRACE", "http://a.test/", &[], ""),
            req("GET", "ftp://a.test/", &[], ""),
            req("GET", "http://a.test/a b", &[], ""),
            req("GET", "http://u:p@a.test/", &[], ""),
            req("GET", "http://a.test/?k=[REDACTED]", &[], ""),
            req("GET", "http://a.test/", &[("X-A", "1\r\nX-Injected: 1")], ""),
            req("GET", "http://a.test/", &[("X-A\r\nX-B", "1")], ""),
            req("GET", "http://a.test/", &[("Bad Name", "1")], ""),
            req("GET", "http://a.test/", &[("Authorization", "Bearer [REDACTED]")], ""),
            req("POST", "http://a.test/", &[("Transfer-Encoding", "chunked")], "x"),
            req("POST", "http://a.test/", &[("Content-Length", "99")], "x"),
            req("POST", "http://a.test/", &[], "{\"password\":\"[REDACTED]\"}"),
            req("POST", "http://a.test/", &[], "[DropSuite: body not stored] reason=body exceeds the 16 KB capture limit; length=20000 bytes"),
        ];
        for r in &cases {
            assert!(
                prepare(r).is_err(),
                "{} {} {:?}",
                r.method,
                r.url,
                r.headers
            );
        }
    }
}
