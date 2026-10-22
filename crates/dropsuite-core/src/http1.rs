//! HTTP/1.1 message framing for the forwarding proxy (RFC 9112 §6).
//!
//! Forwarding copies the original bytes through a bounded buffer, so a message of any size
//! moves with constant memory and the writer's backpressure. Capture is separate: a
//! [`Capture`] keeps at most [`CAPTURE_LIMIT`] bytes of a body plus its length and SHA-256.
//! Framing that is malformed or ambiguous is rejected, never guessed.

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest accepted message head (start line plus headers).
pub const MAX_HEAD: usize = 64 * 1024;
/// Most header fields parsed in one head.
pub const MAX_HEADERS: usize = 128;
/// Largest body kept for capture; larger bodies are forwarded in full but not stored.
pub const CAPTURE_LIMIT: usize = 16 * 1024;
/// Longest chunk-size line (size plus extensions).
const MAX_CHUNK_LINE: usize = 4096;
/// Bytes read from a socket at a time while forwarding.
const READ_CHUNK: usize = 64 * 1024;
/// A transfer that makes no progress for this long, in either direction, is abandoned.
pub const IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// No progress within [`IO_TIMEOUT`].
    Timeout,
    /// The peer closed the connection before the message was complete.
    Closed,
    HeadTooLarge,
    Malformed(&'static str),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "{e}"),
            FrameError::Timeout => write!(f, "no data within {}s", IO_TIMEOUT.as_secs()),
            FrameError::Closed => write!(f, "connection closed before the message was complete"),
            FrameError::HeadTooLarge => write!(f, "message head larger than {MAX_HEAD} bytes"),
            FrameError::Malformed(why) => write!(f, "malformed message: {why}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Which side of a copy failed: the source (the message itself is bad or cut short) or the
/// destination (the receiver went away).
#[derive(Debug)]
pub enum CopyError {
    Read(FrameError),
    Write(std::io::Error),
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopyError::Read(e) => write!(f, "reading: {e}"),
            CopyError::Write(e) => write!(f, "writing: {e}"),
        }
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
    /// Response bodies only: the body ends when the server closes the connection.
    UntilClose,
}

/// Framing and connection facts from one message head.
#[derive(Debug, Default)]
pub struct HeadInfo {
    pub content_length: Option<u64>,
    /// `Some(true)` when Transfer-Encoding is present and its final coding is chunked.
    pub transfer_encoding: Option<bool>,
    pub connection_close: bool,
    pub upgrade: bool,
    pub content_type: Option<String>,
}

/// Read the framing headers strictly: Content-Length values must agree, Transfer-Encoding may
/// name chunked only once and only last, and the two may not appear together.
pub fn inspect_headers(headers: &[httparse::Header<'_>]) -> Result<HeadInfo, FrameError> {
    let mut info = HeadInfo::default();
    let mut codings: Vec<String> = Vec::new();
    for h in headers {
        let value =
            std::str::from_utf8(h.value).map_err(|_| FrameError::Malformed("non-ASCII header"));
        if h.name.eq_ignore_ascii_case("content-length") {
            for part in value?.split(',') {
                let part = part.trim();
                if part.is_empty() || part.len() > 19 || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(FrameError::Malformed("invalid Content-Length"));
                }
                let n: u64 = part
                    .parse()
                    .map_err(|_| FrameError::Malformed("invalid Content-Length"))?;
                if info.content_length.is_some_and(|prev| prev != n) {
                    return Err(FrameError::Malformed("conflicting Content-Length values"));
                }
                info.content_length = Some(n);
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            for coding in value?.split(',') {
                let coding = coding.trim().to_ascii_lowercase();
                if !coding.is_empty() {
                    codings.push(coding);
                }
            }
            info.transfer_encoding = Some(false);
        } else if h.name.eq_ignore_ascii_case("connection") {
            for token in value.unwrap_or("").split(',') {
                let token = token.trim();
                info.connection_close |= token.eq_ignore_ascii_case("close");
                info.upgrade |= token.eq_ignore_ascii_case("upgrade");
            }
        } else if h.name.eq_ignore_ascii_case("content-type") {
            info.content_type = value.ok().map(str::to_string);
        }
    }
    if info.transfer_encoding.is_some() {
        if info.content_length.is_some() {
            return Err(FrameError::Malformed(
                "both Transfer-Encoding and Content-Length",
            ));
        }
        let chunked = codings.iter().filter(|c| *c == "chunked").count();
        if codings.is_empty()
            || chunked > 1
            || (chunked == 1 && codings.last().unwrap() != "chunked")
        {
            return Err(FrameError::Malformed("invalid Transfer-Encoding"));
        }
        info.transfer_encoding = Some(chunked == 1);
    }
    Ok(info)
}

/// Bounded copy of a body for capture: the first [`CAPTURE_LIMIT`] bytes, the full length and
/// a SHA-256 of the full body. Once the limit is passed the kept bytes are dropped, so no
/// partial body ever reaches storage.
#[derive(Clone)]
pub struct Capture {
    kept: Vec<u8>,
    total: u64,
    hasher: Sha256,
    over_limit: bool,
    limit: usize,
}

/// What capture holds once a body is complete.
pub enum Captured {
    Complete(Vec<u8>),
    TooLarge { length: u64, sha256: String },
}

impl Default for Capture {
    fn default() -> Self {
        Self::new()
    }
}

impl Capture {
    pub fn new() -> Self {
        Self::with_limit(CAPTURE_LIMIT)
    }

    /// A capture that keeps up to `limit` bytes instead of the default [`CAPTURE_LIMIT`]. Replay
    /// uses a larger limit than proxy history, since its responses live only in memory.
    pub fn with_limit(limit: usize) -> Self {
        Capture {
            kept: Vec::new(),
            total: 0,
            hasher: Sha256::new(),
            over_limit: false,
            limit,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        self.hasher.update(data);
        if self.over_limit {
            return;
        }
        if self.kept.len() + data.len() > self.limit {
            self.over_limit = true;
            self.kept = Vec::new();
        } else {
            self.kept.extend_from_slice(data);
        }
    }

    /// The byte limit this capture keeps before dropping the body.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Body bytes seen so far.
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn finish(self) -> Captured {
        if self.over_limit {
            Captured::TooLarge {
                length: self.total,
                sha256: self
                    .hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            }
        } else {
            Captured::Complete(self.kept)
        }
    }
}

/// Buffered reader over one direction of a connection. Bytes past the current message stay
/// buffered for the next one, so pipelined requests keep their boundaries.
pub struct Reader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(inner: R) -> Self {
        Reader {
            inner,
            buf: Vec::with_capacity(READ_CHUNK),
            pos: 0,
        }
    }

    /// Construct a reader from an existing stream plus any bytes already read from it.
    /// The pending bytes are yielded before any further reads from `inner`.
    pub fn from_parts(inner: R, pending: Vec<u8>) -> Self {
        Reader {
            inner,
            buf: pending,
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    /// Read more bytes; returns 0 at end of stream.
    async fn fill(&mut self) -> Result<usize, FrameError> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let old = self.buf.len();
        self.buf.resize(old + READ_CHUNK, 0);
        let result = tokio::time::timeout(IO_TIMEOUT, self.inner.read(&mut self.buf[old..])).await;
        let n = match result {
            Err(_) => Err(FrameError::Timeout),
            Ok(Err(e)) => Err(FrameError::Io(e)),
            Ok(Ok(n)) => Ok(n),
        };
        self.buf.truncate(old + *n.as_ref().unwrap_or(&0));
        n
    }

    /// The next message head, through its blank line. `None` when the peer closes cleanly
    /// before sending anything. Empty lines before a head are skipped (RFC 9112 §2.2).
    pub async fn read_head(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        loop {
            while self.available().starts_with(b"\r\n") {
                self.consume(2);
            }
            let avail = self.available();
            let crlf_end = avail.windows(4).position(|w| w == b"\r\n\r\n");
            // A blank line made of bare LFs: framing a lenient parser might read differently.
            let bare_lf = avail.windows(2).position(|w| w == b"\n\n");
            if bare_lf.is_some_and(|b| crlf_end.is_none_or(|c| b < c)) {
                return Err(FrameError::Malformed("bare LF line endings in the head"));
            }
            if crlf_end.unwrap_or(avail.len()) > MAX_HEAD {
                return Err(FrameError::HeadTooLarge);
            }
            if let Some(p) = crlf_end {
                let head = avail[..p + 4].to_vec();
                self.consume(p + 4);
                return Ok(Some(head));
            }
            if self.fill().await? == 0 {
                return if self.available().is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::Closed)
                };
            }
        }
    }

    /// One CRLF-terminated line, CRLF included.
    async fn read_line(&mut self, limit: usize) -> Result<Vec<u8>, FrameError> {
        loop {
            let avail = self.available();
            if let Some(p) = avail.windows(2).position(|w| w == b"\r\n") {
                let line = avail[..p + 2].to_vec();
                self.consume(p + 2);
                return Ok(line);
            }
            if avail.len() > limit {
                return Err(FrameError::Malformed("chunk line too long"));
            }
            if self.fill().await? == 0 {
                return Err(FrameError::Closed);
            }
        }
    }

    /// Forward exactly `n` bytes, feeding them to `capture` as body data.
    async fn copy_exact<W: AsyncWrite + Unpin>(
        &mut self,
        mut n: u64,
        out: &mut W,
        capture: &mut Capture,
    ) -> Result<(), CopyError> {
        while n > 0 {
            if self.available().is_empty() && self.fill().await.map_err(CopyError::Read)? == 0 {
                return Err(CopyError::Read(FrameError::Closed));
            }
            let take = self
                .available()
                .len()
                .min(n.min(usize::MAX as u64) as usize);
            let data = &self.buf[self.pos..self.pos + take];
            write_all(out, data).await?;
            capture.feed(data);
            self.consume(take);
            n -= take as u64;
        }
        Ok(())
    }

    /// Forward a chunked body byte for byte (sizes, extensions and trailers included),
    /// feeding only the chunk data to `capture`.
    async fn copy_chunked<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        capture: &mut Capture,
    ) -> Result<(), CopyError> {
        loop {
            let line = self
                .read_line(MAX_CHUNK_LINE)
                .await
                .map_err(CopyError::Read)?;
            let size = parse_chunk_size(&line[..line.len() - 2]).map_err(CopyError::Read)?;
            write_all(out, &line).await?;
            if size == 0 {
                // Trailer fields, then the final empty line.
                let mut trailer_bytes = 0;
                loop {
                    let line = self.read_line(MAX_HEAD).await.map_err(CopyError::Read)?;
                    trailer_bytes += line.len();
                    if trailer_bytes > MAX_HEAD {
                        return Err(CopyError::Read(FrameError::HeadTooLarge));
                    }
                    write_all(out, &line).await?;
                    if line == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            self.copy_exact(size, out, capture).await?;
            let end = self.read_line(2).await.map_err(CopyError::Read)?;
            if end != b"\r\n" {
                return Err(CopyError::Read(FrameError::Malformed(
                    "chunk data not followed by CRLF",
                )));
            }
            write_all(out, &end).await?;
        }
    }

    /// Forward everything until the peer closes.
    async fn copy_to_end<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        capture: &mut Capture,
    ) -> Result<(), CopyError> {
        loop {
            if self.available().is_empty() && self.fill().await.map_err(CopyError::Read)? == 0 {
                return Ok(());
            }
            let take = self.available().len();
            let data = &self.buf[self.pos..self.pos + take];
            write_all(out, data).await?;
            capture.feed(data);
            self.consume(take);
        }
    }

    /// Forward one body with the given framing. Returns the number of bytes forwarded.
    pub async fn copy_body<W: AsyncWrite + Unpin>(
        &mut self,
        framing: BodyFraming,
        out: &mut W,
        capture: &mut Capture,
    ) -> Result<u64, CopyError> {
        let mut counted = Counting(out, 0);
        match framing {
            BodyFraming::None => {}
            BodyFraming::Length(n) => self.copy_exact(n, &mut counted, capture).await?,
            BodyFraming::Chunked => self.copy_chunked(&mut counted, capture).await?,
            BodyFraming::UntilClose => self.copy_to_end(&mut counted, capture).await?,
        }
        Ok(counted.1)
    }

    /// Read and discard input until the peer closes, `max` bytes pass or `within` elapses.
    /// Closing a socket with unread input makes Windows send a reset, which can destroy a
    /// reply the peer has not read yet; draining first lets the reply arrive.
    pub async fn discard(&mut self, max: usize, within: Duration) {
        let mut seen = 0;
        let _ = tokio::time::timeout(within, async {
            self.buf.clear();
            self.pos = 0;
            let mut tmp = vec![0u8; READ_CHUNK];
            while seen < max {
                match self.inner.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen += n,
                }
            }
        })
        .await;
    }

    /// Hand back the stream and any bytes read past the last message (for a protocol switch).
    pub fn into_parts(self) -> (R, Vec<u8>) {
        let rest = self.buf[self.pos..].to_vec();
        (self.inner, rest)
    }
}

/// Counts bytes written through it.
struct Counting<'a, W>(&'a mut W, u64);

async fn write_all<W: AsyncWrite + Unpin>(out: &mut W, data: &[u8]) -> Result<(), CopyError> {
    match tokio::time::timeout(IO_TIMEOUT, out.write_all(data)).await {
        Err(_) => Err(CopyError::Write(std::io::ErrorKind::TimedOut.into())),
        Ok(r) => r.map_err(CopyError::Write),
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Counting<'_, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let r = std::pin::Pin::new(&mut *this.0).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            this.1 += *n as u64;
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// `1*HEXDIG [ BWS ";" chunk-ext ]`, at most 16 hex digits.
fn parse_chunk_size(line: &[u8]) -> Result<u64, FrameError> {
    let size_part = match line.iter().position(|&b| b == b';') {
        Some(p) => &line[..p],
        None => line,
    };
    let digits = size_part
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(&size_part[..0], |end| &size_part[..=end]);
    if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(FrameError::Malformed("invalid chunk size"));
    }
    let text =
        std::str::from_utf8(digits).map_err(|_| FrameError::Malformed("invalid chunk size"))?;
    u64::from_str_radix(text, 16).map_err(|_| FrameError::Malformed("invalid chunk size"))
}

/// Header fields that describe one connection only and are never forwarded (RFC 9110 §7.6.1),
/// plus the proxy's own credentials and challenges, which belong to the client-proxy hop.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// Fields a Connection header may not remove: they frame or route the message, so dropping
/// them on a client's say-so would change where the message ends or where it goes.
const PROTECTED: &[&str] = &["content-length", "transfer-encoding", "host"];

/// Lowercased option names from every Connection header in a validated head.
fn connection_options(lines: &[(&str, &[u8])]) -> Vec<String> {
    lines
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| {
            String::from_utf8_lossy(value)
                .split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// Split a validated head (CRLF lines, no folding) into its start line and header lines.
fn head_lines(head: &[u8]) -> (&[u8], Vec<(&str, &[u8])>) {
    let body = &head[..head.len() - 4]; // without the final blank line
    let mut lines = body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let start = lines.next().unwrap_or_default();
    let fields = lines
        .filter_map(|l| {
            let colon = l.iter().position(|&b| b == b':')?;
            Some((std::str::from_utf8(&l[..colon]).ok()?, &l[colon + 1..]))
        })
        .collect();
    (start, fields)
}

fn is_dropped(name: &str, options: &[String], keep_upgrade: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if keep_upgrade && lower == "upgrade" {
        return false;
    }
    HOP_BY_HOP.contains(&lower.as_str())
        || (options.contains(&lower) && !PROTECTED.contains(&lower.as_str()))
}

/// The origin-form target (RFC 9112 §3.2.1) of an absolute `http://` or `https://` target:
/// path and query, `/` when the path is empty (`*` for OPTIONS), fragment removed.
pub fn origin_form(method: &str, absolute: &str) -> String {
    let rest = if absolute.len() >= 7 && absolute[..7].eq_ignore_ascii_case("http://") {
        &absolute[7..]
    } else if absolute.len() >= 8 && absolute[..8].eq_ignore_ascii_case("https://") {
        &absolute[8..]
    } else {
        absolute
    };
    let tail = &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..];
    let tail = tail.split('#').next().unwrap_or("");
    match tail {
        "" if method.eq_ignore_ascii_case("OPTIONS") => "*".to_string(),
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    }
}

/// The request head as sent to the origin server (RFC 9110 §7.6, RFC 9112 §3.2):
/// - the target in origin form, and Host set from an absolute target's authority
///   (`host_from_target`, userinfo removed), replacing whatever Host the client sent;
/// - hop-by-hop fields, fields named in Connection, and Proxy-Authorization removed;
///   Content-Length, Transfer-Encoding and Host are never removed, so framing is unchanged;
/// - `Connection: Upgrade` with the Upgrade field kept for a valid upgrade request, otherwise
///   `Connection: close`, because each upstream connection carries one exchange.
///
/// Every other field keeps its position, name and value bytes.
pub fn origin_request_head(
    head: &[u8],
    method: &str,
    target: &str,
    host_from_target: Option<&str>,
    upgrade: bool,
) -> Vec<u8> {
    let (start, fields) = head_lines(head);
    let options = connection_options(&fields);
    let version = start.rsplit(|&b| b == b' ').next().unwrap_or(b"HTTP/1.1");
    let mut out = format!("{method} {target} ").into_bytes();
    out.extend_from_slice(version);
    out.extend_from_slice(b"\r\n");
    let mut host_written = false;
    if let Some(host) = host_from_target {
        if !fields.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
            out.extend(format!("Host: {host}\r\n").as_bytes());
            host_written = true;
        }
    }
    for (name, value) in &fields {
        if name.eq_ignore_ascii_case("host") {
            if let Some(host) = host_from_target {
                if !host_written {
                    out.extend(format!("{name}: {host}\r\n").as_bytes());
                    host_written = true;
                }
                continue;
            }
        }
        if is_dropped(name, &options, upgrade) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.push(b':');
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(if upgrade {
        b"Connection: Upgrade\r\n\r\n".as_slice()
    } else {
        b"Connection: close\r\n\r\n".as_slice()
    });
    out
}

/// The response head as sent to the client: the status line and end-to-end fields unchanged,
/// hop-by-hop fields from the server's connection removed, and `Connection: close` added when
/// the proxy will close the client connection after this response. A 101 head is passed
/// through unchanged, since its Upgrade and Connection fields complete the switch.
pub fn client_response_head(head: &[u8], status: u16, close: bool) -> Vec<u8> {
    if status == 101 {
        return head.to_vec();
    }
    let (start, fields) = head_lines(head);
    let options = connection_options(&fields);
    let mut out = start.to_vec();
    out.extend_from_slice(b"\r\n");
    for (name, value) in &fields {
        if is_dropped(name, &options, false) {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.push(b':');
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Split `host[:port]` or `[v6]:port` (an authority without userinfo) into host and port.
pub fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        match after {
            "" => (h, None),
            p => (h, Some(p.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None | Some("") => default_port,
        Some(p) => p.parse().ok()?,
    };
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(list: &[(&'static str, &'static str)]) -> Vec<httparse::Header<'static>> {
        list.iter()
            .map(|(n, v)| httparse::Header {
                name: n,
                value: v.as_bytes(),
            })
            .collect()
    }

    #[test]
    fn framing_headers_are_strict() {
        let ok = inspect_headers(&hdrs(&[("Content-Length", "5"), ("content-length", "5")]));
        assert_eq!(ok.unwrap().content_length, Some(5));
        for bad in [
            vec![("Content-Length", "5"), ("Content-Length", "6")],
            vec![("Content-Length", "5, 6")],
            vec![("Content-Length", "-1")],
            vec![("Content-Length", "")],
            vec![("Content-Length", "0x10")],
            vec![("Transfer-Encoding", "chunked"), ("Content-Length", "5")],
            vec![("Transfer-Encoding", "chunked, gzip")],
            vec![("Transfer-Encoding", "chunked, chunked")],
            vec![("Transfer-Encoding", "")],
        ] {
            assert!(inspect_headers(&hdrs(&bad)).is_err(), "{bad:?}");
        }
        let te = inspect_headers(&hdrs(&[("Transfer-Encoding", "gzip, chunked")])).unwrap();
        assert_eq!(te.transfer_encoding, Some(true));
        let te = inspect_headers(&hdrs(&[("Transfer-Encoding", "gzip")])).unwrap();
        assert_eq!(te.transfer_encoding, Some(false));
    }

    #[test]
    fn origin_form_targets() {
        assert_eq!(origin_form("GET", "http://a.test"), "/");
        assert_eq!(
            origin_form("GET", "http://a.test:81/p/q?x=1#frag"),
            "/p/q?x=1"
        );
        assert_eq!(origin_form("GET", "http://a.test?x=1"), "/?x=1");
        assert_eq!(origin_form("OPTIONS", "http://a.test"), "*");
        assert_eq!(origin_form("OPTIONS", "http://a.test/"), "/");
    }

    #[test]
    fn request_head_for_origin() {
        let head = b"POST http://u:p@a.test:81/x?y=1 HTTP/1.1\r\nHost: spoofed.test\r\nProxy-Authorization: Basic c2VjcmV0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Hop, Content-Length\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\nX-Hop: 1\r\nUpgrade: websocket\r\nX-Keep:  spaced value \r\nContent-Length: 3\r\n\r\n";
        let out = origin_request_head(head, "POST", "/x?y=1", Some("a.test:81"), false);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /x?y=1 HTTP/1.1\r\nHost: a.test:81\r\nX-Keep:  spaced value \r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
        );
        let up = b"GET http://a.test/ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n";
        let out = origin_request_head(up, "GET", "/ws", Some("a.test"), true);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\nConnection: Upgrade\r\n\r\n"
        );
        // No Host at all: one is added from the target.
        let out = origin_request_head(
            b"GET http://a.test/ HTTP/1.0\r\n\r\n",
            "GET",
            "/",
            Some("a.test"),
            false,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET / HTTP/1.0\r\nHost: a.test\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn response_head_for_client() {
        let head = b"HTTP/1.1 200 OK\r\nConnection: close, X-Srv-Hop\r\nX-Srv-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Connection: close\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=b\r\n\r\n";
        assert_eq!(
            String::from_utf8(client_response_head(head, 200, false)).unwrap(),
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=b\r\n\r\n"
        );
        assert!(String::from_utf8(client_response_head(head, 200, true))
            .unwrap()
            .ends_with("Set-Cookie: a=b\r\nConnection: close\r\n\r\n"));
        let switch = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(client_response_head(switch, 101, false), switch);
    }

    #[test]
    fn chunk_sizes() {
        assert_eq!(parse_chunk_size(b"1a").unwrap(), 26);
        assert_eq!(parse_chunk_size(b"1A ;ext=1").unwrap(), 26);
        for bad in [&b""[..], b"zz", b"-1", b"12345678901234567", b" 1"] {
            assert!(parse_chunk_size(bad).is_err());
        }
    }

    #[test]
    fn authorities() {
        assert_eq!(split_authority("a.test", 80), Some(("a.test".into(), 80)));
        assert_eq!(
            split_authority("a.test:81", 80),
            Some(("a.test".into(), 81))
        );
        assert_eq!(
            split_authority("u:p@a.test:81", 80),
            Some(("a.test".into(), 81))
        );
        assert_eq!(
            split_authority("[::1]:9090", 80),
            Some(("::1".into(), 9090))
        );
        assert_eq!(split_authority("[::1]", 80), Some(("::1".into(), 80)));
        assert_eq!(split_authority("a.test:x", 80), None);
        assert_eq!(split_authority("", 80), None);
    }
}
