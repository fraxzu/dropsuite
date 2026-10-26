//! HTTP/2 over an already-negotiated TLS stream, for the upstream leg only.
//!
//! Browsers reach a destination over h2 and bot protection notices when a client claims h2 but
//! speaks something else. Offering h2 in ALPN and then actually speaking it removes that signal.
//! The leg toward the browser stays HTTP/1.1; only the destination leg changes here.
//!
//! A prepared HTTP/1.1 head is re-parsed into an h2 request: connection-only fields are dropped
//! and the authority comes from the URI. Callers may stream the request body ([`H2Call::send_chunk`])
//! and the response body ([`H2Call::pump_body`]) rather than buffering either side.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::http1::{Capture, IO_TIMEOUT};

/// Fields h2 states per stream rather than sending as ordinary headers.
const H2_FORBIDDEN: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// A response head read over h2.
pub struct H2Head {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

/// A request in flight: the send half, the response future and the connection driver.
pub struct H2Call {
    sender: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    body: Option<h2::RecvStream>,
    driver: tokio::task::JoinHandle<()>,
}

impl H2Call {
    /// Send one request head. `end_stream` marks a body-less request.
    pub async fn send_chunk(&mut self, chunk: Bytes, last: bool) -> Result<(), String> {
        self.sender
            .send_data(chunk, last)
            .map_err(|e| format!("h2 body send failed: {e}"))
    }

    /// Wait for the response head. The body stays available to [`pump_body`](Self::pump_body).
    pub async fn response(&mut self, deadline: Duration) -> Result<H2Head, String> {
        let future = self.response.take().ok_or("response already taken")?;
        let response = match tokio::time::timeout(deadline, future).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(format!("h2 response failed: {e}")),
            Err(_) => return Err("destination sent no response".to_string()),
        };
        let status = response.status().as_u16();
        let reason = response
            .status()
            .canonical_reason()
            .unwrap_or("")
            .to_string();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).to_string(),
                )
            })
            .collect();
        self.body = Some(response.into_body());
        Ok(H2Head {
            status,
            reason,
            headers,
        })
    }

    /// Stream the response body into `capture` and, when given, `sink`. Returns the bytes read.
    pub async fn pump_body<W: AsyncWrite + Unpin>(
        &mut self,
        capture: &mut Capture,
        mut sink: Option<&mut W>,
    ) -> Result<u64, String> {
        let Some(mut body) = self.body.take() else {
            return Ok(0);
        };
        let mut total = 0u64;
        loop {
            let next = match tokio::time::timeout(IO_TIMEOUT, body.data()).await {
                Ok(next) => next,
                Err(_) => return Err("response body stalled".to_string()),
            };
            match next {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    capture.feed(&chunk);
                    if let Some(out) = sink.as_deref_mut() {
                        out.write_all(&chunk)
                            .await
                            .map_err(|e| format!("writing the response failed: {e}"))?;
                    }
                    let _ = body.flow_control().release_capacity(len);
                    total += len as u64;
                }
                Some(Err(e)) => return Err(format!("response body: {e}")),
                None => break,
            }
        }
        Ok(total)
    }

    /// Hand the send stream and the pending response to the caller, for adapters that speak
    /// AsyncWrite/AsyncRead.
    pub fn split(
        self,
    ) -> (
        h2::SendStream<Bytes>,
        h2::client::ResponseFuture,
        tokio::task::JoinHandle<()>,
    ) {
        (
            self.sender,
            self.response.expect("response future is taken once"),
            self.driver,
        )
    }

    /// Stop the connection driver.
    pub fn finish(self) {
        self.driver.abort();
    }
}

/// Start a request. `end_stream` marks a body-less request; otherwise feed the body with
/// [`H2Call::send_chunk`] before asking for the response.
pub async fn begin<S>(io: S, head: &[u8], end_stream: bool) -> Result<H2Call, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (host, target, method, fields) = parse_head(head)?;

    let (mut sender, connection) = h2::client::handshake(io)
        .await
        .map_err(|e| format!("h2 handshake failed: {e}"))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let path_and_query = target
        .strip_prefix("https://")
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or(&target)
        .to_string();

    // h2 derives the pseudo headers from the URI: scheme and authority become `:scheme` and
    // `:authority`, and the path becomes `:path`.
    let authority = format!("https://{host}{path_and_query}");
    let mut builder = Request::builder()
        .method(method.as_str())
        .uri(authority.as_str());
    for (name, value) in fields {
        let lower = name.to_ascii_lowercase();
        if H2_FORBIDDEN.contains(&lower.as_str()) || lower.starts_with(':') {
            continue;
        }
        if lower == "te" && !value.eq_ignore_ascii_case("trailers") {
            continue;
        }
        let Ok(value) = HeaderValue::from_str(&value) else {
            continue;
        };
        builder = builder.header(lower, value);
    }
    let request = builder.body(()).map_err(|e| format!("h2 request: {e}"))?;

    let (response, stream) = match sender.send_request(request, end_stream) {
        Ok(pair) => pair,
        Err(e) => {
            driver.abort();
            return Err(format!("h2 send failed: {e}"));
        }
    };

    Ok(H2Call {
        sender: stream,
        response: Some(response),
        body: None,
        driver,
    })
}

/// Send a whole body at once, then read and capture the response. Used where the body is already
/// in memory (Replay).
pub async fn exchange<S>(
    io: S,
    head: &[u8],
    body: &[u8],
    capture: &mut Capture,
    head_deadline: Duration,
) -> Result<H2Head, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut call = begin(io, head, body.is_empty()).await?;
    if !body.is_empty() {
        let mut offset = 0;
        while offset < body.len() {
            let end = (offset + 16_384).min(body.len());
            let last = end == body.len();
            if let Err(e) = call
                .send_chunk(Bytes::copy_from_slice(&body[offset..end]), last)
                .await
            {
                call.finish();
                return Err(e);
            }
            offset = end;
        }
    }
    let head = match call.response(head_deadline).await {
        Ok(h) => h,
        Err(e) => {
            call.finish();
            return Err(e);
        }
    };
    if let Err(e) = call.pump_body(capture, None::<&mut tokio::io::Sink>).await {
        call.finish();
        return Err(e);
    }
    call.finish();
    Ok(head)
}

type ParsedHead = (String, String, Method, Vec<(String, String)>);

/// Split a prepared request head into authority, target, method and fields.
fn parse_head(head: &[u8]) -> Result<ParsedHead, String> {
    let mut fields = [httparse::EMPTY_HEADER; crate::http1::MAX_HEADERS];
    let mut request = httparse::Request::new(&mut fields);
    match request.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("request head could not be parsed for h2".into()),
    }
    let method = request.method.ok_or("missing method")?;
    let target = request.path.ok_or("missing target")?.to_string();
    let method = Method::from_bytes(method.as_bytes()).map_err(|e| format!("bad method: {e}"))?;

    let mut host = String::new();
    let mut out = Vec::new();
    for field in request.headers {
        let value = String::from_utf8_lossy(field.value).to_string();
        if field.name.eq_ignore_ascii_case("host") {
            host = value;
            continue;
        }
        out.push((field.name.to_string(), value));
    }
    if host.is_empty() {
        return Err("missing Host for h2 authority".into());
    }
    Ok((host, target, method, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_is_split_into_authority_target_and_fields() {
        let head = b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        let (host, target, method, fields) = parse_head(head).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(target, "/a?b=1");
        assert_eq!(method, Method::GET);
        assert_eq!(
            fields,
            vec![("Accept".to_string(), "text/html".to_string())]
        );
    }

    #[test]
    fn missing_host_is_rejected() {
        assert!(parse_head(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n").is_err());
    }
}
