use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tracing::{error, info, warn};

use crate::allowlist::{normalize_host, InterceptAllowlist};
use crate::ca::{CaError, CaStatus};
use crate::http1::{self, BodyFraming, Capture, Captured, CopyError, FrameError, HeadInfo, Reader};
use crate::http2;
use crate::https::{HttpsInterceptConfig, HttpsInterception, TlsError};
use crate::interception::{HoldError, InterceptAction, InterceptManager, MAX_INTERCEPT_BODY_SIZE};
use crate::match_replace::MatchReplaceEngine;
use crate::models::{ProxyStatus, TransactionRecord};
use crate::sanitize::{omission_record, sanitize_record};
use crate::scope::ScopeEngine;
use crate::storage::StorageManager;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Test seam: answers a hostname lookup before the system resolver is asked. `None` falls
/// through to DNS. Lets tests make a name resolve to a restricted address without real DNS.
pub type ResolverOverride = Arc<dyn Fn(&str) -> Option<Vec<IpAddr>> + Send + Sync>;

/// Test seam: consulted after the destination policy has passed and before any socket is
/// opened; `false` refuses the connect. It can only deny, never permit what the policy refused.
pub type ConnectGate = Arc<dyn Fn(&[SocketAddr]) -> bool + Send + Sync>;

pub struct ProxyEngine {
    bind_ip: String,
    port: u16,
    is_running: Arc<AtomicBool>,
    shutdown_tx: Option<watch::Sender<bool>>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
    storage: StorageManager,
    tx_events: broadcast::Sender<TransactionRecord>,
    total_captured: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    https: Option<Arc<HttpsInterception>>,
    outbound_connects: Arc<AtomicUsize>,
    resolver: Option<ResolverOverride>,
    connect_gate: Option<ConnectGate>,
    intercept: Arc<InterceptManager>,
    scope: Arc<ScopeEngine>,
    match_replace: Arc<MatchReplaceEngine>,
}

#[derive(Clone)]
struct Shared {
    listen_addr: SocketAddr,
    storage: StorageManager,
    tx_events: broadcast::Sender<TransactionRecord>,
    total_captured: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    https: Option<Arc<HttpsInterception>>,
    outbound_connects: Arc<AtomicUsize>,
    resolver: Option<ResolverOverride>,
    connect_gate: Option<ConnectGate>,
    intercept: Arc<InterceptManager>,
    scope: Arc<ScopeEngine>,
    match_replace: Arc<MatchReplaceEngine>,
}

enum Next {
    KeepAlive,
    Close,
    Tunnel(Reader<BoxedRead>, BoxedWrite),
}

struct ResponseHead {
    head: Vec<u8>,
    status: u16,
    headers: Vec<(String, String)>,
    info: HeadInfo,
    framing: BodyFraming,
    client_close: bool,
}

struct ResponseContext<'a> {
    is_head: bool,
    upgrade: bool,
    client_keep_alive: bool,
    request_done: &'a AtomicBool,
    final_sent: &'a AtomicBool,
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

struct SessionPin {
    host: String,
    port: u16,
}

struct ExchangeCtx<'a> {
    scheme: Scheme,
    session: Option<&'a SessionPin>,
}

type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Upstream connection. HTTP/2 keeps the TLS stream so the request can be spoken over h2;
/// HTTP/1.1 is split into the reader/writer pair the relay works with.
enum Upstream {
    H1 {
        reader: Reader<BoxedRead>,
        writer: BoxedWrite,
    },
    H2(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

struct H2Reader {
    response: Option<h2::client::ResponseFuture>,
    state: Option<H2Body>,
    driver: tokio::task::JoinHandle<()>,
}

struct H2Body {
    prefix: Vec<u8>,
    pos: usize,
    stream: h2::RecvStream,
    chunk: Option<bytes::Bytes>,
}

impl H2Reader {
    fn new(response: h2::client::ResponseFuture, driver: tokio::task::JoinHandle<()>) -> Self {
        H2Reader {
            response: Some(response),
            state: None,
            driver,
        }
    }

    /// Turn the h2 response into the HTTP/1.1 head `Reader` expects, then stream its body.
    fn materialize(&mut self, response: http::Response<h2::RecvStream>) -> H2Body {
        let (parts, body) = response.into_parts();
        let mut prefix = Vec::new();
        let reason = parts.status.canonical_reason().unwrap_or("");
        prefix.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", parts.status.as_u16(), reason).as_bytes(),
        );
        for (name, value) in parts.headers.iter() {
            prefix.extend_from_slice(name.as_str().as_bytes());
            prefix.extend_from_slice(b": ");
            prefix.extend_from_slice(value.as_bytes());
            prefix.extend_from_slice(b"\r\n");
        }
        prefix.extend_from_slice(b"\r\n");
        H2Body {
            prefix,
            pos: 0,
            stream: body,
            chunk: None,
        }
    }
}

impl AsyncRead for H2Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.state.is_none() {
            let Some(mut fut) = self.response.take() else {
                return Poll::Ready(Ok(()));
            };
            match Pin::new(&mut fut).poll(cx) {
                Poll::Pending => {
                    self.response = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("h2 response: {e}"))))
                }
                Poll::Ready(Ok(response)) => {
                    let body = self.materialize(response);
                    self.state = Some(body);
                }
            }
        }

        let state = self.state.as_mut().expect("state set above");
        loop {
            if state.pos < state.prefix.len() {
                let take = (state.prefix.len() - state.pos).min(buf.remaining());
                buf.put_slice(&state.prefix[state.pos..state.pos + take]);
                state.pos += take;
                return Poll::Ready(Ok(()));
            }
            if let Some(chunk) = state.chunk.take() {
                if buf.remaining() == 0 {
                    state.chunk = Some(chunk);
                    return Poll::Ready(Ok(()));
                }
                let take = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..take]);
                if take < chunk.len() {
                    state.chunk = Some(chunk.slice(take..));
                }
                return Poll::Ready(Ok(()));
            }
            match state.stream.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.driver.abort();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(format!("h2 body: {e}"))))
                }
                // A chunk arrived: loop so it is copied into `buf` before returning.
                Poll::Ready(Some(Ok(chunk))) => state.chunk = Some(chunk),
            }
        }
    }
}

/// Sends request body bytes as h2 DATA frames. h2 buffers internally, which is enough for request
/// bodies; responses stream the other way through `H2Reader`.
struct H2Writer {
    stream: h2::SendStream<bytes::Bytes>,
    ended: bool,
}

impl H2Writer {
    fn new(stream: h2::SendStream<bytes::Bytes>) -> Self {
        H2Writer {
            stream,
            ended: false,
        }
    }
}

impl AsyncWrite for H2Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let take = buf.len().min(16_384);
        let chunk = bytes::Bytes::copy_from_slice(&buf[..take]);
        match self.stream.send_data(chunk, false) {
            Ok(()) => Poll::Ready(Ok(take)),
            Err(e) => Poll::Ready(Err(std::io::Error::other(format!("h2 write: {e}")))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.ended {
            self.ended = true;
            if let Err(e) = self.stream.send_data(bytes::Bytes::new(), true) {
                return Poll::Ready(Err(std::io::Error::other(format!("h2 end: {e}"))));
            }
        }
        Poll::Ready(Ok(()))
    }
}

struct PrependStream<S> {
    rest: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let avail = self.rest.len() - self.pos;
        if avail > 0 {
            let take = avail.min(buf.remaining());
            buf.put_slice(&self.rest[self.pos..self.pos + take]);
            self.pos += take;
            if self.pos == self.rest.len() {
                self.rest.clear();
                self.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl ProxyEngine {
    pub fn new(bind_ip: &str, port: u16, storage: StorageManager) -> Self {
        let (tx_events, _) = broadcast::channel(1024);
        let initial_count = storage.count_transactions().unwrap_or(0);
        Self {
            bind_ip: bind_ip.to_string(),
            port,
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
            accept_task: None,
            storage,
            tx_events,
            total_captured: Arc::new(AtomicUsize::new(initial_count)),
            total_bytes: Arc::new(AtomicUsize::new(0)),
            https: None,
            outbound_connects: Arc::new(AtomicUsize::new(0)),
            resolver: None,
            connect_gate: None,
            intercept: Arc::new(InterceptManager::new()),
            scope: Arc::new(ScopeEngine::new()),
            match_replace: Arc::new(MatchReplaceEngine::new()),
        }
    }

    pub fn intercept(&self) -> Arc<InterceptManager> {
        self.intercept.clone()
    }

    pub fn scope(&self) -> Arc<ScopeEngine> {
        self.scope.clone()
    }

    pub fn match_replace(&self) -> Arc<MatchReplaceEngine> {
        self.match_replace.clone()
    }

    /// Test seam: refuse outbound connects the gate rejects, without opening a socket.
    /// Takes effect on the next `start`.
    #[doc(hidden)]
    pub fn set_connect_gate(&mut self, gate: ConnectGate) {
        self.connect_gate = Some(gate);
    }

    /// Test seam: consult `resolver` before DNS. Takes effect on the next `start`.
    #[doc(hidden)]
    pub fn set_resolver_override(&mut self, resolver: ResolverOverride) {
        self.resolver = Some(resolver);
    }

    /// Outbound TCP connections this engine has attempted (upstream, tunnel, or TLS origin).
    /// Counted before the connect call, so a refused destination leaves it unchanged.
    #[doc(hidden)]
    pub fn outbound_connect_attempts(&self) -> usize {
        self.outbound_connects.load(Ordering::SeqCst)
    }

    pub fn set_https_interception(&mut self, config: HttpsInterceptConfig) {
        match HttpsInterception::new(config) {
            Ok(h) => self.https = Some(Arc::new(h)),
            Err(e) => {
                warn!("Could not initialise HTTPS interception: {e}");
                self.https = None;
            }
        }
    }

    pub fn https_status(&self) -> Option<CaStatus> {
        self.https.as_ref().map(|h| h.ca_status())
    }

    /// ClientHello profile used toward destinations (header presets pick the same one).
    pub fn set_tls_profile(&self, profile: crate::tls_profile::TlsProfile) {
        if let Some(h) = &self.https {
            h.set_tls_profile(profile);
        }
    }

    pub fn set_https_allowlist(&self, list: InterceptAllowlist) {
        if let Some(h) = &self.https {
            h.set_allowlist(list);
        }
    }

    pub fn is_minted_leaf(&self, fp: &str) -> bool {
        self.https
            .as_ref()
            .map(|h| h.is_minted_leaf(fp))
            .unwrap_or(false)
    }

    pub fn minted_leaf_host(&self, fp: &str) -> Option<String> {
        self.https.as_ref().and_then(|h| h.minted_leaf_host(fp))
    }

    pub fn leaf_cache(&self) -> Option<std::sync::Arc<std::sync::RwLock<crate::https::LeafCache>>> {
        self.https.as_ref().map(|h| h.leaf_cache())
    }

    pub async fn remove_ca(&self) -> Result<(), crate::ca::CaError> {
        if let Some(h) = &self.https {
            h.remove_ca().await
        } else {
            Ok(())
        }
    }

    pub async fn load_or_generate_ca(&self) -> Result<(), crate::ca::CaError> {
        if let Some(h) = &self.https {
            h.load_or_generate_ca().await.map(|_| ())
        } else {
            Ok(())
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionRecord> {
        self.tx_events.subscribe()
    }

    pub fn status(&self) -> ProxyStatus {
        ProxyStatus {
            is_running: self.is_running.load(Ordering::SeqCst),
            bind_address: self.bind_ip.clone(),
            port: self.port,
            total_captured: self.total_captured.load(Ordering::Relaxed),
            total_bytes_transferred: self.total_bytes.load(Ordering::Relaxed),
        }
    }

    pub fn sanitize_header_value(name: &str, value: &str) -> String {
        crate::sanitize::redact_header_value(name, value)
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Validate that bind_ip is loopback only. Non-loopback binding without authentication
        // creates an open proxy / SSRF exposure and is strictly prohibited in P2.
        let bind_ip: std::net::IpAddr = self
            .bind_ip
            .parse()
            .map_err(|e| format!("Invalid bind IP address '{}': {e}", self.bind_ip))?;
        let canonical_bind = canonical_ip(bind_ip);
        if !canonical_bind.is_loopback() {
            return Err(format!(
                "Non-loopback bind address '{}' is prohibited: DropSuite does not support unauthenticated remote proxy access.",
                self.bind_ip
            )
            .into());
        }

        let addr = format!("{}:{}", self.bind_ip, self.port);
        let listener = TcpListener::bind(&addr).await.map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                if e.kind() == std::io::ErrorKind::AddrInUse
                    || e.kind() == std::io::ErrorKind::PermissionDenied
                {
                    format!(
                        "Port {} on {} is already in use by another program.",
                        self.port, self.bind_ip
                    )
                    .into()
                } else {
                    format!("Could not listen on {addr}: {e}").into()
                }
            },
        )?;
        let listen_addr = listener.local_addr()?;
        self.port = listen_addr.port();
        info!(
            "DropSuite Proxy Listener active on {}:{}",
            self.bind_ip, self.port
        );

        self.is_running.store(true, Ordering::SeqCst);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let is_running_clone = self.is_running.clone();
        let shared = Shared {
            listen_addr,
            storage: self.storage.clone(),
            tx_events: self.tx_events.clone(),
            total_captured: self.total_captured.clone(),
            total_bytes: self.total_bytes.clone(),
            https: self.https.clone(),
            outbound_connects: self.outbound_connects.clone(),
            resolver: self.resolver.clone(),
            connect_gate: self.connect_gate.clone(),
            intercept: self.intercept.clone(),
            scope: self.scope.clone(),
            match_replace: self.match_replace.clone(),
        };

        self.accept_task = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((client_stream, client_addr)) => {
                                let shared = shared.clone();
                                tokio::spawn(async move {
                                    Self::handle_connection(client_stream, client_addr, shared).await;
                                });
                            }
                            Err(e) => {
                                error!("Listener accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Shutting down DropSuite proxy listener.");
                            break;
                        }
                    }
                }
            }
            is_running_clone.store(false, Ordering::SeqCst);
        }));

        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        self.is_running.store(false, Ordering::SeqCst);
        info!("Proxy listener stopped.");
    }

    pub async fn shutdown(&mut self) {
        self.stop();
        if let Some(task) = self.accept_task.take() {
            let _ = task.await;
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_port(&mut self, port: u16) -> Result<(), String> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err("Stop the listener before changing its port.".into());
        }
        self.port = port;
        Ok(())
    }

    async fn handle_connection(client: TcpStream, client_addr: SocketAddr, shared: Shared) {
        let (client_read, mut client_out) = client.into_split();
        let mut client_in: Reader<OwnedReadHalf> = Reader::new(client_read);
        let tunnel = loop {
            let head = match client_in.read_head().await {
                Ok(Some(head)) => head,
                Ok(None) => break None,
                Err(FrameError::HeadTooLarge) => {
                    reply(
                        &mut client_out,
                        "431 Request Header Fields Too Large",
                        "the request head is larger than 64 KB.",
                    )
                    .await;
                    break None;
                }
                Err(e @ FrameError::Malformed(_)) => {
                    reply(&mut client_out, "400 Bad Request", &format!("{e}.")).await;
                    break None;
                }
                Err(_) => break None,
            };

            let (method, target) = parse_start_line(&head);
            if method.eq_ignore_ascii_case("CONNECT") {
                Self::handle_connect(client_in, client_out, &head, shared, client_addr).await;
                return;
            }

            match Self::exchange(
                &head,
                &target,
                &mut client_in,
                &mut client_out,
                &ExchangeCtx {
                    scheme: Scheme::Http,
                    session: None,
                },
                &shared,
            )
            .await
            {
                Next::KeepAlive => continue,
                Next::Close => break None,
                Next::Tunnel(up_in, up_out) => break Some((up_in, up_out)),
            }
        };

        match tunnel {
            Some((up_in, up_out)) => {
                let (client_read, rest) = client_in.into_parts();
                let client_in = Reader::from_parts(Box::new(client_read) as BoxedRead, rest);
                let client_out: BoxedWrite = Box::new(client_out);
                relay_tunnel(client_in, client_out, up_in, up_out).await;
            }
            None => {
                let _ = client_out.shutdown().await;
                client_in.discard(1024 * 1024, Duration::from_secs(2)).await;
            }
        }
        tracing::debug!("Connection from {client_addr} closed");
    }

    async fn handle_connect(
        client_in: Reader<OwnedReadHalf>,
        mut client_out: OwnedWriteHalf,
        head: &[u8],
        shared: Shared,
        _client_addr: SocketAddr,
    ) {
        let authority = match parse_connect_authority(head) {
            Ok(a) => a,
            Err(e) => {
                reply(&mut client_out, "400 Bad Request", &e).await;
                return;
            }
        };

        let Some((target_host, target_port)) = http1::split_authority(&authority, 443) else {
            reply(
                &mut client_out,
                "400 Bad Request",
                "the CONNECT authority is invalid.",
            )
            .await;
            return;
        };

        if target_port == 0 {
            reply(
                &mut client_out,
                "400 Bad Request",
                "the CONNECT authority has an invalid port.",
            )
            .await;
            return;
        }

        if target_port == 25 {
            reply(
                &mut client_out,
                "403 Forbidden",
                "CONNECT to port 25 (SMTP) is prohibited.",
            )
            .await;
            return;
        }

        let targets = match resolve(&target_host, target_port, shared.resolver.as_ref()).await {
            Ok(addrs) => addrs,
            Err(e) => {
                warn!("Could not resolve {target_host}: {e}");
                bad_gateway(&mut client_out).await;
                return;
            }
        };

        let Some(https) = shared.https.as_ref() else {
            reply(
                &mut client_out,
                "501 Not Implemented",
                "HTTPS (CONNECT) is not supported. Configure HTTPS interception or use an http:// target.",
            )
            .await;
            return;
        };

        let allowlisted = https.allows(&target_host, target_port);
        for target_addr in &targets {
            if is_own_listener(*target_addr, shared.listen_addr) {
                warn!("Refused CONNECT to the proxy's own address {authority}: forwarding loop");
                reply(
                    &mut client_out,
                    "508 Loop Detected",
                    "the proxy will not connect to itself.",
                )
                .await;
                return;
            }
            if let Some(reason) = is_restricted_destination(*target_addr) {
                warn!("Refused CONNECT to {authority} ({target_addr}): {reason}");
                reply(&mut client_out, "403 Forbidden", reason).await;
                return;
            }
        }

        if !allowlisted {
            // Blind tunnel for non-allowlisted targets: connect upstream, relay raw bytes.
            if let Err(e) = begin_outbound_connect(&shared, &targets) {
                warn!("{e}");
                bad_gateway(&mut client_out).await;
                return;
            }
            let upstream =
                match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&targets[..])).await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("Could not connect to {target_host}:{target_port}: {e}");
                        bad_gateway(&mut client_out).await;
                        return;
                    }
                    Err(_) => {
                        warn!("Connecting to {target_host}:{target_port} timed out");
                        bad_gateway(&mut client_out).await;
                        return;
                    }
                };

            if let Err(e) = write_timed(
                &mut client_out,
                b"HTTP/1.1 200 Connection Established\r\n\r\n",
            )
            .await
            {
                warn!("Could not send 200 Connection Established: {e}");
                return;
            }

            let (client_read, rest) = client_in.into_parts();
            let client_stream = match client_read.reunite(client_out) {
                Ok(s) => s,
                Err(_) => return,
            };
            let client_stream = PrependStream {
                rest,
                pos: 0,
                inner: client_stream,
            };
            blind_relay(client_stream, upstream).await;
            return;
        }

        // Intercept: generate leaf cert, send 200, accept TLS, serve HTTP session.
        let acceptor = match https.acceptor_for(&target_host).await {
            Ok(a) => a,
            Err(TlsError::Ca(CaError::NotGenerated)) => {
                warn!("Refused CONNECT to allowlisted {authority}: no root CA has been generated");
                reply(
                    &mut client_out,
                    "502 Bad Gateway",
                    "HTTPS interception needs a root CA. Generate one in DropSuite's listener settings.",
                )
                .await;
                return;
            }
            Err(e) => {
                warn!("Could not create TLS acceptor for {target_host}: {e}");
                bad_gateway(&mut client_out).await;
                return;
            }
        };

        if let Err(e) = write_timed(
            &mut client_out,
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        )
        .await
        {
            warn!("Could not send 200 Connection Established: {e}");
            return;
        }

        let (client_read, rest) = client_in.into_parts();
        let client_stream = match client_read.reunite(client_out) {
            Ok(s) => s,
            Err(_) => return,
        };
        let client_stream = PrependStream {
            rest,
            pos: 0,
            inner: client_stream,
        };

        let accept =
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(client_stream)).await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    info!(
                    "TLS handshake for {authority} failed (client may not trust the local CA): {e}"
                );
                    return;
                }
                Err(_) => {
                    warn!("TLS handshake for {authority} timed out");
                    return;
                }
            };

        let alpn = accept.get_ref().1.alpn_protocol();
        if let Some(p) = alpn {
            if p != b"http/1.1" {
                warn!(
                    "TLS session for {authority} negotiated unsupported ALPN: {:?}",
                    String::from_utf8_lossy(p)
                );
                return;
            }
        }

        Self::serve_tls_session(accept, target_host, target_port, shared).await;
    }

    async fn serve_tls_session(
        tls_stream: tokio_rustls::server::TlsStream<PrependStream<TcpStream>>,
        host: String,
        port: u16,
        shared: Shared,
    ) {
        let (tls_read, tls_write) = tokio::io::split(tls_stream);
        let mut client_in: Reader<BoxedRead> = Reader::new(Box::new(tls_read) as BoxedRead);
        let mut client_out: BoxedWrite = Box::new(tls_write);
        let session = SessionPin { host, port };

        let tunnel = loop {
            let head = match client_in.read_head().await {
                Ok(Some(head)) => head,
                Ok(None) => break None,
                Err(FrameError::HeadTooLarge) => {
                    reply(
                        &mut client_out,
                        "431 Request Header Fields Too Large",
                        "the request head is larger than 64 KB.",
                    )
                    .await;
                    break None;
                }
                Err(e @ FrameError::Malformed(_)) => {
                    reply(&mut client_out, "400 Bad Request", &format!("{e}.")).await;
                    break None;
                }
                Err(_) => break None,
            };

            let (_method, target) = parse_start_line(&head);
            if target.as_bytes().starts_with(b"PRI * HTTP/2") {
                reply(
                    &mut client_out,
                    "505 HTTP Version Not Supported",
                    "HTTP/2 is not supported by this proxy.",
                )
                .await;
                break None;
            }

            match Self::exchange(
                &head,
                &target,
                &mut client_in,
                &mut client_out,
                &ExchangeCtx {
                    scheme: Scheme::Https,
                    session: Some(&session),
                },
                &shared,
            )
            .await
            {
                Next::KeepAlive => continue,
                Next::Close => break None,
                Next::Tunnel(up_in, up_out) => break Some((up_in, up_out)),
            }
        };

        if let Some((up_in, up_out)) = tunnel {
            let (client_read, rest) = client_in.into_parts();
            let client_in = Reader::from_parts(client_read, rest);
            relay_tunnel(client_in, client_out, up_in, up_out).await;
        } else {
            let _ = client_out.shutdown().await;
        }
    }

    async fn exchange<R, W>(
        head: &[u8],
        target: &str,
        client_in: &mut Reader<R>,
        client_out: &mut W,
        ctx: &ExchangeCtx<'_>,
        shared: &Shared,
    ) -> Next
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let start_time = Instant::now();
        let mut header_buf = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
        let mut req = httparse::Request::new(&mut header_buf);
        match req.parse(head) {
            Ok(httparse::Status::Complete(n)) if n == head.len() => {}
            Err(httparse::Error::TooManyHeaders) => {
                reply(
                    client_out,
                    "431 Request Header Fields Too Large",
                    "the request has too many header fields.",
                )
                .await;
                return Next::Close;
            }
            _ => {
                reply(
                    client_out,
                    "400 Bad Request",
                    "the request head could not be parsed.",
                )
                .await;
                return Next::Close;
            }
        }
        let method = req.method.unwrap_or_default().to_string();
        let version = req.version.unwrap_or(1);
        let info = match http1::inspect_headers(req.headers) {
            Ok(info) => info,
            Err(e) => {
                reply(client_out, "400 Bad Request", &format!("{e}.")).await;
                return Next::Close;
            }
        };
        let request_headers = header_pairs(req.headers);
        let host_headers: Vec<&str> = request_headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())
            .collect();

        let absolute_http = starts_with_ignore_case(target, "http://");
        let absolute_https = starts_with_ignore_case(target, "https://");

        let (scheme, authority, url_path, target_host, target_port) = match ctx.scheme {
            Scheme::Https => {
                let session = ctx
                    .session
                    .as_ref()
                    .expect("TLS session context required for HTTPS");
                if host_headers.len() != 1 {
                    reply(
                        client_out,
                        "400 Bad Request",
                        "the request must have exactly one Host header.",
                    )
                    .await;
                    return Next::Close;
                }
                let h = host_headers[0];
                let host_only = h.rsplit_once(':').map(|(name, _)| name).unwrap_or(h);
                if normalize_host(host_only).as_deref()
                    != Some(session.host.to_ascii_lowercase().as_str())
                {
                    reply(
                        client_out,
                        "400 Bad Request",
                        "the Host header does not match the CONNECT authority.",
                    )
                    .await;
                    return Next::Close;
                }

                // Prevent history spoofing / request confusion: if an absolute URI is sent inside the TLS tunnel,
                // its authority must match the session authority.
                if absolute_http || absolute_https {
                    let rest = if absolute_http {
                        &target[7..]
                    } else {
                        &target[8..]
                    };
                    let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
                    let auth = auth.rsplit_once('@').map_or(auth, |(_, a)| a);
                    if let Some((target_h, target_p)) = http1::split_authority(auth, 443) {
                        if normalize_host(&target_h).as_deref()
                            != Some(session.host.to_ascii_lowercase().as_str())
                            || target_p != session.port
                        {
                            reply(
                                client_out,
                                "400 Bad Request",
                                "the request target authority does not match the TLS session host.",
                            )
                            .await;
                            return Next::Close;
                        }
                    } else {
                        reply(
                            client_out,
                            "400 Bad Request",
                            "invalid absolute target in TLS session.",
                        )
                        .await;
                        return Next::Close;
                    }
                } else if !target.starts_with('/')
                    && !(method.eq_ignore_ascii_case("OPTIONS") && target == "*")
                {
                    reply(
                        client_out,
                        "400 Bad Request",
                        "request target must be in origin form within a TLS session.",
                    )
                    .await;
                    return Next::Close;
                }

                (
                    Scheme::Https,
                    format!("{}:{}", session.host, session.port),
                    target.to_string(),
                    session.host.clone(),
                    session.port,
                )
            }
            Scheme::Http => {
                if absolute_https {
                    let rest = &target[8..];
                    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
                    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
                    let Some((host, port)) = http1::split_authority(authority, 443) else {
                        reply(
                            client_out,
                            "400 Bad Request",
                            "the request has an invalid HTTPS target.",
                        )
                        .await;
                        return Next::Close;
                    };
                    if let Some(https) = &shared.https {
                        if !https.allows(&host, port) {
                            reply(
                                client_out,
                                "501 Not Implemented",
                                "the HTTPS target is not on the interception allowlist.",
                            )
                            .await;
                            return Next::Close;
                        }
                    } else {
                        reply(
                            client_out,
                            "501 Not Implemented",
                            "HTTPS is not supported. Configure HTTPS interception.",
                        )
                        .await;
                        return Next::Close;
                    }
                    (
                        Scheme::Https,
                        authority.to_string(),
                        target.to_string(),
                        host,
                        port,
                    )
                } else {
                    let absolute = absolute_http;
                    let authority = if absolute {
                        let rest = &target[7..];
                        let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
                        authority
                            .rsplit_once('@')
                            .map_or(authority, |(_, a)| a)
                            .to_string()
                    } else if target.starts_with('/') && host_headers.len() == 1 {
                        host_headers[0].to_string()
                    } else {
                        String::new()
                    };
                    let Some((host, port)) =
                        http1::split_authority(&authority, 80).filter(|_| host_headers.len() <= 1)
                    else {
                        reply(
                            client_out,
                            "400 Bad Request",
                            "the request has no usable target host (absolute URL or one Host header).",
                        )
                        .await;
                        return Next::Close;
                    };
                    (Scheme::Http, authority, target.to_string(), host, port)
                }
            }
        };

        let request_framing = match (info.transfer_encoding, info.content_length) {
            (Some(true), _) if version == 1 => BodyFraming::Chunked,
            (Some(_), _) => {
                reply(
                    client_out,
                    "400 Bad Request",
                    "Transfer-Encoding must end with chunked on an HTTP/1.1 request.",
                )
                .await;
                return Next::Close;
            }
            (None, Some(n)) if n > 0 => BodyFraming::Length(n),
            (None, _) => BodyFraming::None,
        };
        let client_keep_alive = version == 1 && !info.connection_close;
        let upgrade = version == 1
            && info.upgrade
            && host_headers.len() <= 1
            && request_headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("upgrade"));

        let upstream_head = match scheme {
            Scheme::Http => {
                if absolute_http {
                    http1::origin_request_head(
                        head,
                        &method,
                        &http1::origin_form(&method, &url_path),
                        Some(&authority),
                        upgrade,
                    )
                } else {
                    http1::origin_request_head(head, &method, &url_path, None, upgrade)
                }
            }
            Scheme::Https => http1::origin_request_head(
                head,
                &method,
                &http1::origin_form(&method, &url_path),
                Some(&authority),
                upgrade,
            ),
        };

        let url = if absolute_http || absolute_https {
            target.to_string()
        } else {
            match scheme {
                Scheme::Http if target_host.contains(':') => {
                    format!("http://[{target_host}]:{target_port}{url_path}")
                }
                Scheme::Http => format!("http://{target_host}:{target_port}{url_path}"),
                Scheme::Https if target_host.contains(':') => {
                    format!("https://[{target_host}]:{target_port}{url_path}")
                }
                Scheme::Https => format!("https://{target_host}:{target_port}{url_path}"),
            }
        };

        if shared.scope.should_drop_out_of_scope(&url) {
            info!(url = %url, "Dropping out-of-scope request by policy");
            reply(
                client_out,
                "403 Forbidden",
                "Request dropped: target is out of scope.",
            )
            .await;
            return Next::Close;
        }

        let upstream_head = shared.match_replace.apply_request_head(&upstream_head);

        let (
            upstream_head,
            intercepted_body,
            method,
            url,
            authority,
            url_path,
            target_host,
            target_port,
            request_headers,
        ) = if shared.intercept.is_intercept_requests_enabled() {
            let mut body_buf = Vec::new();
            let mut cap = Capture::new();
            if request_framing != BodyFraming::None {
                match client_in
                    .copy_body(request_framing, &mut body_buf, &mut cap)
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Client body read error during intercept: {e}");
                        reply(
                            client_out,
                            "400 Bad Request",
                            "could not read request body.",
                        )
                        .await;
                        return Next::Close;
                    }
                }
            }

            let hold_res = shared
                .intercept
                .hold_request(
                    method.clone(),
                    url.clone(),
                    target_host.clone(),
                    url_path.clone(),
                    request_headers.clone(),
                    head.to_vec(),
                    body_buf.clone(),
                )
                .await;

            let (held_id, rx) = match hold_res {
                Ok(pair) => pair,
                Err(HoldError::QueueFull) => {
                    reply(
                        client_out,
                        "503 Service Unavailable",
                        "intercept queue capacity reached.",
                    )
                    .await;
                    return Next::Close;
                }
                Err(HoldError::BodyTooLarge(sz)) => {
                    reply(client_out, "413 Payload Too Large", &format!("request body too large for interactive interception ({sz} bytes, limit {MAX_INTERCEPT_BODY_SIZE} bytes).")).await;
                    return Next::Close;
                }
                Err(_) => (0, tokio::sync::oneshot::channel().1),
            };

            let decision = if held_id > 0 {
                tokio::select! {
                    d = rx => match d {
                        Ok(act) => act,
                        Err(_) => InterceptAction::Drop,
                    },
                    _ = tokio::time::sleep(shared.intercept.timeout()) => {
                        shared.intercept.remove_held(held_id).await;
                        reply(client_out, "504 Gateway Timeout", "intercepted request timed out waiting for decision.").await;
                        return Next::Close;
                    }
                }
            } else {
                InterceptAction::Forward {
                    modified_wire: None,
                }
            };

            match decision {
                InterceptAction::Drop => {
                    return Next::Close;
                }
                InterceptAction::Forward {
                    modified_wire: None,
                } => (
                    upstream_head,
                    Some((body_buf, cap)),
                    method,
                    url,
                    authority,
                    url_path,
                    target_host,
                    target_port,
                    request_headers,
                ),
                InterceptAction::Forward {
                    modified_wire: Some(wire),
                } => match parse_edited_request(&wire, scheme, ctx.session) {
                    Ok(edited) => {
                        let mut new_cap = Capture::new();
                        if !edited.body.is_empty() {
                            new_cap.feed(&edited.body);
                        }
                        (
                            edited.upstream_head,
                            Some((edited.body, new_cap)),
                            edited.method,
                            edited.url,
                            edited.authority,
                            edited.url_path,
                            edited.target_host,
                            edited.target_port,
                            edited.headers,
                        )
                    }
                    Err(e) => {
                        warn!("Invalid edited request: {e}");
                        reply(
                            client_out,
                            "400 Bad Request",
                            &format!("edited request error: {e}"),
                        )
                        .await;
                        return Next::Close;
                    }
                },
            }
        } else {
            (
                upstream_head,
                None,
                method,
                url,
                authority,
                url_path,
                target_host,
                target_port,
                request_headers,
            )
        };

        // Re-validate scope against the (possibly edited) target. Interception can rewrite the
        // request line / Host to a new host or path, so the initial check above is not enough: an
        // in-scope request could be edited to escape scope. With drop-out-of-scope enabled this must
        // be refused here, before any DNS resolution or upstream connection.
        if shared.scope.should_drop_out_of_scope(&url) {
            info!(url = %url, "Dropping out-of-scope request after edit by policy");
            reply(
                client_out,
                "403 Forbidden",
                "Request dropped: edited target is out of scope.",
            )
            .await;
            return Next::Close;
        }

        if target_port == 25 {
            reply(
                client_out,
                "403 Forbidden",
                "forwarding to port 25 (SMTP) is prohibited.",
            )
            .await;
            return Next::Close;
        }

        let targets = match resolve(&target_host, target_port, shared.resolver.as_ref()).await {
            Ok(addrs) => addrs,
            Err(e) => {
                warn!("Could not resolve {target_host}: {e}");
                bad_gateway(client_out).await;
                return Next::Close;
            }
        };
        for target_addr in &targets {
            if is_own_listener(*target_addr, shared.listen_addr) {
                warn!("Refused request to the proxy's own address {authority}: forwarding loop");
                reply(
                    client_out,
                    "508 Loop Detected",
                    "this request is addressed to the proxy itself.",
                )
                .await;
                return Next::Close;
            }
            if let Some(reason) = is_restricted_destination(*target_addr) {
                warn!("Refused request to {authority} ({target_addr}): {reason}");
                reply(client_out, "403 Forbidden", reason).await;
                return Next::Close;
            }
        }

        let upstream =
            match connect_upstream(target_host.as_str(), &targets[..], scheme, shared).await {
                Ok(u) => u,
                Err(e) => {
                    warn!("Could not connect to {target_host}:{target_port}: {e}");
                    bad_gateway(client_out).await;
                    return Next::Close;
                }
            };

        // h2 writes its own head during the handshake, so only the h1 path sends it here.
        let (mut up_in, mut up_out, h2) = match upstream {
            Upstream::H1 { reader, writer } => (reader, writer, false),
            Upstream::H2(stream) => {
                let call = match http2::begin(*stream, &upstream_head, false).await {
                    Ok(call) => call,
                    Err(e) => {
                        warn!("h2 setup with {target_host}:{target_port} failed: {e}");
                        bad_gateway(client_out).await;
                        return Next::Close;
                    }
                };
                let (sender, response, driver) = call.split();
                (
                    Reader::new(Box::new(H2Reader::new(response, driver)) as BoxedRead),
                    Box::new(H2Writer::new(sender)) as BoxedWrite,
                    true,
                )
            }
        };

        if !h2 && up_out.write_all(&upstream_head).await.is_err() {
            bad_gateway(client_out).await;
            return Next::Close;
        }
        let mut response_capture = Capture::new();
        let final_sent = AtomicBool::new(false);
        let request_done =
            AtomicBool::new(request_framing == BodyFraming::None || intercepted_body.is_some());
        let exchange = ResponseContext {
            is_head: method.eq_ignore_ascii_case("HEAD"),
            upgrade,
            client_keep_alive,
            request_done: &request_done,
            final_sent: &final_sent,
        };
        let mut request_capture = match &intercepted_body {
            Some((_, cap)) => cap.clone(),
            None => Capture::new(),
        };

        let (request_result, response) = if let Some((body, _)) = intercepted_body {
            if !body.is_empty() && up_out.write_all(&body).await.is_err() {
                bad_gateway(client_out).await;
                return Next::Close;
            }
            if h2 {
                let _ = up_out.shutdown().await;
            }
            let resp = relay_response(
                &mut up_in,
                client_out,
                &exchange,
                &mut response_capture,
                shared,
                &method,
                &url,
                &target_host,
                &url_path,
            )
            .await;
            (Some(Ok(body.len() as u64)), Some(resp))
        } else {
            let request_fut = async {
                let copied = client_in
                    .copy_body(request_framing, &mut up_out, &mut request_capture)
                    .await;
                // h2 needs an explicit end of stream; h1 relies on framing or connection close.
                if h2 {
                    let _ = up_out.shutdown().await;
                }
                copied
            };
            let response_fut = relay_response(
                &mut up_in,
                client_out,
                &exchange,
                &mut response_capture,
                shared,
                &method,
                &url,
                &target_host,
                &url_path,
            );
            tokio::pin!(request_fut, response_fut);
            let mut request_result = None;
            let response = loop {
                tokio::select! {
                    r = &mut request_fut, if request_result.is_none() => {
                        let client_failed = matches!(r, Err(CopyError::Read(_)));
                        request_done.store(r.is_ok(), Ordering::SeqCst);
                        request_result = Some(r);
                        if client_failed {
                            break None;
                        }
                    }
                    r = &mut response_fut => break Some(r),
                }
            };
            (request_result, response)
        };
        let sent_final = final_sent.load(Ordering::SeqCst);

        let Some((response_head, response_result)) = response else {
            if let Some(Err(e)) = &request_result {
                warn!("Request body from the client was not completed: {e}");
                if matches!(e, CopyError::Read(FrameError::Malformed(_))) && !sent_final {
                    reply(client_out, "400 Bad Request", &format!("{e}.")).await;
                }
            }
            return Next::Close;
        };
        let Some(response_head) = response_head else {
            if let Err(e) = &response_result {
                warn!("No usable response from {target_host}:{target_port}: {e}");
            }
            if !sent_final {
                bad_gateway(client_out).await;
            }
            return Next::Close;
        };
        if let Err(e) = &response_result {
            warn!("Response from {target_host}:{target_port} was not completed: {e}");
        }

        let request_complete = matches!(request_result, Some(Ok(_)));
        let response_complete = response_result.is_ok();
        let response_bytes =
            response_head.head.len() as u64 + *response_result.as_ref().unwrap_or(&0);
        let request_bytes = upstream_head.len() as u64
            + match &request_result {
                Some(Ok(n)) => *n,
                _ => request_capture.len(),
            };
        shared
            .total_bytes
            .fetch_add((request_bytes + response_bytes) as usize, Ordering::Relaxed);

        let raw = TransactionRecord {
            id: 0,
            timestamp: chrono::Utc::now().timestamp_millis(),
            duration_ms: start_time.elapsed().as_millis() as u64,
            method,
            url,
            host: authority,
            path: url_path,
            request_headers,
            request_body: captured_message(
                &upstream_head,
                request_framing,
                request_capture,
                request_complete,
                info.content_type.as_deref(),
            ),
            status_code: response_head.status,
            response_headers: response_head.headers.clone(),
            response_body: captured_message(
                &response_head.head,
                response_head.framing,
                response_capture,
                response_complete,
                response_head.info.content_type.as_deref(),
            ),
            content_type: response_head.info.content_type.clone(),
            content_length: response_bytes as usize,
        };
        // insert_transaction redacts the copy it writes to disk, and we redact the copy the live UI
        // sees below, while it keeps one unredacted copy in the session-only reveal cache. Pass the
        // raw record so the reveal (eye) can recover real cookie and token values this session.
        if let Ok(id) = shared.storage.insert_transaction(&raw) {
            let mut stored_record = sanitize_record(&raw);
            stored_record.id = id;
            shared.total_captured.fetch_add(1, Ordering::Relaxed);
            let _ = shared.tx_events.send(stored_record);
        }

        if response_head.status == 101 && !h2 && response_complete && request_complete {
            return Next::Tunnel(up_in, up_out);
        }
        if request_complete && response_complete && !response_head.client_close {
            Next::KeepAlive
        } else {
            Next::Close
        }
    }
}

// --- Free functions ---

fn parse_start_line(head: &[u8]) -> (String, String) {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).unwrap_or("");
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    (method, target)
}

fn parse_connect_authority(head: &[u8]) -> Result<String, String> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| "invalid UTF-8 in request line".to_string())?;
    let mut parts = line.splitn(3, ' ');
    let _method = parts.next().ok_or("missing method")?;
    let authority = parts
        .next()
        .ok_or("missing CONNECT authority")?
        .trim()
        .to_string();
    if authority.is_empty() || authority.len() > 253 {
        return Err("invalid CONNECT authority".into());
    }
    if authority.contains(['@', '/', '?', '#', ' ', '\t', '\r', '\0']) {
        return Err("CONNECT authority must not contain userinfo, path, query, or fragment".into());
    }
    Ok(authority)
}

/// Resolve `host` once, through the test resolver when one is set. Callers check every returned
/// address and then connect to exactly these addresses, never to the name again.
pub(crate) async fn resolve(
    host: &str,
    port: u16,
    resolver: Option<&ResolverOverride>,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(ips) = resolver.and_then(|r| r(host)) {
        return Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    Ok(lookup_host((host, port)).await?.collect())
}

/// Counts an outbound connect and applies the test gate, before any socket is opened.
fn begin_outbound_connect(shared: &Shared, targets: &[SocketAddr]) -> Result<(), String> {
    shared.outbound_connects.fetch_add(1, Ordering::SeqCst);
    match &shared.connect_gate {
        Some(gate) if !gate(targets) => Err("outbound connect refused by the connect gate".into()),
        _ => Ok(()),
    }
}

struct EditedRequest {
    method: String,
    authority: String,
    target_host: String,
    target_port: u16,
    url: String,
    url_path: String,
    upstream_head: Vec<u8>,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

fn parse_edited_request(
    wire: &str,
    scheme: Scheme,
    session: Option<&SessionPin>,
) -> Result<EditedRequest, String> {
    let (head_str, body) = if let Some(idx) = wire.find("\r\n\r\n") {
        (&wire[..idx + 4], wire.as_bytes()[idx + 4..].to_vec())
    } else if let Some(idx) = wire.find("\n\n") {
        (&wire[..idx + 2], wire.as_bytes()[idx + 2..].to_vec())
    } else {
        (wire, Vec::new())
    };

    let mut header_buf = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
    let mut req = httparse::Request::new(&mut header_buf);
    let _ = req
        .parse(head_str.as_bytes())
        .map_err(|e| format!("invalid HTTP/1.1 request head in edited text: {e}"))?;

    let method = req.method.ok_or("missing HTTP method")?.to_string();
    let target = req.path.ok_or("missing HTTP target")?.to_string();

    let mut headers = header_pairs(req.headers);
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
    if !body.is_empty() {
        headers.push(("Content-Length".to_string(), body.len().to_string()));
    }

    let host_headers: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .collect();

    let (authority, target_host, target_port, url_path) = match session {
        Some(s) => (
            format!("{}:{}", s.host, s.port),
            s.host.clone(),
            s.port,
            target.clone(),
        ),
        None => {
            let authority = if target.starts_with("http://") || target.starts_with("https://") {
                let rest = target
                    .strip_prefix("http://")
                    .or_else(|| target.strip_prefix("https://"))
                    .unwrap_or(&target);
                let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
                auth.rsplit_once('@').map_or(auth, |(_, a)| a).to_string()
            } else if host_headers.len() == 1 {
                host_headers[0].to_string()
            } else {
                return Err("missing or ambiguous Host header in edited request".into());
            };

            let default_port = match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            };
            let (h, p) = http1::split_authority(&authority, default_port)
                .ok_or("invalid host and port in edited request")?;
            (authority, h, p, target.clone())
        }
    };

    let url = match scheme {
        Scheme::Http if target_host.contains(':') => {
            format!("http://[{target_host}]:{target_port}{url_path}")
        }
        Scheme::Http => format!("http://{target_host}:{target_port}{url_path}"),
        Scheme::Https if target_host.contains(':') => {
            format!("https://[{target_host}]:{target_port}{url_path}")
        }
        Scheme::Https => format!("https://{target_host}:{target_port}{url_path}"),
    };

    let origin_path = http1::origin_form(&method, &url_path);
    let mut reconstructed_head = format!("{method} {origin_path} HTTP/1.1\r\n");
    for (name, val) in &headers {
        reconstructed_head.push_str(&format!("{name}: {val}\r\n"));
    }
    reconstructed_head.push_str("\r\n");

    Ok(EditedRequest {
        method,
        authority,
        target_host,
        target_port,
        url,
        url_path,
        upstream_head: reconstructed_head.into_bytes(),
        body,
        headers,
    })
}

async fn connect_upstream(
    host: &str,
    targets: &[SocketAddr],
    scheme: Scheme,
    shared: &Shared,
) -> Result<Upstream, String> {
    begin_outbound_connect(shared, targets)?;
    let (reader, writer, h2): (BoxedRead, BoxedWrite, bool) = match scheme {
        Scheme::Http => {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(targets))
                .await
                .map_err(|_| format!("connect to {host} timed out"))?
                .map_err(|e| format!("connect to {host}: {e}"))?;
            let (r, w) = stream.into_split();
            (Box::new(r), Box::new(w), false)
        }
        Scheme::Https => {
            let Some(https) = &shared.https else {
                return Err(
                    "HTTPS upstream requested but HTTPS interception is not configured".into(),
                );
            };
            let upstream = https
                .connect_upstream_targets(host, targets)
                .await
                .map_err(|e| e.to_string())?;
            eprintln!("DEBUG upstream alpn h2={}", upstream.h2);
            if upstream.h2 {
                return Ok(Upstream::H2(Box::new(upstream.stream)));
            }
            let (r, w) = tokio::io::split(upstream.stream);
            (Box::new(r), Box::new(w), false)
        }
    };
    let _ = h2;
    Ok(Upstream::H1 {
        reader: Reader::new(reader),
        writer,
    })
}

#[allow(clippy::too_many_arguments)]
async fn relay_response<W: AsyncWrite + Unpin>(
    up_in: &mut Reader<BoxedRead>,
    client_out: &mut W,
    ctx: &ResponseContext<'_>,
    capture: &mut Capture,
    shared: &Shared,
    method: &str,
    url: &str,
    host: &str,
    path: &str,
) -> (Option<ResponseHead>, Result<u64, String>) {
    loop {
        let head = match up_in.read_head().await {
            Ok(Some(head)) => shared.match_replace.apply_response_head(&head),
            Ok(None) => return (None, Err("closed without a response".into())),
            Err(e) => return (None, Err(format!("response head: {e}"))),
        };
        let mut header_buf = [httparse::EMPTY_HEADER; http1::MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut header_buf);
        match resp.parse(&head) {
            Ok(httparse::Status::Complete(n)) if n == head.len() => {}
            _ => return (None, Err("response head could not be parsed".into())),
        }
        let status = resp.code.unwrap_or(0);
        let info = match http1::inspect_headers(resp.headers) {
            Ok(info) => info,
            Err(e) => return (None, Err(e.to_string())),
        };
        if (100..200).contains(&status) && status != 101 {
            if let Err(e) = write_timed(client_out, &head).await {
                return (None, Err(format!("client: {e}")));
            }
            continue;
        }
        if status == 101 && !ctx.upgrade {
            return (
                None,
                Err("101 Switching Protocols without an upgrade request".into()),
            );
        }
        let framing = if status == 101 || ctx.is_head || status == 204 || status == 304 {
            BodyFraming::None
        } else {
            match (info.transfer_encoding, info.content_length) {
                (Some(true), _) => BodyFraming::Chunked,
                (Some(false), _) => BodyFraming::UntilClose,
                (None, Some(n)) => BodyFraming::Length(n),
                (None, None) => BodyFraming::UntilClose,
            }
        };
        let client_close = !ctx.client_keep_alive
            || framing == BodyFraming::UntilClose
            || resp.version != Some(1)
            || !ctx.request_done.load(Ordering::SeqCst);
        let response_head = ResponseHead {
            status,
            headers: header_pairs(resp.headers),
            info,
            framing,
            client_close,
            head,
        };
        let to_client = http1::client_response_head(&response_head.head, status, client_close);

        if shared.intercept.is_intercept_responses_enabled()
            && framing != BodyFraming::UntilClose
            && status != 101
        {
            let mut resp_body = Vec::new();
            let mut body_capture = Capture::new();
            let body_res = up_in
                .copy_body(framing, &mut resp_body, &mut body_capture)
                .await;
            if let Ok(bytes_copied) = body_res {
                capture.feed(&resp_body);
                let hold_res = shared
                    .intercept
                    .hold_response(
                        method.to_string(),
                        url.to_string(),
                        status,
                        host.to_string(),
                        path.to_string(),
                        response_head.headers.clone(),
                        to_client.clone(),
                        resp_body.clone(),
                    )
                    .await;

                if let Ok((held_id, rx)) = hold_res {
                    let decision = tokio::select! {
                        d = rx => match d {
                            Ok(act) => act,
                            Err(_) => InterceptAction::Drop,
                        },
                        _ = tokio::time::sleep(shared.intercept.timeout()) => {
                            shared.intercept.remove_held(held_id).await;
                            InterceptAction::Forward { modified_wire: None }
                        }
                    };

                    match decision {
                        InterceptAction::Drop => {
                            ctx.final_sent.store(true, Ordering::SeqCst);
                            return (None, Err("response dropped by user in intercept".into()));
                        }
                        InterceptAction::Forward {
                            modified_wire: None,
                        } => {
                            if let Err(e) = write_timed(client_out, &to_client).await {
                                return (None, Err(format!("client: {e}")));
                            }
                            ctx.final_sent.store(true, Ordering::SeqCst);
                            if !resp_body.is_empty() {
                                if let Err(e) = write_timed(client_out, &resp_body).await {
                                    return (None, Err(format!("client: {e}")));
                                }
                            }
                            return (Some(response_head), Ok(bytes_copied));
                        }
                        InterceptAction::Forward {
                            modified_wire: Some(text),
                        } => {
                            if let Err(e) = write_timed(client_out, text.as_bytes()).await {
                                return (None, Err(format!("client: {e}")));
                            }
                            ctx.final_sent.store(true, Ordering::SeqCst);
                            return (Some(response_head), Ok(text.len() as u64));
                        }
                    }
                }
            }
        }
        if let Err(e) = write_timed(client_out, &to_client).await {
            return (None, Err(format!("client: {e}")));
        }
        ctx.final_sent.store(true, Ordering::SeqCst);
        let body = up_in
            .copy_body(framing, client_out, capture)
            .await
            .map_err(|e| e.to_string());
        return (Some(response_head), body);
    }
}

async fn relay_tunnel(
    client_in: Reader<BoxedRead>,
    mut client_out: BoxedWrite,
    up_in: Reader<BoxedRead>,
    mut up_out: BoxedWrite,
) {
    let (mut client_read, client_rest) = client_in.into_parts();
    let (mut up_read, up_rest) = up_in.into_parts();
    let upward = async {
        up_out.write_all(&client_rest).await?;
        tokio::io::copy(&mut client_read, &mut up_out).await?;
        up_out.shutdown().await
    };
    let downward = async {
        client_out.write_all(&up_rest).await?;
        tokio::io::copy(&mut up_read, &mut client_out).await?;
        client_out.shutdown().await
    };
    let _ = tokio::join!(upward, downward);
}

async fn blind_relay<S1, S2>(mut client: S1, mut upstream: S2)
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

pub(crate) fn captured_message(
    head: &[u8],
    framing: BodyFraming,
    capture: Capture,
    complete: bool,
    content_type: Option<&str>,
) -> Vec<u8> {
    let mut out = head.to_vec();
    if !complete {
        if framing != BodyFraming::None || !capture.is_empty() {
            out.extend(omission_record(
                "transfer interrupted before the body was complete",
                content_type,
                capture.len(),
                None,
            ));
        }
        return out;
    }
    let limit_kb = capture.limit() / 1024;
    match capture.finish() {
        Captured::Complete(body) if body.is_empty() => {}
        Captured::Complete(body) if framing == BodyFraming::Chunked => {
            out.extend(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend(body);
            out.extend(b"\r\n0\r\n\r\n");
        }
        Captured::Complete(body) => out.extend(body),
        Captured::TooLarge { length, sha256 } => out.extend(omission_record(
            &format!("body exceeds the {limit_kb} KB capture limit"),
            content_type,
            length,
            Some(&sha256),
        )),
    }
    out
}

pub(crate) fn header_pairs(headers: &[httparse::Header<'_>]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect()
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

async fn write_timed<W: AsyncWrite + Unpin>(out: &mut W, data: &[u8]) -> std::io::Result<()> {
    match tokio::time::timeout(http1::IO_TIMEOUT, out.write_all(data)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

async fn reply<W: AsyncWrite + Unpin>(out: &mut W, status: &str, message: &str) {
    let body = format!("DropSuite: {message}");
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = write_timed(out, resp.as_bytes()).await;
}

async fn bad_gateway<W: AsyncWrite + Unpin>(out: &mut W) {
    const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\n502 Bad Gateway (Proxy)";
    let _ = write_timed(out, BAD_GATEWAY).await;
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        // `::1` and `::` keep their IPv6 meaning; `to_ipv4()` below would turn them into
        // 0.0.0.1 (not loopback) and 0.0.0.0.
        IpAddr::V6(v6) if v6.is_loopback() || v6.is_unspecified() => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            // Deprecated IPv4-compatible form (::a.b.c.d) is still folded, so it cannot dodge
            // the IPv4 rules.
            None => v6.to_ipv4().map_or(ip, IpAddr::V4),
        },
    }
}

/// Cloud instance-metadata endpoints outside the link-local ranges, blocked by exact address.
const METADATA_V4: [Ipv4Addr; 1] = [
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
];
const METADATA_V6: [Ipv6Addr; 1] = [
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254), // AWS EC2 IMDS over IPv6
];

pub fn is_own_listener(target: SocketAddr, listen: SocketAddr) -> bool {
    if target.port() != listen.port() {
        return false;
    }
    let tip = canonical_ip(target.ip());
    let lip = canonical_ip(listen.ip());
    tip == lip || tip.is_loopback() || tip.is_unspecified()
}

/// The IPv4 address inside an RFC 6052 well-known-prefix NAT64 address (64:ff9b::/96).
/// Network-specific prefixes are not decoded: they cannot be known from here.
fn nat64_embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let [_, _, _, _, _, _, _, _, _, _, _, _, a, b, c, d] = v6.octets();
    (v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]).then(|| Ipv4Addr::new(a, b, c, d))
}

pub fn is_restricted_destination(target: SocketAddr) -> Option<&'static str> {
    let ip = canonical_ip(target.ip());
    if let Some(v4) = match ip {
        IpAddr::V6(v6) => nat64_embedded_ipv4(v6),
        IpAddr::V4(_) => None,
    } {
        // A NAT64 gateway would translate this to `v4`, so it gets exactly the IPv4 rules.
        return is_restricted_destination(SocketAddr::new(IpAddr::V4(v4), target.port()));
    }
    if ip.is_unspecified() {
        return Some("connection to unspecified address is prohibited.");
    }
    if ip.is_multicast() {
        return Some("connection to multicast address is prohibited.");
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return Some("link-local and cloud metadata addresses are strictly prohibited.");
            }
            if METADATA_V4.contains(&v4) {
                return Some("cloud metadata addresses are strictly prohibited.");
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() {
                return Some("link-local addresses are strictly prohibited.");
            }
            if METADATA_V6.contains(&v6) {
                return Some("cloud metadata addresses are strictly prohibited.");
            }
        }
    }
    None
}
