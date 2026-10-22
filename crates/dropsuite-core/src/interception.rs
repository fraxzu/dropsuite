//! Interactive proxy interception engine.
//!
//! Provides hold, inspect, edit, forward, and drop capabilities for in-flight
//! HTTP requests and responses. Designed with bounded queues, backpressure,
//! cancellation detection, and configurable timeouts to prevent indefinite client stalls.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, Mutex};

/// Maximum number of messages that can be held simultaneously.
pub const MAX_INTERCEPT_QUEUE_SIZE: usize = 100;

/// Default timeout after which an unhandled intercepted message is dropped to avoid stalls.
pub const DEFAULT_INTERCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum body size eligible for interactive in-memory interception (1 MB).
pub const MAX_INTERCEPT_BODY_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptKind {
    Request,
    Response,
}

impl std::fmt::Display for InterceptKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterceptKind::Request => write!(f, "request"),
            InterceptKind::Response => write!(f, "response"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptAction {
    Forward {
        /// If modified_wire is provided, it replaces the raw HTTP message.
        modified_wire: Option<String>,
    },
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptedMessageSummary {
    pub id: u64,
    pub kind: String,
    pub method: String,
    pub url: String,
    pub status_code: Option<u16>,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub raw_message: String,
    pub body_len: usize,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptStatus {
    pub enabled: bool,
    pub intercept_requests: bool,
    pub intercept_responses: bool,
    pub queue_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterceptEvent {
    MessageHeld(InterceptedMessageSummary),
    MessageResolved { id: u64, action: String },
    StateChanged(InterceptStatus),
}

pub struct HeldMessage {
    pub summary: InterceptedMessageSummary,
    pub raw_head: Vec<u8>,
    pub raw_body: Vec<u8>,
    pub sender: oneshot::Sender<InterceptAction>,
    pub created_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum HoldError {
    #[error("interception is currently disabled")]
    Disabled,
    #[error("intercept queue capacity reached (maximum {MAX_INTERCEPT_QUEUE_SIZE} held messages)")]
    QueueFull,
    #[error("message body too large for interactive interception ({0} bytes, limit {MAX_INTERCEPT_BODY_SIZE})")]
    BodyTooLarge(usize),
}

pub struct InterceptManager {
    enabled: AtomicBool,
    intercept_requests: AtomicBool,
    intercept_responses: AtomicBool,
    next_id: AtomicU64,
    queue: Arc<Mutex<VecDeque<HeldMessage>>>,
    events: broadcast::Sender<InterceptEvent>,
    timeout_ms: AtomicU64,
}

impl Default for InterceptManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InterceptManager {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        InterceptManager {
            enabled: AtomicBool::new(false),
            intercept_requests: AtomicBool::new(true),
            intercept_responses: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            events,
            timeout_ms: AtomicU64::new(DEFAULT_INTERCEPT_TIMEOUT.as_millis() as u64),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<InterceptEvent> {
        self.events.subscribe()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn is_intercept_requests_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst) && self.intercept_requests.load(Ordering::SeqCst)
    }

    pub fn is_intercept_responses_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst) && self.intercept_responses.load(Ordering::SeqCst)
    }

    /// Configured timeout for held requests/responses before automatic action is taken.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed))
    }

    /// Set custom timeout for interception (used for tests and user preference).
    pub fn set_timeout(&self, timeout: Duration) {
        self.timeout_ms
            .store(timeout.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    pub async fn status(&self) -> InterceptStatus {
        let queue_len = self.queue.lock().await.len();
        InterceptStatus {
            enabled: self.enabled.load(Ordering::SeqCst),
            intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
            intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
            queue_len,
        }
    }

    pub async fn set_enabled(&self, enabled: bool) -> InterceptStatus {
        let prev = self.enabled.swap(enabled, Ordering::SeqCst);
        if prev && !enabled {
            // Turning intercept off automatically forwards all held messages without modifications
            self.resolve_all(InterceptAction::Forward {
                modified_wire: None,
            })
            .await;
        }
        let st = self.status().await;
        let _ = self.events.send(InterceptEvent::StateChanged(st.clone()));
        st
    }

    pub async fn set_intercept_requests(&self, enabled: bool) -> InterceptStatus {
        self.intercept_requests.store(enabled, Ordering::SeqCst);
        let st = self.status().await;
        let _ = self.events.send(InterceptEvent::StateChanged(st.clone()));
        st
    }

    pub async fn set_intercept_responses(&self, enabled: bool) -> InterceptStatus {
        self.intercept_responses.store(enabled, Ordering::SeqCst);
        let st = self.status().await;
        let _ = self.events.send(InterceptEvent::StateChanged(st.clone()));
        st
    }

    pub async fn queue_len(&self) -> usize {
        self.queue.lock().await.len()
    }

    pub async fn list_held(&self) -> Vec<InterceptedMessageSummary> {
        let q = self.queue.lock().await;
        q.iter().map(|h| h.summary.clone()).collect()
    }

    pub async fn get_held(&self, id: u64) -> Option<InterceptedMessageSummary> {
        let q = self.queue.lock().await;
        q.iter().find(|h| h.summary.id == id).map(|h| h.summary.clone())
    }

    /// Submit a request to be held for user decision. Returns a oneshot receiver for the decision.
    pub async fn hold_request(
        &self,
        method: String,
        url: String,
        host: String,
        path: String,
        headers: Vec<(String, String)>,
        raw_head: Vec<u8>,
        raw_body: Vec<u8>,
    ) -> Result<(u64, oneshot::Receiver<InterceptAction>), HoldError> {
        if !self.is_intercept_requests_enabled() {
            return Err(HoldError::Disabled);
        }
        if raw_body.len() > MAX_INTERCEPT_BODY_SIZE {
            return Err(HoldError::BodyTooLarge(raw_body.len()));
        }

        let mut q = self.queue.lock().await;
        if q.len() >= MAX_INTERCEPT_QUEUE_SIZE {
            return Err(HoldError::QueueFull);
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let timestamp_ms = chrono::Utc::now().timestamp_millis();

        // Construct formatted raw message for inspector/editor
        let raw_head_str = String::from_utf8_lossy(&raw_head);
        let raw_body_str = String::from_utf8_lossy(&raw_body);
        let raw_message = format!("{raw_head_str}{raw_body_str}");

        let summary = InterceptedMessageSummary {
            id,
            kind: InterceptKind::Request.to_string(),
            method,
            url,
            status_code: None,
            host,
            path,
            headers,
            raw_message,
            body_len: raw_body.len(),
            timestamp_ms,
        };

        let (tx, rx) = oneshot::channel();
        q.push_back(HeldMessage {
            summary: summary.clone(),
            raw_head,
            raw_body,
            sender: tx,
            created_at: Instant::now(),
        });

        let _ = self.events.send(InterceptEvent::MessageHeld(summary));
        let _ = self.events.send(InterceptEvent::StateChanged(InterceptStatus {
            enabled: self.enabled.load(Ordering::SeqCst),
            intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
            intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
            queue_len: q.len(),
        }));

        Ok((id, rx))
    }

    /// Submit a response to be held for user decision. Returns a oneshot receiver for the decision.
    pub async fn hold_response(
        &self,
        method: String,
        url: String,
        status_code: u16,
        host: String,
        path: String,
        headers: Vec<(String, String)>,
        raw_head: Vec<u8>,
        raw_body: Vec<u8>,
    ) -> Result<(u64, oneshot::Receiver<InterceptAction>), HoldError> {
        if !self.is_intercept_responses_enabled() {
            return Err(HoldError::Disabled);
        }
        if raw_body.len() > MAX_INTERCEPT_BODY_SIZE {
            return Err(HoldError::BodyTooLarge(raw_body.len()));
        }

        let mut q = self.queue.lock().await;
        if q.len() >= MAX_INTERCEPT_QUEUE_SIZE {
            return Err(HoldError::QueueFull);
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let timestamp_ms = chrono::Utc::now().timestamp_millis();

        let raw_head_str = String::from_utf8_lossy(&raw_head);
        let raw_body_str = String::from_utf8_lossy(&raw_body);
        let raw_message = format!("{raw_head_str}{raw_body_str}");

        let summary = InterceptedMessageSummary {
            id,
            kind: InterceptKind::Response.to_string(),
            method,
            url,
            status_code: Some(status_code),
            host,
            path,
            headers,
            raw_message,
            body_len: raw_body.len(),
            timestamp_ms,
        };

        let (tx, rx) = oneshot::channel();
        q.push_back(HeldMessage {
            summary: summary.clone(),
            raw_head,
            raw_body,
            sender: tx,
            created_at: Instant::now(),
        });

        let _ = self.events.send(InterceptEvent::MessageHeld(summary));
        let _ = self.events.send(InterceptEvent::StateChanged(InterceptStatus {
            enabled: self.enabled.load(Ordering::SeqCst),
            intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
            intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
            queue_len: q.len(),
        }));

        Ok((id, rx))
    }

    /// Resolve a specific held message by ID (Forward with optional modifications, or Drop).
    pub async fn resolve(&self, id: u64, action: InterceptAction) -> bool {
        let mut q = self.queue.lock().await;
        if let Some(pos) = q.iter().position(|h| h.summary.id == id) {
            let held = q.remove(pos).unwrap();
            let action_str = match &action {
                InterceptAction::Forward { modified_wire } => {
                    if modified_wire.is_some() {
                        "forward_modified"
                    } else {
                        "forward"
                    }
                }
                InterceptAction::Drop => "drop",
            };
            let _ = held.sender.send(action);
            let _ = self.events.send(InterceptEvent::MessageResolved {
                id,
                action: action_str.to_string(),
            });
            let _ = self.events.send(InterceptEvent::StateChanged(InterceptStatus {
                enabled: self.enabled.load(Ordering::SeqCst),
                intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
                intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
                queue_len: q.len(),
            }));
            true
        } else {
            false
        }
    }

    /// Remove a held message without sending on its channel (e.g. on client disconnect or timeout).
    pub async fn remove_held(&self, id: u64) -> bool {
        let mut q = self.queue.lock().await;
        if let Some(pos) = q.iter().position(|h| h.summary.id == id) {
            q.remove(pos);
            let _ = self.events.send(InterceptEvent::MessageResolved {
                id,
                action: "evicted".to_string(),
            });
            let _ = self.events.send(InterceptEvent::StateChanged(InterceptStatus {
                enabled: self.enabled.load(Ordering::SeqCst),
                intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
                intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
                queue_len: q.len(),
            }));
            true
        } else {
            false
        }
    }

    /// Resolve all currently held messages with the specified action.
    pub async fn resolve_all(&self, action: InterceptAction) {
        let mut q = self.queue.lock().await;
        while let Some(held) = q.pop_front() {
            let _ = held.sender.send(action.clone());
        }
        let _ = self.events.send(InterceptEvent::StateChanged(InterceptStatus {
            enabled: self.enabled.load(Ordering::SeqCst),
            intercept_requests: self.intercept_requests.load(Ordering::SeqCst),
            intercept_responses: self.intercept_responses.load(Ordering::SeqCst),
            queue_len: 0,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_intercept_rejects_hold() {
        let mgr = InterceptManager::new();
        assert!(!mgr.is_enabled());
        let res = mgr
            .hold_request(
                "GET".into(),
                "http://example.com/".into(),
                "example.com".into(),
                "/".into(),
                vec![],
                b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                vec![],
            )
            .await;
        assert!(matches!(res, Err(HoldError::Disabled)));
    }

    #[tokio::test]
    async fn forward_and_drop_flow() {
        let mgr = InterceptManager::new();
        mgr.set_enabled(true).await;
        assert!(mgr.is_enabled());

        let (id, rx) = mgr
            .hold_request(
                "POST".into(),
                "http://example.com/api".into(),
                "example.com".into(),
                "/api".into(),
                vec![("Content-Type".into(), "application/json".into())],
                b"POST /api HTTP/1.1\r\n\r\n".to_vec(),
                b"{\"test\":true}".to_vec(),
            )
            .await
            .unwrap();

        assert_eq!(mgr.queue_len().await, 1);
        let list = mgr.list_held().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert_eq!(list[0].method, "POST");

        let resolved = mgr
            .resolve(
                id,
                InterceptAction::Forward {
                    modified_wire: Some("POST /api HTTP/1.1\r\n\r\n{\"edited\":true}".into()),
                },
            )
            .await;
        assert!(resolved);
        assert_eq!(mgr.queue_len().await, 0);

        let decision = rx.await.unwrap();
        match decision {
            InterceptAction::Forward { modified_wire } => {
                assert_eq!(
                    modified_wire,
                    Some("POST /api HTTP/1.1\r\n\r\n{\"edited\":true}".into())
                );
            }
            _ => panic!("Expected Forward action"),
        }
    }

    #[tokio::test]
    async fn queue_capacity_limit_enforced() {
        let mgr = InterceptManager::new();
        mgr.set_enabled(true).await;

        let mut rxs = Vec::new();
        for _ in 0..MAX_INTERCEPT_QUEUE_SIZE {
            let (_, rx) = mgr
                .hold_request(
                    "GET".into(),
                    "http://example.com/".into(),
                    "example.com".into(),
                    "/".into(),
                    vec![],
                    b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                    vec![],
                )
                .await
                .unwrap();
            rxs.push(rx);
        }

        let overflow = mgr
            .hold_request(
                "GET".into(),
                "http://example.com/overflow".into(),
                "example.com".into(),
                "/overflow".into(),
                vec![],
                b"GET /overflow HTTP/1.1\r\n\r\n".to_vec(),
                vec![],
            )
            .await;
        assert!(matches!(overflow, Err(HoldError::QueueFull)));

        mgr.set_enabled(false).await;
        assert_eq!(mgr.queue_len().await, 0);
    }
}
