use serde::{Deserialize, Serialize};

/// Represents an individual HTTP request-response transaction captured by DropSuite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: i64,
    pub timestamp: i64,
    pub duration_ms: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub request_headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub request_body: Vec<u8>,
    pub status_code: u16,
    pub response_headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub response_body: Vec<u8>,
    pub content_type: Option<String>,
    pub content_length: usize,
}

/// Lightweight summary of a transaction used for high-performance table views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub id: i64,
    pub timestamp: i64,
    pub duration_ms: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status_code: u16,
    pub content_type: Option<String>,
    pub content_length: usize,
}

impl From<&TransactionRecord> for TransactionSummary {
    fn from(r: &TransactionRecord) -> Self {
        Self {
            id: r.id,
            timestamp: r.timestamp,
            duration_ms: r.duration_ms,
            method: r.method.clone(),
            host: r.host.clone(),
            path: r.path.clone(),
            status_code: r.status_code,
            content_type: r.content_type.clone(),
            content_length: r.content_length,
        }
    }
}

/// Query filter options for searching and paginating through captured traffic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryFilter {
    pub query: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub content_type: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Real-time proxy listener status and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub is_running: bool,
    pub bind_address: String,
    pub port: u16,
    pub total_captured: usize,
    pub total_bytes_transferred: usize,
}

/// Represents a persistent Repeater tab workbench session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterTabRecord {
    pub id: i64,
    pub name: String,
    pub color: Option<String>,
    pub group_name: Option<String>,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Represents a single manual execution attempt within a Repeater tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepeaterAttemptRecord {
    pub id: i64,
    pub tab_id: i64,
    pub seq: u32,
    pub created_at: i64,
    pub method: String,
    pub destination: String,
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    pub total_bytes: u64,
    pub sent_bytes: u64,
    pub response_headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub response_body: Vec<u8>,
    pub content_type: Option<String>,
    pub failure_kind: Option<String>,
    pub failure_message: Option<String>,
}
