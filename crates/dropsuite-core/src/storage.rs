use rusqlite::{params, Connection, OpenFlags, Result, Row};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

use crate::cookies::StoredCookie;

/// A browser fingerprint recorded for a host that solved a challenge. Cloudflare binds the
/// clearance cookie to it, so Replay must reuse the exact value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePin {
    pub host: String,
    pub user_agent: String,
    /// Preset name (`edge`, `chrome`, ...) that produced the header set.
    pub preset: String,
    pub expires_at: i64,
}
use crate::models::{
    HistoryFilter, RepeaterAttemptRecord, RepeaterTabRecord, TransactionRecord, TransactionSummary,
};
use crate::sanitize::{
    sanitize_header_pairs, sanitize_raw_message, sanitize_record, sanitize_target,
};

#[derive(Clone)]
pub struct StorageManager {
    conn: Arc<Mutex<Connection>>,
}

/// Counts of stored rows that still hold data the current redaction policy would remove.
/// Holds counts only; never any captured value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyAudit {
    pub total_records: usize,
    pub affected_records: usize,
    pub request_raw_affected: usize,
    pub response_raw_affected: usize,
    pub url_or_path_affected: usize,
    pub parsed_headers_affected: usize,
}

const RECORD_COLUMNS: &str = "id, timestamp, duration_ms, method, url, host, path,
    request_headers, request_body, status_code,
    response_headers, response_body, content_type, content_length";

fn row_to_record(row: &Row) -> Result<TransactionRecord> {
    let req_headers_str: String = row.get(7)?;
    let resp_headers_str: String = row.get(10)?;
    Ok(TransactionRecord {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        duration_ms: row.get::<_, i64>(2)? as u64,
        method: row.get(3)?,
        url: row.get(4)?,
        host: row.get(5)?,
        path: row.get(6)?,
        request_headers: serde_json::from_str(&req_headers_str).unwrap_or_default(),
        request_body: row.get::<_, Option<Vec<u8>>>(8)?.unwrap_or_default(),
        status_code: row.get(9)?,
        response_headers: serde_json::from_str(&resp_headers_str).unwrap_or_default(),
        response_body: row.get::<_, Option<Vec<u8>>>(11)?.unwrap_or_default(),
        content_type: row.get(12)?,
        content_length: row.get::<_, i64>(13)? as usize,
    })
}

impl StorageManager {
    /// Initialize or open an existing SQLite database at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Performance optimizations for local desktop testing tool:
        // WAL mode enables concurrent reads and writes.
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
        ",
        )?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        storage.init_schema()?;
        info!("SQLite storage manager initialized successfully.");
        Ok(storage)
    }

    /// Open an existing database without write access, for audits. Creates nothing.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// In-memory storage for unit tests or ephemeral mode.
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                request_headers TEXT NOT NULL,
                request_body BLOB,
                status_code INTEGER NOT NULL,
                response_headers TEXT NOT NULL,
                response_body BLOB,
                content_type TEXT,
                content_length INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transactions_host ON transactions(host);
            CREATE INDEX IF NOT EXISTS idx_transactions_path ON transactions(path);
            CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status_code);
            CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp DESC);

            CREATE TABLE IF NOT EXISTS repeater_tabs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                color TEXT,
                group_name TEXT,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_repeater_tabs_updated ON repeater_tabs(updated_at DESC);

            CREATE TABLE IF NOT EXISTS repeater_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tab_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                method TEXT NOT NULL,
                destination TEXT NOT NULL,
                status_code INTEGER,
                duration_ms INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                sent_bytes INTEGER NOT NULL,
                response_headers TEXT,
                response_body BLOB,
                content_type TEXT,
                failure_kind TEXT,
                failure_message TEXT,
                FOREIGN KEY(tab_id) REFERENCES repeater_tabs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_repeater_attempts_tab_seq ON repeater_attempts(tab_id, seq);

            CREATE TABLE IF NOT EXISTS cookies (
                host TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                domain TEXT,
                value TEXT NOT NULL,
                secure INTEGER NOT NULL,
                http_only INTEGER NOT NULL,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (host, name, path)
            );

            CREATE INDEX IF NOT EXISTS idx_cookies_host ON cookies(host);

            CREATE TABLE IF NOT EXISTS challenge_pins (
                host TEXT PRIMARY KEY,
                user_agent TEXT NOT NULL,
                preset TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
        ",
        )?;
        Ok(())
    }

    /// Insert a new captured transaction into the database. Returns the generated ID.
    ///
    /// This is the persistence boundary: the record is always sanitized here, so no caller
    /// can store unredacted headers, raw messages or URLs, whatever it passes in.
    pub fn insert_transaction(&self, record: &TransactionRecord) -> Result<i64> {
        let record = sanitize_record(record);
        let conn = self.conn.lock().unwrap();
        let req_headers_json = serde_json::to_string(&record.request_headers).unwrap_or_default();
        let resp_headers_json = serde_json::to_string(&record.response_headers).unwrap_or_default();

        conn.execute(
            "INSERT INTO transactions (
                timestamp, duration_ms, method, url, host, path,
                request_headers, request_body, status_code,
                response_headers, response_body, content_type, content_length
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.timestamp,
                record.duration_ms as i64,
                record.method,
                record.url,
                record.host,
                record.path,
                req_headers_json,
                record.request_body,
                record.status_code,
                resp_headers_json,
                record.response_body,
                record.content_type,
                record.content_length as i64,
            ],
        )?;

        let id = conn.last_insert_rowid();
        debug!(id = id, url = %record.url, "Persisted transaction");
        Ok(id)
    }

    /// Fetch lightweight summaries matching filter criteria (for virtualized UI table).
    pub fn list_summaries(&self, filter: &HistoryFilter) -> Result<Vec<TransactionSummary>> {
        let conn = self.conn.lock().unwrap();
        let limit = filter.limit.unwrap_or(500);
        let offset = filter.offset.unwrap_or(0);

        let mut query = String::from(
            "SELECT id, timestamp, duration_ms, method, host, path, status_code, content_type, content_length
             FROM transactions WHERE 1=1",
        );

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ref m) = filter.method {
            query.push_str(" AND method = ?");
            params.push(Box::new(m.to_uppercase()));
        }

        if let Some(code) = filter.status_code {
            query.push_str(" AND status_code = ?");
            params.push(Box::new(code));
        }

        if let Some(min_code) = filter.status_min {
            query.push_str(" AND status_code >= ?");
            params.push(Box::new(min_code));
        }

        if let Some(max_code) = filter.status_max {
            query.push_str(" AND status_code <= ?");
            params.push(Box::new(max_code));
        }

        if let Some(ref ct) = filter.content_type {
            query.push_str(" AND content_type LIKE ?");
            params.push(Box::new(format!("%{}%", ct)));
        }

        if let Some(ref q) = filter.query {
            let pattern = format!("%{}%", q);
            query.push_str(" AND (url LIKE ? OR host LIKE ? OR path LIKE ?)");
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern.clone()));
            params.push(Box::new(pattern));
        }

        let sort_column = match filter.sort_by.as_deref() {
            Some("timestamp") => "timestamp",
            Some("duration_ms") => "duration_ms",
            Some("method") => "method",
            Some("host") => "host",
            Some("path") => "path",
            Some("status_code") => "status_code",
            Some("content_length") => "content_length",
            _ => "id",
        };

        let sort_dir = match filter.sort_order.as_deref() {
            Some("ASC") | Some("asc") => "ASC",
            _ => "DESC",
        };

        query.push_str(&format!(
            " ORDER BY {} {} LIMIT ? OFFSET ?",
            sort_column, sort_dir
        ));
        params.push(Box::new(limit as i64));
        params.push(Box::new(offset as i64));

        let params_slice: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params_slice.as_slice(), |row| {
            let host: String = row.get(4)?;
            let path: String = row.get(5)?;
            // Read-side sanitization keeps rows written before P1.6 safe to display.
            Ok(TransactionSummary {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                duration_ms: row.get::<_, i64>(2)? as u64,
                method: row.get(3)?,
                host: host
                    .rsplit_once('@')
                    .map_or(host.clone(), |(_, h)| h.to_string()),
                path: sanitize_target(&path),
                status_code: row.get(6)?,
                content_type: row.get(7)?,
                content_length: row.get::<_, i64>(8)? as usize,
            })
        })?;

        let mut summaries = Vec::new();
        for r in rows {
            summaries.push(r?);
        }
        Ok(summaries)
    }

    /// Retrieve full details of a transaction including raw headers and bodies.
    /// The result is sanitized on the way out, so rows stored before P1.6 cannot leak
    /// plaintext credentials through the API even though their bytes remain on disk.
    pub fn get_transaction_by_id(&self, id: i64) -> Result<Option<TransactionRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM transactions WHERE id = ?1"
        ))?;
        let mut rows = stmt.query(params![id])?;
        match rows.next()? {
            Some(row) => Ok(Some(sanitize_record(&row_to_record(row)?))),
            None => Ok(None),
        }
    }

    /// Fold the WAL into the main database file. Called on orderly shutdown so the database
    /// is self-contained on disk; SQLite stays crash-safe without it.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
    }

    /// Total count of captured transactions in storage.
    pub fn count_transactions(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// Delete every captured transaction. Returns the number of rows removed. Destructive
    /// and irreversible. `secure_delete` plus a WAL checkpoint keep the purged bytes from
    /// lingering in the database file; copies outside it (HAR exports, backups) are untouched.
    /// HTTP history, the site map, and the passive scanner all read this table, so clearing it
    /// empties them too. Repeater tabs and their saved attempts live in other tables and remain.
    pub fn clear_transactions(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA secure_delete = ON;")?;
        let removed = conn.execute("DELETE FROM transactions", [])?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(removed)
    }

    /// Count stored rows that the current redaction policy would change, without
    /// returning or logging any captured value. Read-only.
    pub fn audit_legacy_records(&self) -> Result<LegacyAudit> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&format!("SELECT {RECORD_COLUMNS} FROM transactions"))?;
        let mut rows = stmt.query([])?;
        let mut audit = LegacyAudit::default();
        while let Some(row) = rows.next()? {
            let record = row_to_record(row)?;
            let clean = sanitize_record(&record);
            audit.total_records += 1;
            let req = sanitize_raw_message(&record.request_body) != record.request_body;
            let resp = sanitize_raw_message(&record.response_body) != record.response_body;
            let target =
                clean.url != record.url || clean.path != record.path || clean.host != record.host;
            let headers = clean.request_headers != record.request_headers
                || clean.response_headers != record.response_headers;
            audit.request_raw_affected += req as usize;
            audit.response_raw_affected += resp as usize;
            audit.url_or_path_affected += target as usize;
            audit.parsed_headers_affected += headers as usize;
            audit.affected_records += (req || resp || target || headers) as usize;
        }
        Ok(audit)
    }

    /// Rewrite every stored row with the current redaction policy, then purge the old bytes
    /// from SQLite's own storage (secure_delete, WAL checkpoint, VACUUM). Returns the number
    /// of rows rewritten. Destructive and irreversible: only run with the user's explicit
    /// consent and with the daemon stopped. It cannot reach copies outside the database file
    /// (backups, snapshots, filesystem slack); see docs/SECURITY.md.
    pub fn redact_legacy_records(&self) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA secure_delete = ON;")?;
        let records = {
            let mut stmt = conn.prepare(&format!("SELECT {RECORD_COLUMNS} FROM transactions"))?;
            let mapped = stmt.query_map([], row_to_record)?;
            mapped.collect::<Result<Vec<_>>>()?
        };
        let tx = conn.transaction()?;
        let mut rewritten = 0;
        for record in &records {
            let clean = sanitize_record(record);
            let changed = clean.url != record.url
                || clean.path != record.path
                || clean.host != record.host
                || clean.request_headers != record.request_headers
                || clean.response_headers != record.response_headers
                || clean.request_body != record.request_body
                || clean.response_body != record.response_body;
            if !changed {
                continue;
            }
            tx.execute(
                "UPDATE transactions SET url = ?1, host = ?2, path = ?3, request_headers = ?4,
                    request_body = ?5, response_headers = ?6, response_body = ?7 WHERE id = ?8",
                params![
                    clean.url,
                    clean.host,
                    clean.path,
                    serde_json::to_string(&clean.request_headers).unwrap_or_default(),
                    clean.request_body,
                    serde_json::to_string(&clean.response_headers).unwrap_or_default(),
                    clean.response_body,
                    record.id,
                ],
            )?;
            rewritten += 1;
        }
        tx.commit()?;
        conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);",
        )?;
        Ok(rewritten)
    }

    // =========================================================================
    // Multi-Tab Repeater Workbench Persistence
    // =========================================================================

    /// List all repeater tabs ordered by ID ascending.
    pub fn list_repeater_tabs(&self) -> Result<Vec<RepeaterTabRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, color, group_name, method, url, headers, body, created_at, updated_at
             FROM repeater_tabs ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let headers_str: String = row.get(6)?;
            Ok(RepeaterTabRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                color: row.get(2)?,
                group_name: row.get(3)?,
                method: row.get(4)?,
                url: row.get(5)?,
                headers: serde_json::from_str(&headers_str).unwrap_or_default(),
                body: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;

        let mut tabs = Vec::new();
        for r in rows {
            tabs.push(r?);
        }
        Ok(tabs)
    }

    /// Retrieve a single repeater tab by its ID.
    pub fn get_repeater_tab(&self, id: i64) -> Result<Option<RepeaterTabRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, color, group_name, method, url, headers, body, created_at, updated_at
             FROM repeater_tabs WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let headers_str: String = row.get(6)?;
            Ok(Some(RepeaterTabRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                color: row.get(2)?,
                group_name: row.get(3)?,
                method: row.get(4)?,
                url: row.get(5)?,
                headers: serde_json::from_str(&headers_str).unwrap_or_default(),
                body: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Save (insert or update) a repeater tab. Returns tab ID.
    pub fn save_repeater_tab(&self, tab: &RepeaterTabRecord) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let headers_json = serde_json::to_string(&tab.headers).unwrap_or_default();
        let now = if tab.updated_at > 0 {
            tab.updated_at
        } else {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        };

        if tab.id > 0 {
            conn.execute(
                "UPDATE repeater_tabs
                 SET name = ?1, color = ?2, group_name = ?3, method = ?4, url = ?5, headers = ?6, body = ?7, updated_at = ?8
                 WHERE id = ?9",
                params![
                    tab.name,
                    tab.color,
                    tab.group_name,
                    tab.method,
                    tab.url,
                    headers_json,
                    tab.body,
                    now,
                    tab.id,
                ],
            )?;
            Ok(tab.id)
        } else {
            let created = if tab.created_at > 0 {
                tab.created_at
            } else {
                now
            };
            conn.execute(
                "INSERT INTO repeater_tabs (name, color, group_name, method, url, headers, body, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    tab.name,
                    tab.color,
                    tab.group_name,
                    tab.method,
                    tab.url,
                    headers_json,
                    tab.body,
                    created,
                    now,
                ],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }

    /// Delete a repeater tab and all associated attempts.
    pub fn delete_repeater_tab(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM repeater_attempts WHERE tab_id = ?1",
            params![id],
        )?;
        conn.execute("DELETE FROM repeater_tabs WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// List recorded execution attempts for a repeater tab.
    pub fn list_repeater_attempts(
        &self,
        tab_id: i64,
        limit: Option<usize>,
    ) -> Result<Vec<RepeaterAttemptRecord>> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.unwrap_or(20);
        let mut stmt = conn.prepare(
            "SELECT id, tab_id, seq, created_at, method, destination, status_code, duration_ms,
                    total_bytes, sent_bytes, response_headers, response_body, content_type,
                    failure_kind, failure_message
             FROM repeater_attempts WHERE tab_id = ?1 ORDER BY seq ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![tab_id, limit as i64], |row| {
            let resp_headers_str: Option<String> = row.get(10)?;
            let resp_headers: Vec<(String, String)> = resp_headers_str
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(RepeaterAttemptRecord {
                id: row.get(0)?,
                tab_id: row.get(1)?,
                seq: row.get::<_, i64>(2)? as u32,
                created_at: row.get(3)?,
                method: row.get(4)?,
                destination: row.get(5)?,
                status_code: row.get(6)?,
                duration_ms: row.get::<_, i64>(7)? as u64,
                total_bytes: row.get::<_, i64>(8)? as u64,
                sent_bytes: row.get::<_, i64>(9)? as u64,
                response_headers: resp_headers,
                response_body: row.get::<_, Option<Vec<u8>>>(11)?.unwrap_or_default(),
                content_type: row.get(12)?,
                failure_kind: row.get(13)?,
                failure_message: row.get(14)?,
            })
        })?;

        let mut attempts = Vec::new();
        for r in rows {
            attempts.push(r?);
        }
        Ok(attempts)
    }

    /// Record a manual send attempt for a repeater tab, sanitizing response headers and body.
    pub fn save_repeater_attempt(&self, attempt: &RepeaterAttemptRecord) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let clean_headers = sanitize_header_pairs(&attempt.response_headers);
        let clean_body = sanitize_raw_message(&attempt.response_body);
        let headers_json = serde_json::to_string(&clean_headers).unwrap_or_default();

        conn.execute(
            "INSERT INTO repeater_attempts (
                tab_id, seq, created_at, method, destination, status_code, duration_ms,
                total_bytes, sent_bytes, response_headers, response_body, content_type,
                failure_kind, failure_message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                attempt.tab_id,
                attempt.seq as i64,
                attempt.created_at,
                attempt.method,
                attempt.destination,
                attempt.status_code,
                attempt.duration_ms as i64,
                attempt.total_bytes as i64,
                attempt.sent_bytes as i64,
                headers_json,
                clean_body,
                attempt.content_type,
                attempt.failure_kind,
                attempt.failure_message,
            ],
        )?;

        let id = conn.last_insert_rowid();

        // Enforce max 20 attempts retention per tab to prevent SQLite bloat
        conn.execute(
            "DELETE FROM repeater_attempts WHERE tab_id = ?1 AND id NOT IN (
                SELECT id FROM repeater_attempts WHERE tab_id = ?1 ORDER BY seq DESC LIMIT 20
            )",
            params![attempt.tab_id],
        )?;

        Ok(id)
    }

    /// Clear all attempts for a given repeater tab.
    pub fn clear_repeater_attempts(&self, tab_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM repeater_attempts WHERE tab_id = ?1",
            params![tab_id],
        )?;
        Ok(())
    }

    // =========================================================================
    // Standard HTTP Archive (HAR 1.2) Export
    // =========================================================================

    /// Export selected transactions to standard HTTP Archive (HAR 1.2) JSON.
    pub fn export_har(&self, ids: &[i64]) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let mut entries = Vec::new();

        for &id in ids {
            let mut stmt = conn.prepare(&format!(
                "SELECT {RECORD_COLUMNS} FROM transactions WHERE id = ?1"
            ))?;
            let mut rows = stmt.query(params![id])?;
            if let Some(row) = rows.next()? {
                let rec = sanitize_record(&row_to_record(row)?);
                let started_dt = chrono::DateTime::from_timestamp_millis(rec.timestamp)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

                let req_headers_json: Vec<serde_json::Value> = rec
                    .request_headers
                    .iter()
                    .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
                    .collect();

                let resp_headers_json: Vec<serde_json::Value> = rec
                    .response_headers
                    .iter()
                    .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
                    .collect();

                let req_body_str = String::from_utf8_lossy(&rec.request_body).to_string();
                let resp_body_str = String::from_utf8_lossy(&rec.response_body).to_string();

                let entry = serde_json::json!({
                    "startedDateTime": started_dt,
                    "time": rec.duration_ms,
                    "request": {
                        "method": rec.method,
                        "url": rec.url,
                        "httpVersion": "HTTP/1.1",
                        "headers": req_headers_json,
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": rec.request_body.len(),
                        "postData": if !rec.request_body.is_empty() {
                            Some(serde_json::json!({
                                "mimeType": "application/octet-stream",
                                "text": req_body_str
                            }))
                        } else {
                            None
                        }
                    },
                    "response": {
                        "status": rec.status_code,
                        "statusText": "",
                        "httpVersion": "HTTP/1.1",
                        "headers": resp_headers_json,
                        "cookies": [],
                        "content": {
                            "size": rec.content_length,
                            "mimeType": rec.content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                            "text": resp_body_str
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": rec.content_length
                    },
                    "cache": {},
                    "timings": {
                        "send": 0,
                        "wait": rec.duration_ms,
                        "receive": 0
                    }
                });
                entries.push(entry);
            }
        }

        let har = serde_json::json!({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "DropSuite",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "pages": [],
                "entries": entries
            }
        });

        serde_json::to_string_pretty(&har).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    }

    /// Store or replace a cookie. The same host, name and path is one row.
    pub fn upsert_cookie(&self, cookie: &StoredCookie) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO cookies (host, name, path, domain, value, secure, http_only, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(host, name, path) DO UPDATE SET
                domain = excluded.domain,
                value = excluded.value,
                secure = excluded.secure,
                http_only = excluded.http_only,
                expires_at = excluded.expires_at",
            params![
                cookie.host,
                cookie.name,
                cookie.path,
                cookie.domain,
                cookie.value,
                cookie.secure as i64,
                cookie.http_only as i64,
                cookie.expires_at,
                cookie.created_at,
            ],
        )?;
        Ok(())
    }

    fn row_to_cookie(row: &Row) -> Result<StoredCookie> {
        Ok(StoredCookie {
            host: row.get(0)?,
            name: row.get(1)?,
            path: row.get(2)?,
            domain: row.get(3)?,
            value: row.get(4)?,
            secure: row.get::<_, i64>(5)? != 0,
            http_only: row.get::<_, i64>(6)? != 0,
            expires_at: row.get(7)?,
            created_at: row.get(8)?,
        })
    }

    /// Every stored cookie, oldest first. Callers filter with [`StoredCookie::matches`].
    pub fn list_cookies(&self) -> Result<Vec<StoredCookie>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT host, name, path, domain, value, secure, http_only, expires_at, created_at
             FROM cookies ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], Self::row_to_cookie)?;
        rows.collect()
    }

    /// Cookies whose stored host is `host` or a parent domain of it. Path, scheme and expiry are
    /// checked by the caller against the concrete request.
    pub fn cookies_for_host(&self, host: &str) -> Result<Vec<StoredCookie>> {
        Ok(self
            .list_cookies()?
            .into_iter()
            .filter(|c| crate::cookies::domain_match(host, c.scope()))
            .collect())
    }

    pub fn delete_cookie(&self, host: &str, name: &str, path: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM cookies WHERE host = ?1 AND name = ?2 AND path = ?3",
            params![host, name, path],
        )
    }

    pub fn clear_cookies(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM cookies", [])
    }

    pub fn upsert_challenge_pin(&self, pin: &ChallengePin) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO challenge_pins (host, user_agent, preset, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(host) DO UPDATE SET
                user_agent = excluded.user_agent,
                preset = excluded.preset,
                expires_at = excluded.expires_at",
            params![pin.host, pin.user_agent, pin.preset, pin.expires_at],
        )?;
        Ok(())
    }

    /// The live pin for a host. Expired rows are purged on the way out.
    pub fn challenge_pin(&self, host: &str, now: i64) -> Result<Option<ChallengePin>> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM challenge_pins WHERE expires_at <= ?1",
            params![now],
        )?;
        let mut stmt = conn.prepare(
            "SELECT host, user_agent, preset, expires_at FROM challenge_pins WHERE host = ?1",
        )?;
        let mut rows = stmt.query(params![host])?;
        match rows.next()? {
            Some(row) => Ok(Some(ChallengePin {
                host: row.get(0)?,
                user_agent: row.get(1)?,
                preset: row.get(2)?,
                expires_at: row.get(3)?,
            })),
            None => Ok(None),
        }
    }

    pub fn clear_challenge_pin(&self, host: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM challenge_pins WHERE host = ?1", params![host])?;
        Ok(())
    }

    /// Drop cookies that have expired by `now`. Returns how many rows went.
    pub fn purge_expired_cookies(&self, now: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM cookies WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )
    }
}
