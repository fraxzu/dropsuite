//! IPC commands available to the main window (each granted in `capabilities/main-window.json`).
//! Everything returned here comes from `dropsuite-core`, which sanitizes records at the
//! persistence boundary and again on read.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dropsuite_core::intruder::{self, Attack, AttemptOutcome, Guards};
use dropsuite_core::models::HistoryFilter;
use dropsuite_core::replay::{self, ReplayError, ReplayOptions, ReplayRequest, ReplayResponse};
use dropsuite_core::{ProxyStatus, ScopeEngine, TransactionRecord, TransactionSummary};
use serde::Serialize;
use tauri::{Manager, State};

use crate::engine::{Engine, EngineState, BIND_IP, DEFAULT_PROXY_PORT};
use crate::settings;

const MAX_QUERY_LEN: usize = 512;

#[tauri::command]
pub async fn get_status(state: State<'_, EngineState>) -> Result<ProxyStatus, String> {
    let engine = state.engine()?;
    let status = engine.proxy.lock().await.status();
    Ok(status)
}

#[tauri::command]
pub fn list_history(
    state: State<'_, EngineState>,
    query: Option<String>,
    method: Option<String>,
) -> Result<Vec<TransactionSummary>, String> {
    let engine = state.engine()?;
    let query = query.filter(|q| !q.is_empty());
    if query.as_ref().is_some_and(|q| q.len() > MAX_QUERY_LEN) {
        return Err("Search text is too long.".into());
    }
    let method = method.filter(|m| !m.is_empty());
    if method
        .as_ref()
        .is_some_and(|m| m.len() > 16 || !m.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Err("Unknown HTTP method filter.".into());
    }
    let filter = HistoryFilter {
        query,
        method,
        ..Default::default()
    };
    engine
        .storage
        .list_summaries(&filter)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_transaction(
    state: State<'_, EngineState>,
    id: i64,
) -> Result<TransactionRecord, String> {
    let engine = state.engine()?;
    engine
        .storage
        .get_transaction_by_id(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "DropSuite has no record with this ID.".into())
}

#[tauri::command]
pub async fn start_proxy(state: State<'_, EngineState>) -> Result<ProxyStatus, String> {
    let engine = state.engine()?;
    let mut proxy = engine.proxy.lock().await;
    // A second start while running is a no-op inside the engine, so no duplicate listener.
    if let Err(e) = proxy.start().await {
        tracing::warn!("Listener did not start: {e}");
        return Err(e.to_string());
    }
    Ok(proxy.status())
}

#[tauri::command]
pub async fn stop_proxy(state: State<'_, EngineState>) -> Result<ProxyStatus, String> {
    let engine = state.engine()?;
    let mut proxy = engine.proxy.lock().await;
    proxy.shutdown().await;
    Ok(proxy.status())
}

/// What the listener settings panel shows.
#[derive(Serialize)]
pub struct ListenerSettings {
    bind_address: &'static str,
    port: u16,
    default_port: u16,
    min_port: u32,
    max_port: u32,
    /// A test run pinned the port through the environment; the saved choice is not used.
    port_from_env: bool,
    log_dir: Option<String>,
}

async fn listener_settings(engine: &Engine) -> ListenerSettings {
    ListenerSettings {
        bind_address: BIND_IP,
        port: engine.proxy.lock().await.port(),
        default_port: DEFAULT_PROXY_PORT,
        min_port: settings::MIN_PORT,
        max_port: settings::MAX_PORT,
        port_from_env: engine.port_from_env,
        log_dir: engine.log_dir.as_ref().map(|d| d.display().to_string()),
    }
}

#[tauri::command]
pub async fn get_listener_settings(
    state: State<'_, EngineState>,
) -> Result<ListenerSettings, String> {
    Ok(listener_settings(state.engine()?).await)
}

/// Save a new listener port. Only while stopped, only 1024-65535, and only when the port is
/// free on 127.0.0.1 now; a busy port is reported, never taken from the program using it.
#[tauri::command]
pub async fn set_listener_port(
    state: State<'_, EngineState>,
    port: u32,
) -> Result<ListenerSettings, String> {
    let engine = state.engine()?;
    let port = settings::validate_port(port)?;
    {
        let mut proxy = engine.proxy.lock().await;
        if proxy.status().is_running {
            return Err("Stop the listener before changing its port.".into());
        }
        if port != proxy.port() {
            match std::net::TcpListener::bind((BIND_IP, port)) {
                Ok(probe) => drop(probe),
                Err(_) => {
                    tracing::warn!("Port {port} on {BIND_IP} is in use; setting not changed");
                    return Err(format!(
                        "Port {port} on {BIND_IP} is already in use by another program."
                    ));
                }
            }
        }
        let mut saved = engine
            .settings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        saved.proxy_port = port;
        settings::save(&engine.data_dir, &saved)?;
        *engine.settings.lock().unwrap_or_else(|e| e.into_inner()) = saved;
        proxy.set_port(port)?;
    }
    tracing::info!("Listener port set to {port}");
    Ok(listener_settings(engine).await)
}

/// At most one Replay request in flight; holds the way to cancel it.
#[derive(Default)]
pub struct ReplayState {
    inflight: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

const REPLAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const REPLAY_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Host of an absolute URL, for pin lookups.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host.split(':').next()?.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Browser preset and jar cookies for one outbound request, from the current settings. The jar
/// is filtered per host later by the replay/prepare layer.
///
/// A host with a live challenge pin overrides the chosen preset: the pinned User-Agent is the
/// one the clearance cookie is bound to, so reusing it is what makes Replay pass.
fn apply_config(
    engine: &crate::engine::Engine,
    host: Option<&str>,
) -> dropsuite_core::replay::ApplyConfig {
    let (preset, attach) = {
        let settings = engine.settings.lock().unwrap_or_else(|e| e.into_inner());
        (settings.header_preset, settings.cookie_jar)
    };
    let pin = host.and_then(|h| engine.storage.challenge_pin(h, now_secs()).ok().flatten());
    let cookies = if attach {
        let _ = engine.storage.purge_expired_cookies(now_secs());
        engine.storage.list_cookies().unwrap_or_default()
    } else {
        Vec::new()
    };
    dropsuite_core::replay::ApplyConfig {
        preset: if pin.is_some() {
            dropsuite_core::BrowserPreset::Edge
        } else {
            preset
        },
        cookies,
        attach_cookies: attach,
        force_preset: pin.is_some(),
        pin_user_agent: pin.map(|p| p.user_agent),
    }
}

/// Send one Replay request, only when the user clicks Send. Nothing is stored; the response
/// comes back sanitized like history. Only the method, destination, status and size are
/// logged.
#[tauri::command]
pub async fn send_replay(
    state: State<'_, EngineState>,
    replay: State<'_, ReplayState>,
    request: ReplayRequest,
) -> Result<ReplayResponse, ReplayError> {
    let engine = state.engine().map_err(|e| ReplayError::new("invalid", e))?;
    let own_listener = {
        let status = engine.proxy.lock().await.status();
        status
            .is_running
            .then(|| std::net::SocketAddr::from(([127, 0, 0, 1], status.port)))
    };
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    {
        let mut slot = replay.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Err(ReplayError::new(
                "busy",
                "A request is already being sent. Wait for it or cancel it.",
            ));
        }
        *slot = Some(cancel_tx);
    }
    let options = ReplayOptions {
        connect_timeout: REPLAY_CONNECT_TIMEOUT,
        response_timeout: REPLAY_RESPONSE_TIMEOUT,
        own_listener,
        tls_roots: Vec::new(),
        apply: apply_config(engine, host_of(request.url.trim()).as_deref()),
    };
    let result = tokio::select! {
        r = replay::send(&request, &options) => r,
        _ = cancel_rx => Err(ReplayError::new("cancelled", "Sending was cancelled. The server may still have received the request.")),
    };
    replay
        .inflight
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    match &result {
        Ok(r) => tracing::info!(
            "Replay {} to {}: {} ({} bytes, {} ms)",
            request.method.trim(),
            r.destination,
            r.status,
            r.total_bytes,
            r.duration_ms
        ),
        Err(e) => tracing::info!("Replay {} not completed: {}", request.method.trim(), e.kind),
    }
    result
}

#[tauri::command]
pub fn cancel_replay(replay: State<'_, ReplayState>) {
    if let Some(tx) = replay
        .inflight
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        let _ = tx.send(());
    }
}

#[derive(Serialize)]
pub struct HttpsSettings {
    pub ca_present: bool,
    pub fingerprint: Option<String>,
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
    pub key_protection: &'static str,
    pub cert_pem: Option<String>,
    pub allowlist: Vec<String>,
}

#[tauri::command]
pub async fn get_https_settings(state: State<'_, EngineState>) -> Result<HttpsSettings, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    let ca_status = proxy.https_status().unwrap_or(dropsuite_core::CaStatus {
        present: false,
        fingerprint: None,
        not_before_unix: None,
        not_after_unix: None,
        key_protection: "none",
        cert_pem: None,
    });
    let allowlist = engine
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .https_allowlist
        .clone();
    Ok(HttpsSettings {
        ca_present: ca_status.present,
        fingerprint: ca_status.fingerprint,
        not_before_unix: ca_status.not_before_unix,
        not_after_unix: ca_status.not_after_unix,
        key_protection: ca_status.key_protection,
        cert_pem: ca_status.cert_pem,
        allowlist,
    })
}

#[tauri::command]
pub async fn set_https_allowlist(
    state: State<'_, EngineState>,
    allowlist: Vec<String>,
) -> Result<HttpsSettings, String> {
    if allowlist.len() > 100 {
        return Err("Too many allowlist entries (maximum 100).".into());
    }
    let engine = state.engine()?;
    let parsed = dropsuite_core::InterceptAllowlist::from_user_entries(&allowlist)?;
    {
        let mut saved = engine
            .settings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        saved.https_allowlist = parsed.to_user_entries();
        settings::save(&engine.data_dir, &saved)?;
        *engine.settings.lock().unwrap_or_else(|e| e.into_inner()) = saved;
    }
    let proxy = engine.proxy.lock().await;
    proxy.set_https_allowlist(parsed);
    drop(proxy);
    get_https_settings(state).await
}

#[tauri::command]
pub async fn generate_ca_certificate(
    state: State<'_, EngineState>,
) -> Result<HttpsSettings, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy
        .load_or_generate_ca()
        .await
        .map_err(|e| e.to_string())?;
    drop(proxy);
    get_https_settings(state).await
}

#[tauri::command]
pub async fn remove_ca_certificate(state: State<'_, EngineState>) -> Result<HttpsSettings, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy.remove_ca().await.map_err(|e| e.to_string())?;
    drop(proxy);
    get_https_settings(state).await
}

#[tauri::command]
pub async fn export_ca_certificate(state: State<'_, EngineState>) -> Result<String, String> {
    let engine = state.engine()?;
    let cert_path = engine.data_dir.join("ca").join("root-ca.pem");
    std::fs::read_to_string(&cert_path)
        .map_err(|e| format!("Could not read root CA certificate (generate it first): {e}"))
}

#[tauri::command]
pub async fn get_intercept_status(
    state: State<'_, EngineState>,
) -> Result<dropsuite_core::interception::InterceptStatus, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.intercept().status().await)
}

#[tauri::command]
pub async fn set_intercept_enabled(
    state: State<'_, EngineState>,
    enabled: bool,
) -> Result<dropsuite_core::interception::InterceptStatus, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.intercept().set_enabled(enabled).await)
}

#[tauri::command]
pub async fn set_intercept_requests(
    state: State<'_, EngineState>,
    enabled: bool,
) -> Result<dropsuite_core::interception::InterceptStatus, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.intercept().set_intercept_requests(enabled).await)
}

#[tauri::command]
pub async fn set_intercept_responses(
    state: State<'_, EngineState>,
    enabled: bool,
) -> Result<dropsuite_core::interception::InterceptStatus, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.intercept().set_intercept_responses(enabled).await)
}

#[tauri::command]
pub async fn list_intercepted_messages(
    state: State<'_, EngineState>,
) -> Result<Vec<dropsuite_core::interception::InterceptedMessageSummary>, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.intercept().list_held().await)
}

#[tauri::command]
pub async fn forward_intercepted_message(
    state: State<'_, EngineState>,
    id: u64,
    modified_wire: Option<String>,
) -> Result<bool, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy
        .intercept()
        .resolve(
            id,
            dropsuite_core::interception::InterceptAction::Forward { modified_wire },
        )
        .await)
}

#[tauri::command]
pub async fn drop_intercepted_message(
    state: State<'_, EngineState>,
    id: u64,
) -> Result<bool, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy
        .intercept()
        .resolve(id, dropsuite_core::interception::InterceptAction::Drop)
        .await)
}

#[tauri::command]
pub async fn forward_all_intercepted(state: State<'_, EngineState>) -> Result<(), String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy
        .intercept()
        .resolve_all(dropsuite_core::interception::InterceptAction::Forward {
            modified_wire: None,
        })
        .await;
    Ok(())
}

#[tauri::command]
pub async fn drop_all_intercepted(state: State<'_, EngineState>) -> Result<(), String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy
        .intercept()
        .resolve_all(dropsuite_core::interception::InterceptAction::Drop)
        .await;
    Ok(())
}

#[tauri::command]
pub fn get_repeater_tabs(
    state: State<'_, EngineState>,
) -> Result<Vec<dropsuite_core::RepeaterTabRecord>, String> {
    let engine = state.engine()?;
    engine
        .storage
        .list_repeater_tabs()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_repeater_tab(
    state: State<'_, EngineState>,
    tab: dropsuite_core::RepeaterTabRecord,
) -> Result<i64, String> {
    let engine = state.engine()?;
    engine
        .storage
        .save_repeater_tab(&tab)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_repeater_tab(state: State<'_, EngineState>, id: i64) -> Result<(), String> {
    let engine = state.engine()?;
    engine
        .storage
        .delete_repeater_tab(id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_repeater_attempts(
    state: State<'_, EngineState>,
    tab_id: i64,
    limit: Option<usize>,
) -> Result<Vec<dropsuite_core::RepeaterAttemptRecord>, String> {
    let engine = state.engine()?;
    engine
        .storage
        .list_repeater_attempts(tab_id, limit)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_repeater_attempt(
    state: State<'_, EngineState>,
    attempt: dropsuite_core::RepeaterAttemptRecord,
) -> Result<i64, String> {
    let engine = state.engine()?;
    engine
        .storage
        .save_repeater_attempt(&attempt)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_repeater_attempts(state: State<'_, EngineState>, tab_id: i64) -> Result<(), String> {
    let engine = state.engine()?;
    engine
        .storage
        .clear_repeater_attempts(tab_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn export_history_har(state: State<'_, EngineState>, ids: Vec<i64>) -> Result<String, String> {
    let engine = state.engine()?;
    engine.storage.export_har(&ids).map_err(|e| e.to_string())
}

/// Delete all captured HTTP history. Also empties the site map and the passive scanner,
/// which read the same table. Repeater tabs and their attempts are kept. Irreversible.
#[tauri::command]
pub fn clear_history(state: State<'_, EngineState>) -> Result<usize, String> {
    let engine = state.engine()?;
    engine
        .storage
        .clear_transactions()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scope_config(
    state: State<'_, EngineState>,
) -> Result<dropsuite_core::ScopeConfig, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.scope().get_config())
}

#[tauri::command]
pub async fn set_scope_config(
    state: State<'_, EngineState>,
    config: dropsuite_core::ScopeConfig,
) -> Result<dropsuite_core::ScopeConfig, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy.scope().set_config(config.clone());
    Ok(config)
}

#[tauri::command]
pub async fn get_match_replace_config(
    state: State<'_, EngineState>,
) -> Result<dropsuite_core::MatchReplaceConfig, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    Ok(proxy.match_replace().get_config())
}

#[tauri::command]
pub async fn set_match_replace_config(
    state: State<'_, EngineState>,
    config: dropsuite_core::MatchReplaceConfig,
) -> Result<dropsuite_core::MatchReplaceConfig, String> {
    let engine = state.engine()?;
    let proxy = engine.proxy.lock().await;
    proxy.match_replace().set_config(config.clone());
    Ok(config)
}

#[tauri::command]
pub async fn get_sitemap(
    state: State<'_, EngineState>,
) -> Result<Vec<dropsuite_core::SiteNodeSummary>, String> {
    let engine = state.engine()?;
    let summaries = engine
        .storage
        .list_summaries(&dropsuite_core::HistoryFilter {
            limit: Some(2000),
            ..Default::default()
        })
        .map_err(|e| e.to_string())?;
    let proxy = engine.proxy.lock().await;
    Ok(dropsuite_core::build_sitemap(&summaries, &proxy.scope()))
}

#[derive(Serialize)]
pub struct ApplySettings {
    pub preset: dropsuite_core::BrowserPreset,
    pub cookie_jar: bool,
}

#[tauri::command]
pub fn get_apply_settings(state: State<'_, EngineState>) -> Result<ApplySettings, String> {
    let engine = state.engine()?;
    let settings = engine.settings.lock().unwrap_or_else(|e| e.into_inner());
    Ok(ApplySettings {
        preset: settings.header_preset,
        cookie_jar: settings.cookie_jar,
    })
}

#[tauri::command]
pub fn set_apply_settings(
    state: State<'_, EngineState>,
    preset: dropsuite_core::BrowserPreset,
    cookie_jar: bool,
) -> Result<ApplySettings, String> {
    let engine = state.engine()?;
    {
        let mut settings = engine.settings.lock().unwrap_or_else(|e| e.into_inner());
        settings.header_preset = preset;
        settings.cookie_jar = cookie_jar;
        settings::save(&engine.data_dir, &settings)?;
    }
    Ok(ApplySettings { preset, cookie_jar })
}

/// One jar row. The value is returned as stored so it can be edited or checked.
#[derive(Serialize)]
pub struct CookieRow {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub domain: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub expires_at: Option<i64>,
}

impl From<dropsuite_core::StoredCookie> for CookieRow {
    fn from(c: dropsuite_core::StoredCookie) -> Self {
        CookieRow {
            host: c.host,
            name: c.name,
            value: c.value,
            path: c.path,
            domain: c.domain,
            secure: c.secure,
            http_only: c.http_only,
            expires_at: c.expires_at,
        }
    }
}

#[tauri::command]
pub fn list_cookies(state: State<'_, EngineState>) -> Result<Vec<CookieRow>, String> {
    let engine = state.engine()?;
    let _ = engine.storage.purge_expired_cookies(now_secs());
    Ok(engine
        .storage
        .list_cookies()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(CookieRow::from)
        .collect())
}

/// Cookies in the jar that would be sent to `host` (domain/path are not checked here, so the
/// list also shows rows that exist but may not match a specific path).
#[tauri::command]
pub fn list_cookies_for_host(
    state: State<'_, EngineState>,
    host: String,
) -> Result<Vec<CookieRow>, String> {
    let engine = state.engine()?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Ok(Vec::new());
    }
    let _ = engine.storage.purge_expired_cookies(now_secs());
    Ok(engine
        .storage
        .cookies_for_host(&host)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(CookieRow::from)
        .collect())
}

/// Save a cookie typed or pasted for `host`. `raw` is `name=value` and may carry attributes
/// (`; Path=/`, `; Secure`, …), so a whole `cf_clearance=…` line from a browser can be pasted.
#[tauri::command]
pub fn save_cookie(
    state: State<'_, EngineState>,
    host: String,
    raw: String,
) -> Result<CookieRow, String> {
    let engine = state.engine()?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('/') || host.contains(' ') {
        return Err("Enter the destination host, for example api.example.com.".into());
    }
    let cookie = dropsuite_core::cookies::parse_set_cookie(&host, raw.trim(), now_secs())
        .ok_or_else(|| "That is not a storable cookie for this host. Check the name, the value and any Domain attribute.".to_string())?;
    engine
        .storage
        .upsert_cookie(&cookie)
        .map_err(|e| e.to_string())?;
    Ok(CookieRow::from(cookie))
}

#[tauri::command]
pub fn delete_cookie(
    state: State<'_, EngineState>,
    host: String,
    name: String,
    path: String,
) -> Result<(), String> {
    let engine = state.engine()?;
    engine
        .storage
        .delete_cookie(&host, &name, &path)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn clear_cookies(state: State<'_, EngineState>) -> Result<(), String> {
    let engine = state.engine()?;
    engine.storage.clear_cookies().map_err(|e| e.to_string())?;
    Ok(())
}

/// Open a browser window for a bot challenge.
///
/// The host is removed from the interception allowlist first, so the proxy tunnels its TLS
/// instead of terminating it: the page then keeps the WebView2 fingerprint, which is the whole
/// point. The allowlist is put back when the window closes. Use
/// [`import_challenge_cookies`] afterwards to move the answer into the jar.
#[tauri::command]
pub async fn open_challenge_browser(
    app: tauri::AppHandle,
    state: State<'_, EngineState>,
    url: String,
) -> Result<(), String> {
    let engine = state.engine()?;
    let parsed: url::Url = url
        .trim()
        .parse()
        .map_err(|e| format!("Invalid URL '{url}': {e}"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("Only http and https URLs can be opened.".into());
    }
    let host = parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "The URL has no host.".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let target = parsed.to_string();

    let (proxy_url, leaf_cache) = {
        let proxy = engine.proxy.lock().await;
        let status = proxy.status();
        if !status.is_running {
            return Err("Proxy listener is stopped. Please start the listener first.".into());
        }
        let proxy_url = url::Url::parse(&format!("http://127.0.0.1:{}", status.port))
            .map_err(|e| e.to_string())?;
        let cache = proxy
            .leaf_cache()
            .ok_or_else(|| "HTTPS interception is not configured".to_string())?;
        (proxy_url, cache)
    };

    let full_allowlist = {
        let settings = engine.settings.lock().unwrap_or_else(|e| e.into_inner());
        settings.https_allowlist.clone()
    };
    let tunneled: Vec<String> = full_allowlist
        .iter()
        .filter(|entry| {
            let name = entry.split(':').next().unwrap_or(entry);
            !name.trim().eq_ignore_ascii_case(&host)
                && !(name.trim().eq_ignore_ascii_case(&host) && port == 443)
        })
        .cloned()
        .collect();
    let list = dropsuite_core::InterceptAllowlist::from_user_entries(&tunneled)
        .unwrap_or_else(|_| dropsuite_core::InterceptAllowlist::loopback_default());
    engine.proxy.lock().await.set_https_allowlist(list);

    let base_dir = crate::engine::data_dir(&app)?;
    let browser_dir = base_dir.join("embedded-browser");
    let window = crate::platform::spawn_embedded_browser(
        &app,
        proxy_url,
        browser_dir,
        &target,
        leaf_cache,
        crate::platform::BrowserMode::Challenge,
    )
    .await?;

    // Put the entry back once the window is gone, so normal interception resumes.
    let restore_app = app.clone();
    let restore = full_allowlist.clone();
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            let Some(state) = restore_app.try_state::<EngineState>() else {
                return;
            };
            let Ok(engine) = state.engine() else { return };
            if let Ok(list) = dropsuite_core::InterceptAllowlist::from_user_entries(&restore) {
                // Short critical section, and this callback runs off the tokio workers.
                tauri::async_runtime::block_on(async {
                    engine.proxy.lock().await.set_https_allowlist(list);
                });
            }
        }
    });

    Ok(())
}

/// What an import actually collected, so the interface can name it instead of just counting.
#[derive(Serialize)]
pub struct ImportOutcome {
    pub imported: Vec<String>,
    /// Whether `cf_clearance` was among them; without it the challenge is usually still up.
    pub has_clearance: bool,
    /// Whether the window's User-Agent was recorded, so Replay can reproduce it.
    pub pinned: bool,
}

/// Copy the cookies of the open challenge window into the jar for `host`. The cookies come from
/// that window's own cookie store, read through WebView2's CookieManager.
#[tauri::command]
pub async fn import_challenge_cookies(
    app: tauri::AppHandle,
    state: State<'_, EngineState>,
    host: String,
) -> Result<ImportOutcome, String> {
    let engine = state.engine()?;
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("Enter the host whose challenge was solved.".into());
    }
    let window = app
        .webview_windows()
        .into_iter()
        .filter(|(label, _)| label.starts_with("challenge-browser-"))
        .max_by_key(|(label, _)| label.clone())
        .map(|(_, w)| w)
        .ok_or_else(|| "No challenge window is open. Open one first.".to_string())?;

    let harvested = crate::platform::harvest_cookies(&window, &format!("https://{host}/")).await?;
    let now = now_secs();
    let mut imported = Vec::new();
    for cookie in &harvested {
        let Some(raw) = crate::platform::harvested_to_set_cookie(cookie) else {
            continue;
        };
        let Some(parsed) = dropsuite_core::cookies::parse_set_cookie(&host, &raw, now) else {
            continue;
        };
        if engine.storage.upsert_cookie(&parsed).is_ok() {
            imported.push(parsed.name.clone());
        }
    }
    if imported.is_empty() {
        return Err(
            "The browser holds no cookie for that host yet. Finish the check in the window first."
                .into(),
        );
    }
    let has_clearance = imported
        .iter()
        .any(|n| n.eq_ignore_ascii_case("cf_clearance"));
    // The clearance is bound to the solving window User-Agent. Record it so Replay sends the
    // same value instead of the editor placeholder UA.
    let mut pinned = false;
    if has_clearance {
        if let Ok(ua) = crate::platform::window_user_agent(&window).await {
            if !ua.trim().is_empty() {
                let pin = dropsuite_core::storage::ChallengePin {
                    host: host.clone(),
                    user_agent: ua,
                    preset: "edge".to_string(),
                    expires_at: now + 3600,
                };
                pinned = engine.storage.upsert_challenge_pin(&pin).is_ok();
            }
        }
    }
    Ok(ImportOutcome {
        imported,
        has_clearance,
        pinned,
    })
}

#[tauri::command]
pub async fn open_embedded_browser(
    app: tauri::AppHandle,
    state: State<'_, EngineState>,
    url: Option<String>,
) -> Result<(), String> {
    let engine = state.engine()?;
    let (proxy_url, leaf_cache) = {
        let proxy = engine.proxy.lock().await;
        let status = proxy.status();
        if !status.is_running {
            return Err("Proxy listener is stopped. Please start the listener first.".into());
        }
        let url = url::Url::parse(&format!("http://127.0.0.1:{}", status.port))
            .map_err(|e| e.to_string())?;
        let cache = proxy
            .leaf_cache()
            .ok_or_else(|| "HTTPS interception is not configured".to_string())?;
        (url, cache)
    };

    let base_dir = crate::engine::data_dir(&app).map_err(|e| e.to_string())?;
    let browser_dir = base_dir.join("embedded-browser");

    let target_url = url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("https://lumens.my.id/");

    crate::platform::spawn_embedded_browser(
        &app,
        proxy_url,
        browser_dir,
        target_url,
        leaf_cache,
        crate::platform::BrowserMode::Intercept,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Intruder (Fuzzer)
//
// Automated fuzzing that runs entirely through `dropsuite-core::intruder`, which in turn sends
// only via the Replay path — so the destination guard (link-local, cloud metadata, …), timeouts
// and memory sanitation apply to every request. Scope is snapshotted at start so a long run never
// holds the proxy lock. Results are polled (like Intercept), not pushed, matching the app's IPC.
// ---------------------------------------------------------------------------------------------

/// One finished attempt, shaped for the interface. Response bodies are never kept.
#[derive(Clone, Serialize)]
pub struct AttemptRow {
    pub index: usize,
    pub replacements: Vec<String>,
    pub ok: bool,
    pub status: Option<u16>,
    pub total_bytes: Option<u64>,
    pub duration_ms: Option<u64>,
    pub destination: Option<String>,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,
}

impl From<AttemptOutcome> for AttemptRow {
    fn from(o: AttemptOutcome) -> Self {
        match o.result {
            Ok(s) => AttemptRow {
                index: o.index,
                replacements: o.replacements,
                ok: true,
                status: Some(s.status),
                total_bytes: Some(s.total_bytes),
                duration_ms: Some(s.duration_ms),
                destination: Some(s.destination),
                error_kind: None,
                error_message: None,
            },
            Err(e) => AttemptRow {
                index: o.index,
                replacements: o.replacements,
                ok: false,
                status: None,
                total_bytes: None,
                duration_ms: None,
                destination: None,
                error_kind: Some(e.kind.to_string()),
                error_message: Some(e.message),
            },
        }
    }
}

#[derive(Default)]
struct IntruderRun {
    running: bool,
    done: bool,
    planned: usize,
    scope_skipped: usize,
    results: Vec<AttemptRow>,
    cancel: Option<Arc<AtomicBool>>,
    error: Option<String>,
}

/// At most one attack in flight; holds its cancel flag and streamed results.
pub struct IntruderState {
    run: Arc<std::sync::Mutex<IntruderRun>>,
}

impl Default for IntruderState {
    fn default() -> Self {
        Self {
            run: Arc::new(std::sync::Mutex::new(IntruderRun::default())),
        }
    }
}

#[derive(Serialize)]
pub struct IntruderStatus {
    pub running: bool,
    pub done: bool,
    pub planned: usize,
    pub completed: usize,
    pub scope_skipped: usize,
    pub error: Option<String>,
}

/// Validate and start an attack. Returns the planned number of attempts; a bad config
/// (no positions, payload-set mismatch, or over the cap) is refused here, before anything runs.
#[tauri::command]
pub async fn start_intruder(
    state: State<'_, EngineState>,
    intruder_state: State<'_, IntruderState>,
    request: ReplayRequest,
    attack: Attack,
    max_concurrency: usize,
    delay_ms: u64,
    max_attempts: usize,
    encode_url: bool,
) -> Result<usize, String> {
    let engine = state.engine()?;
    let planned =
        intruder::planned_attempts(&request, &attack, max_attempts).map_err(|e| e.message)?;

    // Snapshot the listener address and the scope config, so the run does not hold the proxy lock.
    let (own_listener, scope_cfg) = {
        let proxy = engine.proxy.lock().await;
        let status = proxy.status();
        let own = status
            .is_running
            .then(|| std::net::SocketAddr::from(([127, 0, 0, 1], status.port)));
        (own, proxy.scope().get_config())
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let run_state = {
        let mut g = intruder_state.run.lock().unwrap_or_else(|e| e.into_inner());
        if g.running {
            return Err("An attack is already running. Cancel it first.".into());
        }
        *g = IntruderRun {
            running: true,
            cancel: Some(cancel.clone()),
            planned,
            ..Default::default()
        };
        intruder_state.run.clone()
    };

    let options = ReplayOptions {
        connect_timeout: REPLAY_CONNECT_TIMEOUT,
        response_timeout: REPLAY_RESPONSE_TIMEOUT,
        own_listener,
        tls_roots: Vec::new(),
        apply: apply_config(engine, host_of(request.url.trim()).as_deref()),
    };
    let guards = Guards {
        max_concurrency,
        delay_between: std::time::Duration::from_millis(delay_ms),
        max_attempts,
        encode_url,
    };

    tauri::async_runtime::spawn(async move {
        let scope = ScopeEngine::with_config(scope_cfg);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<AttemptOutcome>(256);
        let rs_drain = run_state.clone();
        let drain = async move {
            while let Some(o) = rx.recv().await {
                rs_drain
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .results
                    .push(AttemptRow::from(o));
            }
        };
        let runner = intruder::run(&request, &attack, options, &scope, &guards, cancel, tx);
        let (stats_res, _) = tokio::join!(runner, drain);

        let mut g = run_state.lock().unwrap_or_else(|e| e.into_inner());
        g.running = false;
        g.done = true;
        match stats_res {
            Ok(stats) => {
                g.scope_skipped = stats.scope_skipped;
                if stats.cancelled {
                    g.error = Some("cancelled".into());
                }
            }
            Err(e) => g.error = Some(e.message),
        }
        tracing::info!(
            "Intruder finished: {} planned, {} results, {} out-of-scope",
            g.planned,
            g.results.len(),
            g.scope_skipped
        );
    });

    Ok(planned)
}

/// Progress of the current (or last) attack.
#[tauri::command]
pub fn get_intruder_status(intruder_state: State<'_, IntruderState>) -> IntruderStatus {
    let g = intruder_state.run.lock().unwrap_or_else(|e| e.into_inner());
    IntruderStatus {
        running: g.running,
        done: g.done,
        planned: g.planned,
        completed: g.results.len(),
        scope_skipped: g.scope_skipped,
        error: g.error.clone(),
    }
}

/// A page of finished attempts, `[offset, offset+limit)`.
#[tauri::command]
pub fn list_intruder_results(
    intruder_state: State<'_, IntruderState>,
    offset: usize,
    limit: usize,
) -> Vec<AttemptRow> {
    let g = intruder_state.run.lock().unwrap_or_else(|e| e.into_inner());
    if offset >= g.results.len() {
        return Vec::new();
    }
    let end = offset.saturating_add(limit).min(g.results.len());
    g.results[offset..end].to_vec()
}

/// Ask the running attack to stop dispatching. In-flight requests finish on their own.
#[tauri::command]
pub fn cancel_intruder(intruder_state: State<'_, IntruderState>) {
    let g = intruder_state.run.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = &g.cancel {
        c.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------------------------
// Drop AI (BYOK)
//
// The user's own model + key. Non-secret config lives in settings.json; the key is DPAPI-protected
// (see dropai.rs). Calls go out through a dedicated reqwest client, never the proxy listener.
// Every call is explicit (a button in the UI) and the UI previews what will be sent first.
// ---------------------------------------------------------------------------------------------

#[tauri::command]
pub fn get_dropai_config(
    state: State<'_, EngineState>,
) -> Result<crate::dropai::DropAiStatus, String> {
    let engine = state.engine()?;
    let cfg = engine
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drop_ai
        .clone();
    Ok(crate::dropai::DropAiStatus::from(&cfg, &engine.data_dir))
}

#[tauri::command]
pub fn set_dropai_config(
    state: State<'_, EngineState>,
    config: crate::dropai::DropAiConfig,
) -> Result<crate::dropai::DropAiStatus, String> {
    let engine = state.engine()?;
    let mut saved = engine
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    saved.drop_ai = config;
    settings::save(&engine.data_dir, &saved)?;
    *engine.settings.lock().unwrap_or_else(|e| e.into_inner()) = saved.clone();
    Ok(crate::dropai::DropAiStatus::from(
        &saved.drop_ai,
        &engine.data_dir,
    ))
}

/// Store the API key, protected at rest. An empty string clears it.
#[tauri::command]
pub fn set_dropai_key(state: State<'_, EngineState>, key: String) -> Result<bool, String> {
    let engine = state.engine()?;
    crate::dropai::save_key(&engine.data_dir, &key)?;
    Ok(crate::dropai::has_key(&engine.data_dir))
}

#[tauri::command]
pub fn clear_dropai_key(state: State<'_, EngineState>) -> Result<(), String> {
    let engine = state.engine()?;
    crate::dropai::clear_key(&engine.data_dir)
}

/// Run one completion with the stored config + key. Returns the model's text.
#[tauri::command]
pub async fn dropai_complete(
    state: State<'_, EngineState>,
    system: String,
    user: String,
) -> Result<String, String> {
    let engine = state.engine()?;
    let cfg = engine
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drop_ai
        .clone();
    crate::dropai::complete(&cfg, &engine.data_dir, &system, &user).await
}

/// A tiny round-trip to confirm the endpoint, model and key work.
#[tauri::command]
pub async fn test_dropai(state: State<'_, EngineState>) -> Result<String, String> {
    let engine = state.engine()?;
    let cfg = engine
        .settings
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drop_ai
        .clone();
    crate::dropai::test(&cfg, &engine.data_dir).await
}

/// List the models the configured endpoint exposes, so the UI can offer a pick list.
/// Uses the config passed from the panel (so unsaved edits work) plus the stored key.
#[tauri::command]
pub async fn list_dropai_models(
    state: State<'_, EngineState>,
    config: crate::dropai::DropAiConfig,
) -> Result<Vec<String>, String> {
    let engine = state.engine()?;
    crate::dropai::list_models(&config, &engine.data_dir).await
}

#[derive(Serialize)]
pub struct AppInfo {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub data_dir: String,
    pub logs_dir: String,
}

/// Version, platform and the app's own local folders, for the About panel.
#[tauri::command]
pub fn get_app_info(app: tauri::AppHandle) -> Result<AppInfo, String> {
    let data_dir = crate::engine::data_dir(&app)?;
    let logs_dir = data_dir.join("logs");
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        data_dir: data_dir.display().to_string(),
        logs_dir: logs_dir.display().to_string(),
    })
}

/// Open one of the app's own folders in the system file manager. The UI names the folder by role
/// ("data" or "logs") and the path is resolved here, so the frontend can never open an arbitrary
/// location.
#[tauri::command]
pub fn open_app_folder(app: tauri::AppHandle, which: String) -> Result<(), String> {
    let data_dir = crate::engine::data_dir(&app)?;
    let path = match which.as_str() {
        "data" => data_dir,
        "logs" => data_dir.join("logs"),
        other => return Err(format!("unknown folder: {other}")),
    };
    std::fs::create_dir_all(&path)
        .map_err(|e| format!("could not create {}: {e}", path.display()))?;
    #[cfg(windows)]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("could not open the folder: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("opening a folder is only supported on Windows.".into())
    }
}
