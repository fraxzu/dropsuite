//! The in-process capture engine owned by the desktop app: one history database in the
//! OS application-data directory and one proxy listener, both released on exit.

use std::path::PathBuf;

use dropsuite_core::{ProxyEngine, StorageManager};
use tauri::{AppHandle, Manager};
use tokio::sync::Mutex;

use crate::settings::{self, Settings};

/// Loopback only. The listener never binds a public interface by default.
pub const BIND_IP: &str = "127.0.0.1";
pub const DEFAULT_PROXY_PORT: u16 = 8080;

pub struct Engine {
    pub storage: StorageManager,
    pub proxy: Mutex<ProxyEngine>,
    pub data_dir: PathBuf,
    pub log_dir: Option<PathBuf>,
    pub settings: std::sync::Mutex<Settings>,
    /// `DROPSUITE_PROXY_PORT` is set: test runs pin the port, and the saved setting is ignored.
    pub port_from_env: bool,
}

/// The engine, or the reason it could not start. The window still opens on failure so the
/// interface can explain the problem instead of the app vanishing.
pub struct EngineState(pub Result<Engine, String>);

impl EngineState {
    pub fn open(dir: Result<PathBuf, String>, log_dir: Option<PathBuf>) -> Self {
        EngineState(dir.and_then(|dir| Engine::open(dir, log_dir)))
    }

    pub fn engine(&self) -> Result<&Engine, String> {
        self.0.as_ref().map_err(Clone::clone)
    }
}

impl Engine {
    fn open(dir: PathBuf, log_dir: Option<PathBuf>) -> Result<Engine, String> {
        let db_path = dir.join("dropsuite.db");
        let storage = StorageManager::new(&db_path).map_err(|e| {
            format!(
                "Could not open the history database {}: {e}",
                db_path.display()
            )
        })?;
        let settings = settings::load(&dir);
        let env_port = env_proxy_port();
        let port = env_port.unwrap_or(settings.proxy_port);
        let mut proxy = ProxyEngine::new(BIND_IP, port, storage.clone());
        let allowlist =
            dropsuite_core::InterceptAllowlist::from_user_entries(&settings.https_allowlist)
                .unwrap_or_else(|_| dropsuite_core::InterceptAllowlist::loopback_default());
        let https_cfg = dropsuite_core::HttpsInterceptConfig {
            ca_dir: dir.join("ca"),
            allowlist,
            upstream_roots: Vec::new(),
        };
        proxy.set_https_interception(https_cfg);
        tracing::info!("History database opened; listener port {port} (capture off until started)");
        Ok(Engine {
            storage,
            proxy: Mutex::new(proxy),
            data_dir: dir,
            log_dir,
            settings: std::sync::Mutex::new(settings),
            port_from_env: env_port.is_some(),
        })
    }
}

/// The OS application-data directory for this app (from the bundle identifier), created if
/// needed: Windows `%APPDATA%\com.dropsuite.desktop`, Linux `~/.local/share/com.dropsuite.desktop`,
/// macOS `~/Library/Application Support/com.dropsuite.desktop`.
/// `DROPSUITE_DATA_DIR` overrides it for isolated test runs.
pub fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = match std::env::var_os("DROPSUITE_DATA_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => app
            .path()
            .app_data_dir()
            .map_err(|e| format!("Could not resolve the application data folder: {e}"))?,
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Could not create the data folder {}: {e}", dir.display()))?;
    Ok(dir)
}

/// `DROPSUITE_PROXY_PORT` overrides the listener port for isolated test runs.
fn env_proxy_port() -> Option<u16> {
    std::env::var("DROPSUITE_PROXY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
}

/// Orderly exit: close the listener (releasing its port) and fold the WAL into the database.
pub fn shutdown(app: &AppHandle) {
    let Some(state) = app.try_state::<EngineState>() else {
        return;
    };
    if let Ok(engine) = &state.0 {
        tauri::async_runtime::block_on(async {
            engine.proxy.lock().await.shutdown().await;
        });
        if let Err(e) = engine.storage.checkpoint() {
            tracing::warn!("WAL checkpoint on exit failed: {e}");
        }
        tracing::info!("Capture engine shut down.");
    }
}
