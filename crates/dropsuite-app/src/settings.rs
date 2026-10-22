//! User settings, persisted as `settings.json` in the app data folder. A missing or unreadable
//! file falls back to the defaults, so a bad file can never stop the app from starting.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::DEFAULT_PROXY_PORT;

/// Lowest port the listener may use. Ports below 1024 need elevated rights on Linux and macOS,
/// so they are refused everywhere to keep the setting portable.
pub const MIN_PORT: u32 = 1024;
pub const MAX_PORT: u32 = 65535;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub proxy_port: u16,
    pub https_allowlist: Vec<String>,
    /// Browser header set added to Replay and Intruder requests.
    pub header_preset: dropsuite_core::BrowserPreset,
    /// Attach jar cookies to Replay and Intruder requests.
    pub cookie_jar: bool,
    /// Drop AI (BYOK) non-secret config. The API key lives in a DPAPI-protected file, not here.
    pub drop_ai: crate::dropai::DropAiConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            proxy_port: DEFAULT_PROXY_PORT,
            https_allowlist: dropsuite_core::InterceptAllowlist::loopback_default().to_user_entries(),
            header_preset: dropsuite_core::BrowserPreset::Off,
            cookie_jar: true,
            drop_ai: crate::dropai::DropAiConfig::default(),
        }
    }
}

fn path(dir: &Path) -> PathBuf {
    dir.join("settings.json")
}

pub fn load(dir: &Path) -> Settings {
    let file = path(dir);
    match std::fs::read(&file) {
        Ok(bytes) => match serde_json::from_slice::<Settings>(&bytes) {
            Ok(mut s) if validate_port(s.proxy_port as u32).is_ok() => {
                if dropsuite_core::InterceptAllowlist::from_user_entries(&s.https_allowlist).is_err() {
                    s.https_allowlist = dropsuite_core::InterceptAllowlist::loopback_default().to_user_entries();
                }
                s
            }
            _ => {
                tracing::warn!("Ignoring unreadable settings file; using defaults");
                Settings::default()
            }
        },
        Err(_) => Settings::default(),
    }
}

/// Write through a temporary file and rename, so a crash never leaves a half-written file.
pub fn save(dir: &Path, settings: &Settings) -> Result<(), String> {
    let file = path(dir);
    let tmp = dir.join("settings.json.tmp");
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json)
        .and_then(|_| std::fs::rename(&tmp, &file))
        .map_err(|e| format!("Could not save settings: {e}"))
}

pub fn validate_port(port: u32) -> Result<u16, String> {
    if (MIN_PORT..=MAX_PORT).contains(&port) {
        Ok(port as u16)
    } else {
        Err(format!("Choose a port from {MIN_PORT} to {MAX_PORT}."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_validated() {
        assert_eq!(validate_port(8080), Ok(8080));
        assert_eq!(validate_port(1024), Ok(1024));
        assert_eq!(validate_port(65535), Ok(65535));
        for bad in [0, 80, 1023, 65536, 100_000] {
            assert!(validate_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_round_trip_and_bad_files_fall_back() {
        let dir = std::env::temp_dir().join(format!("dropsuite-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load(&dir).proxy_port, DEFAULT_PROXY_PORT, "missing file");
        save(&dir, &Settings { proxy_port: 18555, ..Default::default() }).unwrap();
        assert_eq!(load(&dir).proxy_port, 18555);
        std::fs::write(path(&dir), b"{not json").unwrap();
        assert_eq!(load(&dir).proxy_port, DEFAULT_PROXY_PORT, "corrupt file");
        std::fs::write(path(&dir), br#"{"proxy_port": 80}"#).unwrap();
        assert_eq!(
            load(&dir).proxy_port,
            DEFAULT_PROXY_PORT,
            "out-of-range port"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
