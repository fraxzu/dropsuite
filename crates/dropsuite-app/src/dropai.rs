//! Drop AI (BYOK) — the user brings their own model and API key.
//!
//! - Two provider shapes cover almost every endpoint on the market: OpenAI-compatible
//!   (`POST {base}/chat/completions`, `Authorization: Bearer`) and Anthropic-compatible
//!   (`POST {base}/v1/messages`, `x-api-key` + `anthropic-version`).
//! - The API key is **DPAPI-protected on disk** (Windows) or a `0600` file (unix), exactly like
//!   the root CA key. It is never written to logs, history, or snapshots, and never leaves the
//!   machine except in the Authorization/x-api-key header of the call the user explicitly made.
//! - AI calls go out through a **dedicated reqwest client**, never the proxy listener — just like
//!   Replay sends directly. There is no DropSuite server in the middle.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const KEY_FILE: &str = "drop-ai.key.dpapi";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
/// A connectivity test should fail fast, not wait as long as a real completion.
const TEST_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    OpenAiCompatible,
    AnthropicCompatible,
}

#[allow(clippy::derivable_impls)]
impl Default for Provider {
    fn default() -> Self {
        Provider::OpenAiCompatible
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DropAiConfig {
    pub provider: Provider,
    /// Base URL without the operation path, e.g. `https://api.openai.com/v1`,
    /// `http://localhost:11434/v1` (Ollama), or `https://api.anthropic.com`.
    pub base_url: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
}

impl Default for DropAiConfig {
    fn default() -> Self {
        DropAiConfig {
            provider: Provider::OpenAiCompatible,
            base_url: "https://api.openai.com/v1".into(),
            model: "gpt-4o-mini".into(),
            temperature: 0.2,
            max_tokens: 1024,
        }
    }
}

/// What the Settings UI shows. Never carries the key itself.
#[derive(Debug, Clone, Serialize)]
pub struct DropAiStatus {
    pub provider: Provider,
    pub base_url: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub has_key: bool,
    pub key_protection: &'static str,
}

impl DropAiStatus {
    pub fn from(cfg: &DropAiConfig, dir: &Path) -> Self {
        DropAiStatus {
            provider: cfg.provider,
            base_url: cfg.base_url.clone(),
            model: cfg.model.clone(),
            temperature: cfg.temperature,
            max_tokens: cfg.max_tokens,
            has_key: has_key(dir),
            key_protection: key_protection(),
        }
    }
}

pub fn key_protection() -> &'static str {
    if cfg!(windows) {
        "Windows DPAPI (current user)"
    } else {
        "file permissions (0600)"
    }
}

pub fn has_key(dir: &Path) -> bool {
    key_path(dir).exists()
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILE)
}

/// Store the key, protected at rest. An empty key clears it instead.
pub fn save_key(dir: &Path, key: &str) -> Result<(), String> {
    if key.trim().is_empty() {
        return clear_key(dir);
    }
    let blob = protect(key.as_bytes()).map_err(|e| format!("Could not protect the key: {e}"))?;
    let path = key_path(dir);
    std::fs::write(&path, &blob).map_err(|e| format!("Could not write the key: {e}"))?;
    set_restrictive_perms(&path);
    Ok(())
}

pub fn clear_key(dir: &Path) -> Result<(), String> {
    let path = key_path(dir);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("Could not remove the key: {e}"))?;
    }
    Ok(())
}

/// Read the key back. Used only to make a call; never returned to the interface.
fn load_key(dir: &Path) -> Result<String, String> {
    let path = key_path(dir);
    if !path.exists() {
        return Err("No Drop AI key is stored. Add one in Settings.".into());
    }
    let blob = std::fs::read(&path).map_err(|e| format!("Could not read the key: {e}"))?;
    let plain = unprotect(&blob).map_err(|e| format!("Could not unprotect the key: {e}"))?;
    String::from_utf8(plain).map_err(|_| "Stored key is not valid UTF-8.".into())
}

/// Run one completion with the stored key. `system` and `user` are the two prompt parts.
pub async fn complete(
    cfg: &DropAiConfig,
    dir: &Path,
    system: &str,
    user: &str,
) -> Result<String, String> {
    complete_inner(cfg, dir, system, user, cfg.max_tokens, REQUEST_TIMEOUT).await
}

/// A quick connectivity check: short reply, low token cap, short timeout, so it returns fast
/// instead of waiting as long as a real completion.
pub async fn test(cfg: &DropAiConfig, dir: &Path) -> Result<String, String> {
    complete_inner(
        cfg,
        dir,
        "You are a connectivity check for DropSuite.",
        "Reply with the single word: OK",
        256,
        TEST_TIMEOUT,
    )
    .await
}

async fn complete_inner(
    cfg: &DropAiConfig,
    dir: &Path,
    system: &str,
    user: &str,
    max_tokens: u32,
    timeout: Duration,
) -> Result<String, String> {
    let key = load_key(dir)?;
    let base = cfg.base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Set a base URL in Settings.".into());
    }
    if cfg.model.trim().is_empty() {
        return Err("Set a model in Settings.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("Could not create HTTP client: {e}"))?;

    match cfg.provider {
        Provider::OpenAiCompatible => {
            openai_complete(&client, base, &key, cfg, system, user, max_tokens).await
        }
        Provider::AnthropicCompatible => {
            anthropic_complete(&client, base, &key, cfg, system, user, max_tokens).await
        }
    }
}

/// List the model ids the endpoint exposes, so the UI can offer a pick list instead of free text.
/// OpenAI-compatible: `GET {base}/models`. Anthropic-compatible: `GET {base}/v1/models`.
pub async fn list_models(cfg: &DropAiConfig, dir: &Path) -> Result<Vec<String>, String> {
    let key = load_key(dir)?;
    let base = cfg.base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("Set a base URL in Settings.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("Could not create HTTP client: {e}"))?;

    let req = match cfg.provider {
        Provider::OpenAiCompatible => client.get(format!("{base}/models")).bearer_auth(&key),
        Provider::AnthropicCompatible => client
            .get(format!("{base}/v1/models"))
            .header("x-api-key", &key)
            .header("anthropic-version", ANTHROPIC_VERSION),
    };
    let value = response_json(req.send().await.map_err(net_error)?).await?;

    // Accept the common shapes: {data:[{id}]}, {models:[{id|name}]}, or a bare array of strings.
    let mut ids: Vec<String> = Vec::new();
    let arr = value
        .get("data")
        .or_else(|| value.get("models"))
        .or(Some(&value))
        .and_then(|v| v.as_array());
    if let Some(items) = arr {
        for it in items {
            if let Some(s) = it.as_str() {
                ids.push(s.to_string());
            } else if let Some(s) = it.get("id").and_then(|v| v.as_str()) {
                ids.push(s.to_string());
            } else if let Some(s) = it.get("name").and_then(|v| v.as_str()) {
                ids.push(s.to_string());
            }
        }
    }
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err("The endpoint returned no models.".into());
    }
    Ok(ids)
}

async fn openai_complete(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    cfg: &DropAiConfig,
    system: &str,
    user: &str,
    max_tokens: u32,
) -> Result<String, String> {
    let body = serde_json::json!({
        "model": cfg.model,
        "temperature": cfg.temperature,
        "max_tokens": max_tokens,
        "stream": false,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user },
        ],
    });
    let resp = client
        .post(format!("{base}/chat/completions"))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .map_err(net_error)?;
    extract_openai(&response_body(resp).await?)
}

async fn anthropic_complete(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    cfg: &DropAiConfig,
    system: &str,
    user: &str,
    max_tokens: u32,
) -> Result<String, String> {
    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": max_tokens,
        "temperature": cfg.temperature,
        "stream": false,
        "system": system,
        "messages": [ { "role": "user", "content": user } ],
    });
    let resp = client
        .post(format!("{base}/v1/messages"))
        .header("x-api-key", key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .json(&body)
        .send()
        .await
        .map_err(net_error)?;
    extract_anthropic(&response_body(resp).await?)
}

fn net_error(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "The model endpoint timed out.".into()
    } else if e.is_connect() {
        "Could not connect to the model endpoint. Check the base URL.".into()
    } else {
        format!("Request to the model failed: {e}")
    }
}

/// Check status (readable error on non-2xx) and return the body text. The error carries the
/// status and a short snippet (the provider's error message), never the request, so the key
/// cannot leak here.
async fn response_body(resp: reqwest::Response) -> Result<String, String> {
    let status = resp.status();
    let text = resp.text().await.map_err(net_error)?;
    if !status.is_success() {
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.pointer("/error/message")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| text.chars().take(300).collect());
        return Err(match status.as_u16() {
            401 | 403 => format!("The endpoint rejected the key ({status}). {detail}"),
            404 => format!(
                "Endpoint or model not found ({status}). Check the base URL and model. {detail}"
            ),
            429 => format!("Rate limited by the endpoint ({status}). {detail}"),
            _ => format!("The endpoint returned {status}. {detail}"),
        });
    }
    Ok(text)
}

/// Parse a 2xx body as a single JSON value (used for the models list).
async fn response_json(resp: reqwest::Response) -> Result<serde_json::Value, String> {
    let text = response_body(resp).await?;
    serde_json::from_str(&text).map_err(|_| unparsable(&text))
}

fn unparsable(text: &str) -> String {
    let snippet: String = text.trim().chars().take(140).collect();
    format!("Could not parse the model's reply. It was not JSON. Starts with: {snippet:?}")
}

/// `data:` payloads from a Server-Sent-Events body (some proxies stream even when asked not to).
fn sse_data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|l| l.strip_prefix("data:").map(|d| d.trim()))
}

/// The model answered but we found no usable text. Include a raw snippet so an unusual response
/// shape (where the text actually sits) can be diagnosed without the key.
fn no_text(text: &str) -> String {
    let snippet: String = text.trim().chars().take(260).collect();
    format!(
        "The model replied but with no text. Reasoning models often spend their whole budget thinking: raise Max tokens, or pick a non-reasoning model. Raw reply: {snippet:?}"
    )
}

/// Text out of a `content` field that may be a plain string or an array of parts
/// (`[{type:"text", text:"..."}]` or `["..."]`).
fn join_content(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Array(parts) => {
            let mut out = String::new();
            for p in parts {
                if let Some(s) = p.as_str() {
                    out.push_str(s);
                } else if let Some(s) = p.get("text").and_then(|t| t.as_str()) {
                    out.push_str(s);
                }
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

/// Pull the assistant text from an OpenAI-style reply: a single JSON object (content may be a
/// string or an array of parts), or an SSE stream of `choices[].delta.content` chunks.
fn extract_openai(text: &str) -> Result<String, String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(choice) = v.pointer("/choices/0") {
            if let Some(t) = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(join_content)
            {
                return Ok(t);
            }
            if let Some(t) = choice
                .get("text")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
            {
                return Ok(t.to_string());
            }
            if choice.get("finish_reason").and_then(|r| r.as_str()) == Some("length") {
                return Err("The model hit the Max tokens limit before producing an answer. Raise Max tokens in Drop AI settings.".into());
            }
        }
        return Err(no_text(text));
    }
    let mut out = String::new();
    let mut had_data = false;
    for data in sse_data_lines(text) {
        had_data = true;
        if data == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(c) = v
                .pointer("/choices/0/delta/content")
                .or_else(|| v.pointer("/choices/0/message/content"))
                .and_then(join_content)
            {
                out.push_str(&c);
            }
        }
    }
    match (out.is_empty(), had_data) {
        (false, _) => Ok(out),
        (true, true) => Err(no_text(text)),
        (true, false) => Err(unparsable(text)),
    }
}

/// Same for an Anthropic-style reply: a single JSON object, or SSE `content_block_delta` events.
fn extract_anthropic(text: &str) -> Result<String, String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(t) = v.get("content").and_then(join_content) {
            return Ok(t);
        }
        if v.get("stop_reason").and_then(|r| r.as_str()) == Some("max_tokens") {
            return Err("The model hit the Max tokens limit before producing an answer. Raise Max tokens in Drop AI settings.".into());
        }
        return Err(no_text(text));
    }
    let mut out = String::new();
    let mut had_data = false;
    for data in sse_data_lines(text) {
        had_data = true;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(s) = v.pointer("/delta/text").and_then(|v| v.as_str()) {
                out.push_str(s);
            }
        }
    }
    match (out.is_empty(), had_data) {
        (false, _) => Ok(out),
        (true, true) => Err(no_text(text)),
        (true, false) => Err(unparsable(text)),
    }
}

// ---- key protection at rest -----------------------------------------------------------------

#[cfg(windows)]
fn set_restrictive_perms(_path: &Path) {}

#[cfg(unix)]
fn set_restrictive_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(windows)]
fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi::protect(plain)
}
#[cfg(windows)]
fn unprotect(blob: &[u8]) -> std::io::Result<Vec<u8>> {
    dpapi::unprotect(blob)
}

// On non-Windows there is no DPAPI; store the bytes as-is behind 0600 permissions. The protection
// label reflects this so the UI is honest about it.
#[cfg(not(windows))]
fn protect(plain: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(plain.to_vec())
}
#[cfg(not(windows))]
fn unprotect(blob: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(blob.to_vec())
}

#[cfg(windows)]
mod dpapi {
    use std::io;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(result)
    }

    pub fn unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_anthropic, extract_openai};

    #[test]
    fn openai_string_content() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"hello world"},"finish_reason":"stop"}]}"#;
        assert_eq!(extract_openai(body).unwrap(), "hello world");
    }

    #[test]
    fn openai_array_content() {
        // Gemini/9Router-style: content is an array of parts.
        let body = r#"{"choices":[{"message":{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]},"finish_reason":"stop"}]}"#;
        assert_eq!(extract_openai(body).unwrap(), "ab");
    }

    #[test]
    fn openai_empty_due_to_length() {
        let body = r#"{"choices":[{"message":{"content":""},"finish_reason":"length"}]}"#;
        assert!(extract_openai(body).unwrap_err().contains("Max tokens"));
    }

    #[test]
    fn openai_reasoning_no_text() {
        // Reasoning model that finished normally but left content empty.
        let body = r#"{"choices":[{"message":{"content":null,"reasoning_content":"thinking..."},"finish_reason":"stop"}]}"#;
        assert!(extract_openai(body).unwrap_err().contains("no text"));
    }

    #[test]
    fn openai_sse_stream() {
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\ndata: [DONE]\n\n";
        assert_eq!(extract_openai(body).unwrap(), "OK!");
    }

    #[test]
    fn anthropic_single_and_stream() {
        let single = r#"{"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}"#;
        assert_eq!(extract_anthropic(single).unwrap(), "hi");
        let sse = "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"he\"}}\n\ndata: {\"delta\":{\"text\":\"llo\"}}\n\n";
        assert_eq!(extract_anthropic(sse).unwrap(), "hello");
    }

    #[test]
    fn non_json_is_unparsable() {
        assert!(extract_openai("<html>502</html>")
            .unwrap_err()
            .contains("not JSON"));
    }
}
