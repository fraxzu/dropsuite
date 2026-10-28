//! OS-specific integration. Everything platform-dependent lives here behind `cfg`, so the
//! rest of the app stays portable; on other platforms these functions are no-ops.

/// Give the window crisp icons at its current DPI.
///
/// Windows: Tauri's default window icon is one bitmap at the 96-DPI large-icon size, set only
/// as the window's small icon. Windows then resamples that single bitmap for every size it
/// draws (24 px small icons and 48 px large icons at 150 %), which shows as jagged icons in
/// Task Manager, Alt+Tab and the title bar. Loading each slot from the executable's multi-size
/// icon resource at the exact size for the window's DPI lets Windows use a native ICO entry.
#[cfg(windows)]
pub fn apply_window_icons(window: &tauri::WebviewWindow) {
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DestroyIcon, LoadImageW, SendMessageW, HICON, ICON_BIG, ICON_SMALL, IMAGE_ICON,
        LR_DEFAULTCOLOR, SM_CXICON, SM_CXSMICON, WM_SETICON,
    };

    /// Resource ID under which tauri-build embeds the app icon (`icons/icon.ico`).
    const APP_ICON_RESOURCE_ID: u16 = 32512;
    /// Icons this function loaded earlier, freed once replaced (as raw addresses).
    static LOADED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    let Ok(hwnd) = window.hwnd() else {
        return;
    };
    let hwnd = hwnd.0 as HWND;
    let mut loaded = Vec::new();
    unsafe {
        let dpi = GetDpiForWindow(hwnd);
        let module = GetModuleHandleW(std::ptr::null());
        for (slot, metric) in [(ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)] {
            let size = GetSystemMetricsForDpi(metric, dpi);
            let icon: HICON = LoadImageW(
                module,
                APP_ICON_RESOURCE_ID as usize as *const u16,
                IMAGE_ICON,
                size,
                size,
                LR_DEFAULTCOLOR,
            );
            if !icon.is_null() {
                SendMessageW(hwnd, WM_SETICON, slot as usize, icon as isize);
                loaded.push(icon as usize);
            }
        }
        let mut previous = LOADED.lock().unwrap_or_else(|e| e.into_inner());
        for old in previous.drain(..) {
            DestroyIcon(old as HICON);
        }
        *previous = loaded;
    }
}

#[cfg(not(windows))]
pub fn apply_window_icons(_window: &tauri::WebviewWindow) {}

/// The window's normal (restored) outer rectangle as `(x, y, width, height)` in physical pixels,
/// also while it is maximized. Windows reports it in workspace coordinates.
#[cfg(windows)]
pub fn normal_rect(window: &tauri::WebviewWindow) -> Option<(i32, i32, u32, u32)> {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowPlacement, WINDOWPLACEMENT};

    let hwnd = window.hwnd().ok()?.0 as HWND;
    // SAFETY: a zeroed WINDOWPLACEMENT with its length set is what GetWindowPlacement expects.
    let mut placement: WINDOWPLACEMENT = unsafe { std::mem::zeroed() };
    placement.length = std::mem::size_of::<WINDOWPLACEMENT>() as u32;
    if unsafe { GetWindowPlacement(hwnd, &mut placement) } == 0 {
        return None;
    }
    let r = placement.rcNormalPosition;
    Some((
        r.left,
        r.top,
        (r.right - r.left).max(0) as u32,
        (r.bottom - r.top).max(0) as u32,
    ))
}

#[cfg(not(windows))]
pub fn normal_rect(_window: &tauri::WebviewWindow) -> Option<(i32, i32, u32, u32)> {
    None
}

#[cfg(any(windows, target_os = "linux"))]
static BROWSER_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Why the embedded browser was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMode {
    /// Browsing while the host is intercepted; DropSuite-minted leaves are trusted.
    Intercept,
    /// Bot-challenge work. The host is expected to be tunneled, so the page keeps the WebView2
    /// TLS fingerprint and the check can actually pass. Cookies are harvested afterwards.
    Challenge,
}

impl BrowserMode {
    fn label_prefix(self) -> &'static str {
        match self {
            BrowserMode::Intercept => "embedded-browser",
            BrowserMode::Challenge => "challenge-browser",
        }
    }

    fn title(self) -> &'static str {
        match self {
            BrowserMode::Intercept => "DropSuite Browser (Proxy Active)",
            BrowserMode::Challenge => "DropSuite Challenge Browser (tunneled)",
        }
    }
}

/// Spawns an isolated embedded browser window connected to the DropSuite proxy.
#[cfg(windows)]
pub async fn spawn_embedded_browser(
    app: &tauri::AppHandle,
    proxy_url: url::Url,
    data_dir: std::path::PathBuf,
    target_url: &str,
    leaf_cache: std::sync::Arc<std::sync::RwLock<dropsuite_core::LeafCache>>,
    mode: BrowserMode,
) -> Result<tauri::WebviewWindow, String> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

    // 1. Strict URL validation: only http/https allowed
    let parsed_url: url::Url = target_url
        .parse()
        .map_err(|e| format!("Invalid URL '{target_url}': {e}"))?;

    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(format!(
            "Invalid URL scheme '{}'. Only 'http' and 'https' are allowed.",
            parsed_url.scheme()
        ));
    }
    let navigate_target = parsed_url.to_string();

    // 2. Cleanly close any previous embedded browser windows
    for (label, window) in app.webview_windows() {
        if label.starts_with("embedded-browser") || label.starts_with("challenge-browser") {
            let _ = window.close();
        }
    }

    // 3. Generate unique monotonic label to prevent window creation race
    let window_label = format!(
        "{}-{}",
        mode.label_prefix(),
        BROWSER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );

    // 4. Build window starting at "about:blank" to prevent any network request or cert check
    // before the ServerCertificateErrorDetected event handler is fully attached.
    tracing::info!(
        "Spawning embedded browser: target='{navigate_target}', proxy='{proxy_url}', data_dir='{}'",
        data_dir.display()
    );
    let blank_url: url::Url = "about:blank".parse().unwrap();
    let builder = WebviewWindowBuilder::new(app, &window_label, WebviewUrl::External(blank_url))
        .title(mode.title())
        .inner_size(1200.0, 800.0)
        .proxy_url(proxy_url)
        .data_directory(data_dir.clone());

    let _ = std::fs::create_dir_all(&data_dir);

    // On Windows, Microsoft Edge WebView2 checks the WEBVIEW2_USER_DATA_FOLDER environment variable
    // before honoring the userDataFolder parameter passed to CreateCoreWebView2EnvironmentWithOptions.
    // If the process has WEBVIEW2_USER_DATA_FOLDER set (e.g. from main.rs pointing to the main app's webview),
    // WebView2 overrides the data_directory parameter and attempts to reuse the main app's folder with
    // conflicting proxy arguments, throwing HRESULT(0x8007139F) (ERROR_INVALID_STATE).
    // We explicitly set WEBVIEW2_USER_DATA_FOLDER to data_dir for this window creation, then restore the previous value.
    let prev_env = std::env::var_os("WEBVIEW2_USER_DATA_FOLDER");
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &data_dir);
    let window_res = builder.build();
    if let Some(prev) = prev_env {
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", prev);
    } else {
        std::env::remove_var("WEBVIEW2_USER_DATA_FOLDER");
    }

    let window =
        window_res.map_err(|e| format!("Failed to create embedded browser window: {e}"))?;

    // 5. Non-blocking oneshot channel: Tokio worker thread does not block
    let (tx, rx) = tokio::sync::oneshot::channel();
    let target_for_closure = navigate_target.clone();
    let cache_for_closure = leaf_cache.clone();

    let dispatch_result = window.with_webview(move |wv| {
        use webview2_com::Microsoft::Web::WebView2::Win32::*;
        use windows_core::Interface;

        let controller = wv.controller();
        unsafe {
            let core = match controller.CoreWebView2() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(format!("CoreWebView2() failed: {e}")));
                    return;
                }
            };

            let core14 = match core.cast::<ICoreWebView2_14>() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(format!(
                        "ICoreWebView2_14 cast failed (WebView2 runtime 101.0.1210+ required): {e}"
                    )));
                    return;
                }
            };

            let handler: ICoreWebView2ServerCertificateErrorDetectedEventHandler = CertErrorHandler {
                leaf_cache: cache_for_closure,
            }
            .into();

            let mut token = std::mem::zeroed();
            if let Err(e) = core14.add_ServerCertificateErrorDetected(&handler, &mut token) {
                let _ = tx.send(Err(format!("add_ServerCertificateErrorDetected failed: {e}")));
                return;
            }

            tracing::info!(
                "Embedded browser: ServerCertificateErrorDetected handler attached (token: {token:?})"
            );

            // Now that handler is hooked without any race condition, navigate to target!
            let target_w: Vec<u16> = target_for_closure
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            if let Err(e) = core.Navigate(windows_core::PCWSTR(target_w.as_ptr())) {
                let _ = tx.send(Err(format!("Navigate to '{target_for_closure}' failed: {e}")));
                return;
            }

            let _ = tx.send(Ok(()));
        }
    });

    if let Err(e) = dispatch_result {
        let _ = window.close();
        return Err(format!("Failed to dispatch to webview: {e}"));
    }

    // 6. Non-blocking async wait with 5-second timeout; if failed or timed out, close window and return Err
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => Ok(window),
        Ok(Ok(Err(err))) => {
            let _ = window.close();
            Err(err)
        }
        Ok(Err(_closed)) => {
            let _ = window.close();
            Err("Embedded browser webview channel closed unexpectedly".into())
        }
        Err(_elapsed) => {
            let _ = window.close();
            Err("Embedded browser initialization timed out after 5s".into())
        }
    }
}

/// Extracts the normalized, pure hostname from a request URI string.
///
/// Guaranteed:
/// - Strips userinfo (e.g. `https://spoof@evil.com/` yields `"evil.com"`, not `"spoof"`).
/// - Strips port (e.g. `https://example.com:8443/` yields `"example.com"`).
/// - Strips path, query, fragment.
/// - Normalizes ASCII to lowercase and trims trailing dots.
/// - Rejects malformed or hostless URIs.
pub fn extract_host_from_uri(uri: &str) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    let host = url.host_str()?;
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertDecision {
    Allow,
    Cancel,
}

#[cfg(windows)]
const _: () = {
    use webview2_com::Microsoft::Web::WebView2::Win32::*;
    assert!(COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_COMMON_NAME_IS_INCORRECT.0 == 1);
    assert!(COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_EXPIRED.0 == 2);
    assert!(COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_REVOKED.0 == 4);
    assert!(COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_IS_INVALID.0 == 5);
};

/// Pure decision function for server certificate trust in the embedded browser.
///
/// Returns `CertDecision::Allow` only when:
/// 1. The error status is the expected untrusted root code (not expired, revoked, or CN mismatch).
/// 2. The leaf certificate's SHA-256 fingerprint exists in DropSuite's actively minted leaves.
/// 3. The requested host matches the host for which DropSuite issued that exact leaf certificate.
pub fn cert_decision(
    leaf_der: &[u8],
    request_host: &str,
    error_status: i32,
    minted_by_fp: &std::collections::HashMap<String, String>,
) -> CertDecision {
    // 1. Mandatory fail-closed on dangerous/untrustworthy status codes
    #[cfg(windows)]
    {
        use webview2_com::Microsoft::Web::WebView2::Win32::*;
        if error_status == COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_COMMON_NAME_IS_INCORRECT.0
            || error_status == COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_EXPIRED.0
            || error_status == COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_REVOKED.0
        {
            tracing::warn!(
                "Embedded browser: Rejecting certificate due to untrustworthy error status: {error_status}"
            );
            return CertDecision::Cancel;
        }
    }
    if error_status == 1 || error_status == 2 || error_status == 4 {
        return CertDecision::Cancel;
    }

    // 2. Leaf fingerprint lookup in minted leaves
    let leaf_fp = dropsuite_core::ca::sha256_hex(leaf_der);
    let Some(minted_host) = minted_by_fp.get(&leaf_fp) else {
        tracing::warn!(
            "Embedded browser: Rejecting certificate - leaf fp '{leaf_fp}' was not minted by DropSuite"
        );
        return CertDecision::Cancel;
    };

    // 3. Match request host with the host DropSuite minted this leaf for
    let clean_req_host = request_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let clean_minted_host = minted_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if clean_req_host.is_empty() || clean_req_host != clean_minted_host {
        tracing::warn!(
            "Embedded browser: Rejecting certificate - request host '{clean_req_host}' does not match minted host '{clean_minted_host}'"
        );
        return CertDecision::Cancel;
    }

    // 4. Expected status for DropSuite self-minted leaf (untrusted root in Windows Schannel = status 5 / CERTIFICATE_IS_INVALID)
    #[cfg(windows)]
    {
        use webview2_com::Microsoft::Web::WebView2::Win32::*;
        if error_status == COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_IS_INVALID.0 {
            tracing::info!(
                "Embedded browser: Verified DropSuite-minted leaf for host '{clean_req_host}' (fp: '{leaf_fp}') - allowing"
            );
            return CertDecision::Allow;
        }
    }
    if error_status == 5 {
        return CertDecision::Allow;
    }

    tracing::warn!(
        "Embedded browser: Rejecting certificate with unexpected error status {error_status} for host '{clean_req_host}'"
    );
    CertDecision::Cancel
}

pub fn evaluate_leaf(
    leaf_der: &[u8],
    request_host: &str,
    error_status: i32,
    leaf_cache: &std::sync::RwLock<dropsuite_core::LeafCache>,
) -> CertDecision {
    let Ok(cache) = leaf_cache.read() else {
        tracing::error!("Embedded browser: leaf_cache lock is poisoned, failing closed");
        return CertDecision::Cancel;
    };
    cert_decision(leaf_der, request_host, error_status, &cache.by_fingerprint)
}

#[cfg(windows)]
struct CoTaskMemPWSTR(windows_core::PWSTR);

#[cfg(windows)]
impl CoTaskMemPWSTR {
    fn null() -> Self {
        Self(windows_core::PWSTR::null())
    }

    fn as_mut_ptr(&mut self) -> *mut windows_core::PWSTR {
        &mut self.0
    }

    fn to_string(&self) -> Result<String, std::string::FromUtf16Error> {
        unsafe { self.0.to_string() }
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

#[cfg(windows)]
impl Drop for CoTaskMemPWSTR {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::System::Com::CoTaskMemFree(self.0 .0 as *const _);
            }
        }
    }
}

#[cfg(windows)]
type CookieSender = std::sync::Arc<
    std::sync::Mutex<Option<tokio::sync::oneshot::Sender<Result<Vec<HarvestedCookie>, String>>>>,
>;

#[cfg(windows)]
#[windows_core::implement(
    webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2GetCookiesCompletedHandler
)]
struct GetCookiesHandler {
    tx: CookieSender,
}

#[cfg(windows)]
impl GetCookiesHandler {
    fn take_sender(
        &self,
    ) -> Option<tokio::sync::oneshot::Sender<Result<Vec<HarvestedCookie>, String>>> {
        self.tx.lock().ok().and_then(|mut g| g.take())
    }
}

#[cfg(windows)]
impl webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2GetCookiesCompletedHandler_Impl
    for GetCookiesHandler_Impl
{
    fn Invoke(
        &self,
        errorcode: windows_core::HRESULT,
        result: windows_core::Ref<
            webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2CookieList,
        >,
    ) -> windows_core::Result<()> {
        let mut out: Result<Vec<HarvestedCookie>, String> = Ok(Vec::new());
        if errorcode.is_err() {
            out = Err(format!("CookieManager returned 0x{:08x}", errorcode.0));
        } else if let Some(list) = result.as_ref() {
            let mut count = 0u32;
            unsafe {
                if list.Count(&mut count).is_ok() {
                    let mut cookies = Vec::new();
                    for i in 0..count {
                        let Ok(cookie) = list.GetValueAtIndex(i) else {
                            continue;
                        };
                        if let Some(raw) = set_cookie_from(&cookie) {
                            cookies.push(HarvestedCookie { raw });
                        }
                    }
                    out = Ok(cookies);
                }
            }
        }
        if let Some(tx) = self.take_sender() {
            let _ = tx.send(out);
        }
        Ok(())
    }
}

/// Build `name=value; Domain=...; Path=...; Secure; HttpOnly; Expires=...` from a WebView2 cookie.
#[cfg(windows)]
fn set_cookie_from(
    cookie: &webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Cookie,
) -> Option<String> {
    let mut raw = String::new();
    unsafe {
        let mut name = CoTaskMemPWSTR::null();
        if cookie.Name(name.as_mut_ptr()).is_err() || name.is_null() {
            return None;
        }
        let name = name.to_string().ok()?;
        let mut value = CoTaskMemPWSTR::null();
        if cookie.Value(value.as_mut_ptr()).is_err() || value.is_null() {
            return None;
        }
        let value = value.to_string().ok()?;
        raw.push_str(&format!("{name}={value}"));

        let mut domain = CoTaskMemPWSTR::null();
        if cookie.Domain(domain.as_mut_ptr()).is_ok() && !domain.is_null() {
            if let Ok(d) = domain.to_string() {
                if !d.is_empty() {
                    raw.push_str(&format!("; Domain={d}"));
                }
            }
        }
        let mut path = CoTaskMemPWSTR::null();
        if cookie.Path(path.as_mut_ptr()).is_ok() && !path.is_null() {
            if let Ok(p) = path.to_string() {
                if p.starts_with('/') {
                    raw.push_str(&format!("; Path={p}"));
                }
            }
        }
        let mut secure = windows_core::BOOL(0);
        if cookie.IsSecure(&mut secure).is_ok() && secure.as_bool() {
            raw.push_str("; Secure");
        }
        let mut http_only = windows_core::BOOL(0);
        if cookie.IsHttpOnly(&mut http_only).is_ok() && http_only.as_bool() {
            raw.push_str("; HttpOnly");
        }
        let mut expires = 0f64;
        if cookie.Expires(&mut expires).is_ok() && expires > 0.0 {
            raw.push_str(&format!("; Expires={}", http_date(expires as i64)));
        }
    }
    Some(raw)
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` for unix seconds.
#[cfg(any(windows, target_os = "linux"))]
pub fn http_date(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Inverse of the day-count algorithm used by the jar: days since epoch to a civil date.
#[cfg(any(windows, target_os = "linux"))]
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
#[cfg(windows)]
#[windows_core::implement(webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ServerCertificateErrorDetectedEventHandler)]
struct CertErrorHandler {
    leaf_cache: std::sync::Arc<std::sync::RwLock<dropsuite_core::LeafCache>>,
}

#[cfg(windows)]
impl webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ServerCertificateErrorDetectedEventHandler_Impl for CertErrorHandler_Impl {
    fn Invoke(
        &self,
        _sender: windows_core::Ref<'_, webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2>,
        args: windows_core::Ref<'_, webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2ServerCertificateErrorDetectedEventArgs>,
    ) -> windows_core::Result<()> {
        use webview2_com::Microsoft::Web::WebView2::Win32::*;

        let Some(args) = args.as_ref() else {
            return Ok(());
        };

        let mut decision = CertDecision::Cancel;

        unsafe {
            let mut status = std::mem::zeroed::<COREWEBVIEW2_WEB_ERROR_STATUS>();
            let _ = args.ErrorStatus(&mut status);
            let error_status = status.0;

            let mut uri_pwstr = CoTaskMemPWSTR::null();
            let mut raw_uri = String::new();
            let mut req_host = String::new();
            if args.RequestUri(uri_pwstr.as_mut_ptr()).is_ok() && !uri_pwstr.is_null() {
                if let Ok(uri_str) = uri_pwstr.to_string() {
                    raw_uri = uri_str.clone();
                    if let Some(h) = extract_host_from_uri(&uri_str) {
                        req_host = h;
                    }
                }
            }

            tracing::info!(
                "Embedded browser: ServerCertificateErrorDetected event received: uri='{raw_uri}', req_host='{req_host}', error_status={error_status}"
            );

            if let Ok(cert) = args.ServerCertificate() {
                let mut pem_pwstr = CoTaskMemPWSTR::null();
                if cert.ToPemEncoding(pem_pwstr.as_mut_ptr()).is_ok() && !pem_pwstr.is_null() {
                    if let Ok(pem_str) = pem_pwstr.to_string() {
                        if let Some(Ok(cert_der)) = rustls_pemfile::certs(&mut pem_str.as_bytes()).next() {
                            decision = evaluate_leaf(
                                cert_der.as_ref(),
                                &req_host,
                                error_status,
                                &self.leaf_cache,
                            );
                        }
                    }
                }
            }

            match decision {
                CertDecision::Allow => {
                    let _ = args.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_ALWAYS_ALLOW);
                }
                CertDecision::Cancel => {
                    let _ = args.SetAction(COREWEBVIEW2_SERVER_CERTIFICATE_ERROR_ACTION_CANCEL);
                }
            }
        }

        Ok(())
    }
}

/// Maps WebKitGTK's TLS error flags onto the same status codes `cert_decision` reasons about on
/// Windows (1 = host/CN mismatch, 2 = expired/not-yet-valid, 4 = revoked, 5 = untrusted root).
/// Anything else is reported as 0 so the shared decision fails closed.
#[cfg(target_os = "linux")]
fn tls_flags_to_status(flags: gio::TlsCertificateFlags) -> i32 {
    use gio::TlsCertificateFlags;
    if flags.contains(TlsCertificateFlags::BAD_IDENTITY) {
        1
    } else if flags.contains(TlsCertificateFlags::EXPIRED)
        || flags.contains(TlsCertificateFlags::NOT_ACTIVATED)
    {
        2
    } else if flags.contains(TlsCertificateFlags::REVOKED) {
        4
    } else if flags.contains(TlsCertificateFlags::UNKNOWN_CA) {
        // The expected status for a DropSuite-minted leaf: its issuer is not in any trust store.
        5
    } else {
        0
    }
}

/// Spawns an isolated embedded browser window connected to the DropSuite proxy (WebKitGTK).
///
/// The Linux counterpart of the Windows WebView2 path: the window routes through the loopback
/// proxy and trusts a server certificate only when it is a leaf DropSuite actively minted for that
/// exact host. It does this through WebKit's `load-failed-with-tls-errors` signal rather than any
/// blanket ignore-certificate flag, so upstream validation stays honest for everything else.
#[cfg(target_os = "linux")]
pub async fn spawn_embedded_browser(
    app: &tauri::AppHandle,
    proxy_url: url::Url,
    data_dir: std::path::PathBuf,
    target_url: &str,
    leaf_cache: std::sync::Arc<std::sync::RwLock<dropsuite_core::LeafCache>>,
    mode: BrowserMode,
) -> Result<tauri::WebviewWindow, String> {
    use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

    // 1. Only http/https, same contract as the Windows path.
    let parsed_url: url::Url = target_url
        .parse()
        .map_err(|e| format!("Invalid URL '{target_url}': {e}"))?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(format!(
            "Invalid URL scheme '{}'. Only 'http' and 'https' are allowed.",
            parsed_url.scheme()
        ));
    }
    let navigate_target = parsed_url.to_string();

    // 2. Close any previous embedded/challenge windows.
    for (label, window) in app.webview_windows() {
        if label.starts_with("embedded-browser") || label.starts_with("challenge-browser") {
            let _ = window.close();
        }
    }

    // 3. Unique monotonic label.
    let window_label = format!(
        "{}-{}",
        mode.label_prefix(),
        BROWSER_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );

    let _ = std::fs::create_dir_all(&data_dir);

    // 4. Start at about:blank so the TLS-error handler is attached before the first HTTPS request.
    tracing::info!(
        "Spawning embedded browser: target='{navigate_target}', proxy='{proxy_url}', data_dir='{}'",
        data_dir.display()
    );
    let blank_url: url::Url = "about:blank".parse().unwrap();
    let window = WebviewWindowBuilder::new(app, &window_label, WebviewUrl::External(blank_url))
        .title(mode.title())
        .inner_size(1200.0, 800.0)
        .proxy_url(proxy_url)
        .data_directory(data_dir)
        .build()
        .map_err(|e| format!("Failed to create embedded browser window: {e}"))?;

    // 5. Attach the cert hook and navigate, all on the GTK main thread.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let target_for_closure = navigate_target.clone();
    let cache_for_closure = leaf_cache.clone();

    let dispatch_result = window.with_webview(move |wv| {
        use gio::prelude::TlsCertificateExt;
        use webkit2gtk::{WebContextExt, WebViewExt};

        let webview: webkit2gtk::WebView = wv.inner();

        // Trust only DropSuite-minted leaves, and only for the host they were minted for. Every
        // other certificate error keeps WebKit's default (the load fails), mirroring the Windows
        // ServerCertificateErrorDetected hook.
        let cache = cache_for_closure.clone();
        webview.connect_load_failed_with_tls_errors(move |view, uri, certificate, errors| {
            let Some(host) = extract_host_from_uri(uri) else {
                return false;
            };
            let Some(der) = certificate.certificate().map(|b| Vec::from(&b[..])) else {
                return false;
            };
            let status = tls_flags_to_status(errors);
            match evaluate_leaf(&der, &host, status, &cache) {
                CertDecision::Allow => {
                    tracing::info!(
                        "Embedded browser: trusting DropSuite-minted leaf for host '{host}' (tls flags {errors:?}) - reloading"
                    );
                    if let Some(context) = view.context() {
                        context.allow_tls_certificate_for_host(certificate, &host);
                    }
                    view.load_uri(uri);
                    true
                }
                CertDecision::Cancel => {
                    tracing::warn!(
                        "Embedded browser: rejecting certificate for host '{host}' (status {status}, tls flags {errors:?})"
                    );
                    false
                }
            }
        });

        webview.load_uri(&target_for_closure);
        let _ = tx.send(Ok::<(), String>(()));
    });

    if let Err(e) = dispatch_result {
        let _ = window.close();
        return Err(format!("Failed to dispatch to webview: {e}"));
    }

    // 6. Same bounded wait as Windows.
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => Ok(window),
        Ok(Ok(Err(err))) => {
            let _ = window.close();
            Err(err)
        }
        Ok(Err(_closed)) => {
            let _ = window.close();
            Err("Embedded browser webview channel closed unexpectedly".into())
        }
        Err(_elapsed) => {
            let _ = window.close();
            Err("Embedded browser initialization timed out after 5s".into())
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn spawn_embedded_browser(
    _app: &tauri::AppHandle,
    _proxy_url: url::Url,
    _data_dir: std::path::PathBuf,
    _target_url: &str,
    _leaf_cache: std::sync::Arc<std::sync::RwLock<dropsuite_core::LeafCache>>,
    _mode: BrowserMode,
) -> Result<tauri::WebviewWindow, String> {
    Err("Embedded browser is currently supported on Windows and Linux.".into())
}

/// One cookie read out of the challenge window, in `Set-Cookie` shape so the jar's own parser
/// validates it. `expires` is unix seconds.
#[derive(Debug, Clone, PartialEq)]
pub struct HarvestedCookie {
    pub raw: String,
}

#[cfg(windows)]
pub async fn harvest_cookies(
    window: &tauri::WebviewWindow,
    url: &str,
) -> Result<Vec<HarvestedCookie>, String> {
    use webview2_com::Microsoft::Web::WebView2::Win32::*;
    use windows_core::Interface;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let url_w: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

    window
        .with_webview(move |wv| unsafe {
            let core = match wv.controller().CoreWebView2() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(format!("CoreWebView2() failed: {e}")));
                    return;
                }
            };
            let core2 = match core.cast::<ICoreWebView2_2>() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(format!("ICoreWebView2_2 cast failed: {e}")));
                    return;
                }
            };
            let manager = match core2.CookieManager() {
                Ok(m) => m,
                Err(e) => {
                    let _ = tx.send(Err(format!("CookieManager() failed: {e}")));
                    return;
                }
            };
            let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
            let handler: ICoreWebView2GetCookiesCompletedHandler =
                GetCookiesHandler { tx: slot.clone() }.into();
            if let Err(e) = manager.GetCookies(windows_core::PCWSTR(url_w.as_ptr()), &handler) {
                if let Ok(mut guard) = slot.lock() {
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(Err(format!("GetCookies failed: {e}")));
                    }
                }
            }
        })
        .map_err(|e| format!("Failed to reach the challenge window: {e}"))?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("The challenge window closed before cookies were read.".into()),
        Err(_) => Err("Reading cookies from the challenge window timed out.".into()),
    }
}

/// Build `name=value; Domain=...; Path=...; Secure; HttpOnly; Expires=...` from a WebKit cookie,
/// the same shape `set_cookie_from` produces on Windows so the jar parser validates it identically.
#[cfg(target_os = "linux")]
fn set_cookie_from_soup(cookie: &mut soup::Cookie) -> Option<String> {
    let name = cookie.name()?;
    if name.is_empty() {
        return None;
    }
    let value = cookie.value().unwrap_or_default();
    let mut raw = format!("{name}={value}");
    if let Some(domain) = cookie.domain() {
        if !domain.is_empty() {
            raw.push_str(&format!("; Domain={domain}"));
        }
    }
    if let Some(path) = cookie.path() {
        if path.starts_with('/') {
            raw.push_str(&format!("; Path={path}"));
        }
    }
    if cookie.is_secure() {
        raw.push_str("; Secure");
    }
    if cookie.is_http_only() {
        raw.push_str("; HttpOnly");
    }
    if let Some(expires) = cookie.expires() {
        let unix = expires.to_unix();
        if unix > 0 {
            raw.push_str(&format!("; Expires={}", http_date(unix)));
        }
    }
    Some(raw)
}

#[cfg(target_os = "linux")]
pub async fn harvest_cookies(
    window: &tauri::WebviewWindow,
    url: &str,
) -> Result<Vec<HarvestedCookie>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let url_owned = url.to_string();

    window
        .with_webview(move |wv| {
            use webkit2gtk::{CookieManagerExt, WebViewExt, WebsiteDataManagerExt};
            let webview: webkit2gtk::WebView = wv.inner();
            let Some(manager) = webview.website_data_manager().and_then(|m| m.cookie_manager())
            else {
                let _ = tx.send(Err("WebKit exposed no cookie manager".to_string()));
                return;
            };
            // The async callback fires on the GTK main loop; the slot lets whichever path runs
            // first own the one-shot sender.
            let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
            manager.cookies(&url_owned, gio::Cancellable::NONE, move |res| {
                let out = match res {
                    Ok(mut cookies) => Ok(cookies
                        .iter_mut()
                        .filter_map(set_cookie_from_soup)
                        .map(|raw| HarvestedCookie { raw })
                        .collect()),
                    Err(e) => Err(format!("CookieManager returned: {e}")),
                };
                if let Ok(mut guard) = slot.lock() {
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(out);
                    }
                }
            });
        })
        .map_err(|e| format!("Failed to reach the challenge window: {e}"))?;

    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("The challenge window closed before cookies were read.".into()),
        Err(_) => Err("Reading cookies from the challenge window timed out.".into()),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn harvest_cookies(
    _window: &tauri::WebviewWindow,
    _url: &str,
) -> Result<Vec<HarvestedCookie>, String> {
    Err("Cookie harvesting needs the Windows WebView2 runtime.".into())
}

/// Read the User-Agent the challenge window actually sends. It is what the clearance cookie is
/// bound to, so it must be reused verbatim.
#[cfg(windows)]
pub async fn window_user_agent(window: &tauri::WebviewWindow) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .with_webview(move |wv| unsafe {
            use webview2_com::Microsoft::Web::WebView2::Win32::*;
            use windows_core::Interface;
            let read = || -> Result<String, String> {
                let core = wv.controller().CoreWebView2().map_err(|e| e.to_string())?;
                let settings = core.Settings().map_err(|e| e.to_string())?;
                let settings = settings
                    .cast::<ICoreWebView2Settings2>()
                    .map_err(|e| e.to_string())?;
                let mut ua = CoTaskMemPWSTR::null();
                settings
                    .UserAgent(ua.as_mut_ptr())
                    .map_err(|e| e.to_string())?;
                if ua.is_null() {
                    return Err("the window reports an empty User-Agent".into());
                }
                ua.to_string()
                    .map_err(|_| "the User-Agent was not valid text".to_string())
            };
            let _ = tx.send(read());
        })
        .map_err(|e| format!("Failed to reach the challenge window: {e}"))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("The challenge window closed before the User-Agent was read.".into()),
        Err(_) => Err("Reading the User-Agent timed out.".into()),
    }
}

#[cfg(target_os = "linux")]
pub async fn window_user_agent(window: &tauri::WebviewWindow) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .with_webview(move |wv| {
            use webkit2gtk::{SettingsExt, WebViewExt};
            let webview: webkit2gtk::WebView = wv.inner();
            let ua = webview
                .settings()
                .and_then(|s| s.user_agent())
                .map(|g| g.to_string())
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "the window reports an empty User-Agent".to_string());
            let _ = tx.send(ua);
        })
        .map_err(|e| format!("Failed to reach the challenge window: {e}"))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("The challenge window closed before the User-Agent was read.".into()),
        Err(_) => Err("Reading the User-Agent timed out.".into()),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn window_user_agent(_window: &tauri::WebviewWindow) -> Result<String, String> {
    Err("The User-Agent can only be read on Windows with WebView2.".into())
}

/// Convert harvested cookies into `Set-Cookie` text for the jar parser. Cookies with no name,
/// or that are already expired, are dropped.
pub fn harvested_to_set_cookie(cookie: &HarvestedCookie) -> Option<String> {
    Some(cookie.raw.clone()).filter(|raw| raw.contains('='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;

    const UNTRUSTED_ROOT_STATUS: i32 = 5; // COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_IS_INVALID
    const CN_MISMATCH_STATUS: i32 = 1; // COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_COMMON_NAME_IS_INCORRECT
    const EXPIRED_STATUS: i32 = 2; // COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_EXPIRED
    const REVOKED_STATUS: i32 = 4; // COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_REVOKED

    #[test]
    fn test_extract_host_from_uri_various_cases() {
        // Standard URL
        assert_eq!(
            extract_host_from_uri("https://lumens.my.id/dashboard"),
            Some("lumens.my.id".to_string())
        );
        // Custom port is stripped
        assert_eq!(
            extract_host_from_uri("https://lumens.my.id:8443/api/v1"),
            Some("lumens.my.id".to_string())
        );
        // Userinfo spoofing attack: host must be evil.com, NOT lumens.my.id!
        assert_eq!(
            extract_host_from_uri("https://lumens.my.id@evil.com/"),
            Some("evil.com".to_string())
        );
        // Userinfo with password
        assert_eq!(
            extract_host_from_uri("https://user:lumens.my.id@evil.com:443/test"),
            Some("evil.com".to_string())
        );
        // Uppercase and trailing dot normalized
        assert_eq!(
            extract_host_from_uri("HTTPS://LUMENS.MY.ID./PATH"),
            Some("lumens.my.id".to_string())
        );
        // IPv4 host
        assert_eq!(
            extract_host_from_uri("http://127.0.0.1:8080/"),
            Some("127.0.0.1".to_string())
        );
        // Non-HTTP / malformed
        assert_eq!(extract_host_from_uri("not a valid url"), None);
        assert_eq!(extract_host_from_uri("javascript:alert(1)"), None);
    }

    #[test]
    fn test_minted_and_host_match_allows() {
        let fake_leaf_der = b"sample-drop-suite-leaf-cert-bytes";
        let fp = dropsuite_core::ca::sha256_hex(fake_leaf_der);

        let mut minted = HashMap::new();
        minted.insert(fp, "example.com".to_string());

        let decision = cert_decision(fake_leaf_der, "example.com", UNTRUSTED_ROOT_STATUS, &minted);
        assert_eq!(decision, CertDecision::Allow);
    }

    #[test]
    fn test_minted_but_host_mismatch_cancels() {
        let fake_leaf_der = b"sample-drop-suite-leaf-cert-bytes";
        let fp = dropsuite_core::ca::sha256_hex(fake_leaf_der);

        let mut minted = HashMap::new();
        minted.insert(fp, "example.com".to_string());

        let decision = cert_decision(
            fake_leaf_der,
            "evil.com", // mismatching host!
            UNTRUSTED_ROOT_STATUS,
            &minted,
        );
        assert_eq!(decision, CertDecision::Cancel);
    }

    #[test]
    fn test_fake_chain_with_root_ca_cancels() {
        // Attacker serves their own leaf for evil.com, appending DropSuite Root CA to the chain.
        let attacker_leaf_der = b"attacker-leaf-cert-bytes";
        let mut minted = HashMap::new();
        minted.insert(
            dropsuite_core::ca::sha256_hex(b"legitimate-leaf"),
            "target.com".to_string(),
        );

        let decision = cert_decision(
            attacker_leaf_der,
            "evil.com",
            UNTRUSTED_ROOT_STATUS,
            &minted,
        );
        assert_eq!(decision, CertDecision::Cancel);
    }

    #[test]
    fn test_cn_mismatch_expired_revoked_always_cancels() {
        let fake_leaf_der = b"sample-leaf";
        let fp = dropsuite_core::ca::sha256_hex(fake_leaf_der);

        let mut minted = HashMap::new();
        minted.insert(fp, "example.com".to_string());

        // CN mismatch
        assert_eq!(
            cert_decision(fake_leaf_der, "example.com", CN_MISMATCH_STATUS, &minted),
            CertDecision::Cancel
        );
        // Expired
        assert_eq!(
            cert_decision(fake_leaf_der, "example.com", EXPIRED_STATUS, &minted),
            CertDecision::Cancel
        );
        // Revoked
        assert_eq!(
            cert_decision(fake_leaf_der, "example.com", REVOKED_STATUS, &minted),
            CertDecision::Cancel
        );
    }

    #[test]
    fn test_poisoned_lock_fails_closed_without_panic() {
        let cache = RwLock::new(dropsuite_core::LeafCache::default());
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.write().unwrap();
            panic!("simulate panic while holding write lock");
        }));
        assert!(cache.is_poisoned());

        let decision = evaluate_leaf(
            b"some-leaf-der",
            "example.com",
            UNTRUSTED_ROOT_STATUS,
            &cache,
        );
        assert_eq!(decision, CertDecision::Cancel);
    }

    #[test]
    fn test_empty_cache_after_ca_regen_cancels() {
        let mut cache = dropsuite_core::LeafCache::default();
        let fake_leaf_der = b"sample-leaf-before-regen";
        let fp = dropsuite_core::ca::sha256_hex(fake_leaf_der);

        cache.by_fingerprint.insert(fp, "example.com".to_string());
        cache.clear();

        let lock = RwLock::new(cache);
        let decision = evaluate_leaf(fake_leaf_der, "example.com", UNTRUSTED_ROOT_STATUS, &lock);
        assert_eq!(decision, CertDecision::Cancel);
    }

    #[test]
    fn test_http_date_matches_the_jar_parser() {
        // The harvest writes `Expires` in this shape; the jar must read the same instant back.
        for unix in [0i64, 784_111_777, 1_700_000_000, 4_102_444_800] {
            let text = format!("sid=1; Expires={}", http_date(unix));
            let parsed = dropsuite_core::cookies::parse_set_cookie("a.test", &text, unix - 1)
                .expect("raw must parse");
            assert_eq!(parsed.expires_at, Some(unix), "{text}");
        }
    }

    #[test]
    fn test_http_date_is_gmt_and_weekday_correct() {
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn test_harvested_cookie_needs_a_pair() {
        assert_eq!(
            harvested_to_set_cookie(&HarvestedCookie {
                raw: "a=1; Path=/".into()
            }),
            Some("a=1; Path=/".to_string())
        );
        assert_eq!(
            harvested_to_set_cookie(&HarvestedCookie {
                raw: "broken".into()
            }),
            None
        );
    }

    #[tokio::test]
    async fn test_integration_engine_mint_and_evaluate_leaf_wiring() {
        let tmp = std::env::temp_dir().join(format!(
            "dropsuite-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ca_dir = tmp.join("ca");
        let allowlist =
            dropsuite_core::InterceptAllowlist::from_user_entries(&["lumens.my.id".to_string()])
                .unwrap();

        let https = dropsuite_core::HttpsInterception::new(dropsuite_core::HttpsInterceptConfig {
            ca_dir,
            allowlist,
            upstream_roots: Vec::new(),
        })
        .unwrap();

        // 1. Generate CA and issue leaf for lumens.my.id
        https.load_or_generate_ca().await.unwrap();
        let _acceptor = https.acceptor_for("lumens.my.id").await.unwrap();

        // 2. Share the EXACT same LeafCache instance that the engine writes to
        let leaf_cache = https.leaf_cache();

        // 3. Extract the real leaf cert DER bytes that were issued
        let cert_der = {
            let cache = leaf_cache.read().unwrap();
            let entry = cache
                .by_host
                .get("lumens.my.id")
                .expect("leaf entry must be present in cache");
            entry.cert_der.clone()
        };

        // 4. Verify evaluate_leaf on this exact cache instance returns Allow
        let decision = evaluate_leaf(
            &cert_der,
            "lumens.my.id",
            UNTRUSTED_ROOT_STATUS,
            &leaf_cache,
        );
        assert_eq!(decision, CertDecision::Allow);

        // 5. Cross-host replay attempt with the same cert must be Rejected (Cancel)
        let cross_host_decision =
            evaluate_leaf(&cert_der, "evil.com", UNTRUSTED_ROOT_STATUS, &leaf_cache);
        assert_eq!(cross_host_decision, CertDecision::Cancel);

        // 6. CA removal wipes LeafCache atomically -> subsequently evaluated leaf must be Cancel
        https.remove_ca().await.unwrap();
        let after_removal_decision = evaluate_leaf(
            &cert_der,
            "lumens.my.id",
            UNTRUSTED_ROOT_STATUS,
            &leaf_cache,
        );
        assert_eq!(after_removal_decision, CertDecision::Cancel);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_tls_flags_to_status_mapping() {
        use gio::TlsCertificateFlags;
        assert_eq!(
            tls_flags_to_status(TlsCertificateFlags::UNKNOWN_CA),
            UNTRUSTED_ROOT_STATUS
        );
        assert_eq!(
            tls_flags_to_status(TlsCertificateFlags::UNKNOWN_CA | TlsCertificateFlags::BAD_IDENTITY),
            CN_MISMATCH_STATUS
        );
        assert_eq!(
            tls_flags_to_status(TlsCertificateFlags::UNKNOWN_CA | TlsCertificateFlags::EXPIRED),
            EXPIRED_STATUS
        );
        assert_eq!(
            tls_flags_to_status(TlsCertificateFlags::UNKNOWN_CA | TlsCertificateFlags::NOT_ACTIVATED),
            EXPIRED_STATUS
        );
        assert_eq!(
            tls_flags_to_status(TlsCertificateFlags::UNKNOWN_CA | TlsCertificateFlags::REVOKED),
            REVOKED_STATUS
        );
        assert_eq!(tls_flags_to_status(TlsCertificateFlags::GENERIC_ERROR), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_set_cookie_from_soup_round_trip() {
        let mut c = soup::Cookie::new("cf_clearance", "tok123", ".lumens.my.id", "/", 3600);
        c.set_secure(true);
        c.set_http_only(true);
        let raw = set_cookie_from_soup(&mut c).expect("valid soup cookie");
        assert!(raw.contains("cf_clearance=tok123"), "{raw}");
        assert!(raw.contains("Domain=.lumens.my.id"), "{raw}");
        assert!(raw.contains("Path=/"), "{raw}");
        assert!(raw.contains("Secure"), "{raw}");
        assert!(raw.contains("HttpOnly"), "{raw}");
        let parsed = dropsuite_core::cookies::parse_set_cookie("lumens.my.id", &raw, 1_700_000_000)
            .expect("jar parser must accept soup cookie output");
        assert_eq!(parsed.name, "cf_clearance");
        assert_eq!(parsed.value, "tok123");
        assert!(parsed.secure);
        assert!(parsed.http_only);
    }
}
