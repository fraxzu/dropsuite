// No console window in release builds on Windows; ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod diagnostics;
mod dropai;
mod engine;
mod platform;
mod settings;
mod window_fit;

use tauri::Manager;

fn main() {
    diagnostics::init_tracing();

    // Size, position and maximized state are remembered; decorations are not, so a state
    // file written by an older, decorated build cannot bring the native title bar back.
    let mut window_state =
        tauri_plugin_window_state::Builder::default().with_state_flags(window_fit::state_flags());
    // Isolated test runs (DROPSUITE_DATA_DIR) keep every piece of state in their own folder:
    // the window-state file (the plugin joins this absolute path onto its config folder,
    // which yields the path itself) and the WebView's storage (read by WebView2 at startup).
    if let Some(dir) = std::env::var_os("DROPSUITE_DATA_DIR").map(std::path::PathBuf::from) {
        window_state = window_state
            .with_filename(dir.join("window-state.json").to_string_lossy().into_owned());
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", dir.join("webview"));
    }

    let app = tauri::Builder::default()
        // Must be registered first: a second launch hands over to the running instance
        // (focusing its window) and exits before it opens the database or a listener.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(window_state.build())
        .manage(commands::ReplayState::default())
        .manage(commands::IntruderState::default())
        .setup(|app| {
            let dir = engine::data_dir(app.handle());
            let log_dir = dir.as_deref().ok().and_then(diagnostics::start_file_log);
            tracing::info!(
                "DropSuite {} starting ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS
            );
            let state = engine::EngineState::open(dir, log_dir);
            if let Err(reason) = &state.0 {
                tracing::error!("Capture engine failed to initialise: {reason}");
            }
            app.manage(state);
            if let Some(window) = app.get_webview_window("main") {
                platform::apply_window_icons(&window);
            }
            // Once the main window is initialized, remove process-wide WEBVIEW2_USER_DATA_FOLDER
            // so subsequent WebView2 windows (like the embedded proxy browser) can specify their own isolated folders.
            std::env::remove_var("WEBVIEW2_USER_DATA_FOLDER");
            Ok(())
        })
        .on_window_event(|window, event| {
            // A move to a monitor with another scale needs icons drawn for the new DPI.
            if let tauri::WindowEvent::ScaleFactorChanged { .. } = event {
                if let Some(webview_window) = window.app_handle().get_webview_window(window.label())
                {
                    platform::apply_window_icons(&webview_window);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::list_history,
            commands::get_transaction,
            commands::start_proxy,
            commands::stop_proxy,
            commands::get_listener_settings,
            commands::set_listener_port,
            commands::send_replay,
            commands::cancel_replay,
            commands::get_https_settings,
            commands::set_https_allowlist,
            commands::generate_ca_certificate,
            commands::remove_ca_certificate,
            commands::export_ca_certificate,
            commands::get_intercept_status,
            commands::set_intercept_enabled,
            commands::set_intercept_requests,
            commands::set_intercept_responses,
            commands::list_intercepted_messages,
            commands::forward_intercepted_message,
            commands::drop_intercepted_message,
            commands::forward_all_intercepted,
            commands::drop_all_intercepted,
            commands::get_repeater_tabs,
            commands::save_repeater_tab,
            commands::delete_repeater_tab,
            commands::list_repeater_attempts,
            commands::save_repeater_attempt,
            commands::clear_repeater_attempts,
            commands::export_history_har,
            commands::clear_history,
            commands::get_app_info,
            commands::open_app_folder,
            commands::get_start_at_login,
            commands::set_start_at_login,
            commands::check_for_update,
            commands::open_release_page,
            commands::get_scope_config,
            commands::set_scope_config,
            commands::get_match_replace_config,
            commands::set_match_replace_config,
            commands::get_sitemap,
            commands::start_intruder,
            commands::get_intruder_status,
            commands::list_intruder_results,
            commands::cancel_intruder,
            commands::get_dropai_config,
            commands::set_dropai_config,
            commands::set_dropai_key,
            commands::clear_dropai_key,
            commands::dropai_complete,
            commands::test_dropai,
            commands::list_dropai_models,
            commands::open_embedded_browser,
            commands::open_challenge_browser,
            commands::import_challenge_cookies,
            commands::get_apply_settings,
            commands::set_apply_settings,
            commands::list_cookies,
            commands::list_cookies_for_host,
            commands::save_cookie,
            commands::delete_cookie,
            commands::clear_cookies,
        ])
        .build(tauri::generate_context!())
        .expect("DropSuite could not create its window");

    app.run(|handle, event| {
        // The window-state plugin restored the saved geometry when the window was created; make
        // sure it fits. This runs on its own thread: each window call is then carried out by the
        // event loop in turn, and the move and resize events it causes reach the plugin's
        // handlers, which record the correction exactly as for a move or maximize by the user.
        // (Made from inside an event-loop callback, the same calls raised no window events, so
        // the plugin never saw them.)
        if let tauri::RunEvent::Ready = event {
            if let Some(window) = handle.get_webview_window("main") {
                std::thread::spawn(move || window_fit::fit_to_work_area(&window));
            }
        }
        if let tauri::RunEvent::Exit = event {
            engine::shutdown(handle);
            tracing::info!("DropSuite exited");
        }
    });
}
