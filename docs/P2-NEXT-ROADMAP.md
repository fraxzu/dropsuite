# DropSuite P2-next Capability Audit & Roadmap

## Capability Matrix: 12 Burp Pro Feature Categories

This document establishes the verified baseline of DropSuite as of P2-RC1 and details the roadmap toward achieving 11/12 functional category coverage.

| # | Category | Baseline Status | Source Files | Test Coverage | Gaps & Next Steps |
|---|---|---|---|---|---|
| 1 | **HTTP Proxy** | **Implemented** | `crates/dropsuite-core/src/proxy.rs`, `http1.rs` | 18 streaming tests, 2 loop tests, 15 policy tests | None for baseline HTTP/1.1 forwarding. |
| 2 | **HTTPS Interception** | **Implemented** | `crates/dropsuite-core/src/ca.rs`, `allowlist.rs`, `https.rs`, `proxy.rs` | 24 TLS tests in `https_interception_test.rs` | DPAPI-backed local root CA, exact allowlist, verified upstream. |
| 3 | **Blind TLS Tunnel** | **Implemented** | `crates/dropsuite-core/src/proxy.rs` (`blind_relay`) | `non_allowlisted_connect_is_tunneled_without_decryption` | Non-allowlisted CONNECT passes raw TCP without decryption or storage. |
| 4 | **HTTP History** | **Implemented** | `crates/dropsuite-core/src/storage.rs`, `models.rs`, `frontend/src/workspaces/ProxyWorkspace.tsx` | 4 SQLite CRUD tests, 4 e2e redaction tests | Full search, status/method filters, raw inspector with headers/body tabs. |
| 5 | **Repeater** | **Partial** | `crates/dropsuite-core/src/replay.rs`, `frontend/src/workspaces/ReplayWorkspace.tsx` | 9 tests in `replay_test.rs` | Core supports sending & sanitization; UI currently single-draft; multi-tab UI planned for Phase 2. |
| 6 | **Interactive Proxy** | **Implemented** | crates/dropsuite-core/src/interception.rs, proxy.rs, rontend/src/components/InterceptPanel.tsx | 21 regression tests in interactive_proxy_test.rs (all passed) | Complete: hold queue, forward, drop, edit, cancel, timeout, and capacity limits. |
| 7 | **Target Scope & Site Map** | **Missing** (Phase 3 Target) | To be added in `crates/dropsuite-core/src/scope.rs`, `sitemap.rs` | None | Hierarchical tree view by host/path, in-scope vs out-of-scope rules. |
| 8 | **Match & Replace** | **Missing** (Phase 4 Target) | To be added in `crates/dropsuite-core/src/match_replace.rs` | None | Regex / literal header and body replacement rules on in-flight traffic. |
| 9 | **Genuine HTTP/2** | **Missing** (Phase 5 Target) | Currently returns 505 on HTTP/2 preface in `proxy.rs` | `proxy.rs` preface test | Full H2 multiplexed framing on proxy and TLS termination paths. |
| 10 | **Intruder-Style Runner** | **Missing** (Phase 6 Target) | Planned in `crates/dropsuite-core/src/intruder.rs` | None | Payload positions (`§param§`), wordlists, concurrent green-thread execution, diffing. |
| 11 | **Security Scanner** | **Missing** (Phase 7 Target) | Planned in `crates/dropsuite-core/src/scanner/` | None | Passive analysis (security headers, cookie flags, information leaks) + safe active checks. |
| 12 | **Third-Party Extensions** | **Excluded** | N/A | N/A | Excluded from initial 11/12 target per specification. |

---

## Phase 1 Implementation Plan: Interactive Proxy

### Architectural Design
1. **Engine Layer (`dropsuite-core`):**
   - Introduce `InterceptQueue` and `InterceptManager`:
     - Thread-safe state (`AtomicBool` for `is_enabled`).
     - Bounded pending queue (max 100 held requests to prevent memory exhaustion).
     - Each held item has a unique monotonic `id: u64`, creation timestamp, original request details, and a one-shot response channel `oneshot::Sender<InterceptDecision>`.
     - `InterceptDecision`:
       - `Forward(Option<Vec<u8>>)`: forward with optional edited raw HTTP message.
       - `Drop`: drop the request (client receives connection termination / 502/empty).
     - Automatic timeout handling (default 60s per held request) to prevent indefinite client stalls or hung connections when user leaves request held.
     - Disconnect detection: if client drops connection while held, request is automatically evicted from queue.
   - Integrate into `proxy.rs::handle_connection` and `proxy.rs::serve_tls_session`:
     - When `shared.intercept.is_enabled()`, eligible requests (non-CONNECT, or inside TLS session) are paused before sending upstream.
     - If user edits request: re-parse head/framing, forward edited bytes to upstream.
     - If user drops request: terminate connection cleanly without forwarding.

2. **IPC & App Layer (`dropsuite-app` & `dropsuite-desktop`):**
   - Commands:
     - `get_intercept_status`: returns `{ enabled: bool, queue_len: usize }`.
     - `set_intercept_enabled`: toggles Intercept On/Off.
     - `list_intercepted_requests`: returns current list of held requests.
     - `forward_intercepted_request`: takes `{ id: u64, modified_wire: Option<String> }`.
     - `drop_intercepted_request`: takes `{ id: u64 }`.
   - Broadcast events via Tauri event system: `intercept:held`, `intercept:evicted`.

3. **Frontend Layer (`frontend`):**
   - Intercept sub-view inside Proxy Workspace (or dedicated tab matching Burp UX):
     - "Intercept is on" / "Intercept is off" toggle button.
     - "Forward" and "Drop" buttons.
     - Raw HTTP request text editor with syntax highlighting and line numbers.
     - Queue count badge when requests are waiting.
   - Direct shortcuts: Ctrl+F to Forward, Ctrl+D to Drop.
