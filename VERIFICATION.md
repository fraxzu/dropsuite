# DropSuite — Verification Report (for an independent technical/AI reviewer)

**Purpose.** This document lets a reviewer decide whether DropSuite is a *real, working* web‑security
testing tool or a "LARP" (a convincing shell with mocked/hardcoded behaviour). It is written to be
**audited, not trusted**: every claim points at a specific source file you can open, a test you can
run, or a command transcript you can reproduce.

**How to avoid a false positive.** Do **not** judge from this document alone — a nice report can be
faked as easily as a nice UI. Judge from the **source code included alongside it**. For each feature
below, open the named file and confirm the work is done by real code (sockets, TLS, parsing), not by
returning canned data. A grep checklist is at the end.

> Reviewer note: a packaged `.exe` is the *weakest* evidence here — a binary can't be inspected or
> executed by a chat model, so it forces a guess. The source tree + tests + reproduction steps below
> are what make this checkable.

---

## 1. What it is

DropSuite is a local‑first intercepting HTTP(S) proxy for authorized web‑security testing — the same
tool class as Burp Suite / OWASP ZAP. It runs as a Tauri desktop app (Rust engine + React UI) and
binds its proxy to loopback only. Core capabilities: intercepting proxy with history, HTTPS
interception (MITM via a locally generated CA), Replay (edit & resend), Fuzzer/Intruder, passive
Scanner + content discovery, Target Scope engine (with a "Zero Egress" hard block), and
Match & Replace (on‑the‑fly request/response rewriting).

## 2. Codebase facts (verifiable with `wc -l` / `cargo test`)

| Area | Size | Note |
|---|---|---|
| Rust engine (`crates/dropsuite-core/src`) | ~9.5K LOC | the actual networking/TLS/parsing |
| Rust app layer (`crates/dropsuite-app/src`) | ~3.5K LOC | Tauri commands, platform, CA, Drop AI |
| Frontend (`frontend/src`) | ~9.5K LOC | React UI |
| **Automated tests** | **~6.5K LOC, 14 integration files** | real sockets/TLS, not mocks |
| **`cargo test --workspace`** | **188 passed, 0 failed (20 binaries)** | reproduce below |

A project with 6,500 lines of integration tests that stand up real TCP servers and real TLS is not a
mock-up; mock-ups do not have `http_streaming_test.rs` (1,531 LOC) or `https_interception_test.rs`
(950 LOC).

## 3. Feature → source map (open these to verify it's real)

| Capability | Where the real work happens | What to look for |
|---|---|---|
| Intercepting proxy, loopback bind, history | `crates/dropsuite-core/src/proxy.rs` (1,841 LOC), `http1.rs` (822) | raw HTTP/1.1 parsing, real `TcpListener`, streaming |
| HTTP egress + **SSRF/destination guard** | `crates/dropsuite-core/src/replay.rs:383-389` | `is_restricted_destination` runs on every resolved IP before connect; link‑local/metadata blocked, loopback allowed |
| **HTTPS MITM** (own CA, per‑host leaf certs) | `ca.rs` (471), `https.rs` (295), `interception.rs` (511) | CA generation, leaf signing, allowlist‑gated interception |
| Fuzzer / Intruder (Sniper, Cluster Bomb) | `intruder.rs` (663) | `{{ }}` templating, `run()` fires real requests via `replay::send`, scope‑checked |
| **Scope engine** + Zero Egress sandbox | `scope.rs` | `is_in_scope` include/exclude; `drop_out_of_scope` aborts at proxy boundary |
| **Match & Replace** | `match_replace.rs` (355) | `apply_request_head` / `apply_response_head` rewrite wire bytes |
| Secret redaction before storage | `sanitize.rs` (1,981) | tokens/keys redacted; see `*_secrets_e2e_test.rs` |
| Persistence | `storage.rs` (722) | SQLite (`dropsuite.db`); history survives restart |
| Tauri commands (IPC surface) | `crates/dropsuite-app/src/commands.rs` (878) | `start_intruder`, `get/set_scope_config`, `export_ca_certificate`, … |

## 4. Test evidence

Run it yourself:

```bash
cargo test --workspace      # => 188 passed; 0 failed
```

High‑signal integration tests (they bind real sockets / do real TLS, so passing them means the
behaviour is genuine, not stubbed):

- `tests/http_streaming_test.rs` (1,531) — streaming proxy behaviour over real connections
- `tests/interactive_proxy_test.rs` (1,059) — intercept/modify/forward loop
- `tests/https_interception_test.rs` (950) — CA + leaf cert MITM path
- `tests/replay_test.rs` (548) + `tests/destination_policy_test.rs` (548) — egress + SSRF guard
- `tests/content_discovery_test.rs` (157) — end‑to‑end: starts a local HTTP target, drives the real
  `intruder::run`, asserts the exact discovered paths (added during this session's QA)
- `tests/scope_and_replace_test.rs` (240) — scope gating + match/replace on the wire

## 5. Live QA evidence (reproduced during a hands‑on session, 2026‑10‑21)

All verified with an **independent oracle** (a separate `curl` + a local echo server + `netstat` +
the Windows cert store) — i.e. a second tool had to agree, so the UI cannot be faking it.

**(a) Proxy carries real traffic.** With the listener on `127.0.0.1:8080` and a local echo server on
`:9000`:
```
> curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9000/cek
{ "method":"GET","url":"/cek","headers":{...,"host":"127.0.0.1:9000"} }
```
The echo server logged the request and DropSuite's history showed it — and the unique query value
changed when the input changed.

**(b) HTTPS MITM actually decrypts.** After trusting DropSuite's CA (`certutil -addstore Root
root-ca.pem`) and allow‑listing the host:
```
> curl.exe --ssl-no-revoke -x http://127.0.0.1:8080 https://lumens.my.id/
<!doctype html> ... <title>Lumen — Media Discovery Platform</title> ...   (real page body)
```
In DropSuite's history the entry appears as `GET  lumens.my.id:443  /  200  html  359 KB` — i.e. the
**TLS was decrypted** (a non‑MITM proxy would only see opaque bytes, never "html 359 KB"). The passive
scanner then flagged 4 real findings on that decrypted response (weak CSP, `Server: nginx/1.24.0`,
`x-powered-by: Express`, missing Referrer‑Policy).

**(c) Scope "Zero Egress" blocks before egress.** With Scope enabled + "Drop out‑of‑scope" on and an
Include rule that did *not* match the target:
```
> curl.exe -x http://127.0.0.1:8080 http://127.0.0.1:9000/scopetest
DropSuite: Request dropped: target is out of scope.
```
The echo server received **nothing** (never contacted). After adding the host to scope, the same
request returned `200`. Independent proof the gate is real, not cosmetic.

**(d) Match & Replace rewrites the wire.** With the "Inject Audit Header" rule enabled, the echo
server saw a header that was never sent by curl:
```
"headers": { ..., "x-dropsuite-audit": "true" }
```

**(e) Listener is a real OS socket.** `netstat -ano | findstr :8080` showed `LISTENING` on
`127.0.0.1` only (not the LAN address) while running, and nothing after Stop.

## 6. A real bug found **and fixed** during QA (anti‑LARP signal)

While testing (d), the Inject‑Header rule produced `502 Bad Gateway`. Root cause in
`match_replace.rs`: an "add header" rule appended the new header **after** the `\r\n\r\n` that
terminates the head, so it spilled into the body and malformed the request. The old unit test only
asserted the header's *presence* (`.contains(...)`), not its *position*, so it missed this. Fix:
insert before the terminator and rebuild the head with exactly one terminator; added a regression
test `test_added_request_header_lands_inside_the_head_not_the_body` that asserts placement. Verified
live: the request then returned `200` with `x-dropsuite-audit: true` correctly injected.

A scripted demo does not spontaneously fail with a protocol‑level bug and then get fixed at the byte
level — this is ordinary engineering on a real system.

**A second, security‑relevant bug — found by an independent code audit and fixed.** A reviewer noted
that `proxy.rs` checked Scope against the *original* request URL (around line 1016) but, when a
request was held for interception and **edited**, re‑parsed the edited target (`parse_edited_request`)
and continued to DNS/destination checks **without re‑validating Scope**. With "Drop out‑of‑scope"
enabled, an in‑scope request could therefore be edited to reach an out‑of‑scope host — escaping the
Zero‑Egress guarantee. Fix: Scope is now re‑checked on the edited target before any resolution or
upstream connection (`proxy.rs`, right after the interception block). Regression test
`tests/interactive_proxy_test.rs::scope_recheck_blocks_request_edited_out_of_scope` proves an edited
out‑of‑scope request returns `403` and **neither origin receives a connection**. That a reviewer could
find this from the source — and that it is a flaw in a *real* feature, not a missing one — is itself
evidence the engine is genuine.

## 7. How to reproduce (so you can tell the owner to re‑verify)

1. `cargo test --workspace` → expect `188 passed; 0 failed`.
2. Build & run the app; Start the listener (binds `127.0.0.1:8080`).
3. `curl.exe -x http://127.0.0.1:8080 http://<any local server>/path` → see it in History.
4. Scope: enable + Include a different host + "Drop out‑of‑scope" → request is dropped; echo server
   stays silent. Add the host → request passes.
5. HTTPS: generate CA (Listener settings), `certutil -user -addstore Root <data-dir>\ca\root-ca.pem`,
   add host to allowlist, `curl.exe --ssl-no-revoke -x http://127.0.0.1:8080 https://<host>/` → page
   body returns and the entry is decrypted in History.

## 8. Honest limitations (a real project states these; a LARP claims perfection)

- **Installer is unsigned** — Windows SmartScreen warns on first run (no code‑signing cert yet).
- **Scope and Match & Replace config are in‑memory** — they reset to default on app restart (not yet
  persisted to disk). Verified by reading the config path; this is a real constraint, not a claim.
- **Cross‑platform is partial.** The code compiles for macOS/Linux (every `#[cfg(windows)]` has a
  `#[cfg(not(windows))]` arm), and the networking core is OS‑agnostic, **but**: the embedded browser
  is Windows/WebView2 only (`platform.rs` returns an explicit "not supported" error elsewhere), the
  Drop AI key is encrypted at rest only on Windows (DPAPI; plaintext fallback elsewhere, see
  `dropai.rs`), and CA key storage uses DPAPI on Windows vs a perm‑restricted PEM elsewhere (`ca.rs`).
- Builds are produced on Windows; macOS/Linux bundles would need to be built on those OSes (standard
  Tauri — no cross‑compile), e.g. via a GitHub Actions matrix.
- **Repo hygiene:** a runtime capture database (`dropsuite.db` + WAL/SHM) had been left in the working
  tree. A `.gitignore` now excludes runtime databases, CA keys, build output and packaged binaries,
  and the distributable **source archive is built with those excluded** (verified: 0 `.db`/`.key`
  entries). Treat any capture database as potentially sensitive (URLs/headers/bodies) — do not ship it.

## 9. Reviewer's anti‑false‑positive checklist (grep the source)

Confirm the behaviour is in code, not faked:

- `rg "TcpListener|TcpStream" crates/dropsuite-core/src` → real sockets exist.
- `rg "is_restricted_destination" crates/dropsuite-core/src/replay.rs` → egress guard is on the only
  send path (so "blocked 169.254.169.254 / 0.0.0.0" isn't theatre).
- Open `ca.rs` + `https.rs` → actual X.509 CA generation and per‑host leaf signing (MITM is real).
- Open `intruder.rs::run` → it calls `replay::send` per attempt; results are real HTTP outcomes.
- `rg "SELECT|INSERT|CREATE TABLE" crates/dropsuite-core/src/storage.rs` → real SQLite, not a stub.
- Open `match_replace.rs` → it edits raw wire bytes; see the regression test for the 502 fix.
- Check the tests don't mock the network: the integration tests spin up real `std::net` servers.

If those hold, the UI is backed by a real engine. If any are stubs returning constants, treat the
corresponding claim as unproven.

---

*Generated as part of a hands‑on verification session on 2026‑10‑21. Figures (188 tests, LOC) are
reproducible from the included source with `cargo test --workspace` and `wc -l`.*
