# DropSuite

A local-first, intercepting web security testing platform — a free workspace for
authorized web application testing. Built in Rust (Tokio) + SQLite with a Tauri 2
desktop shell and a React UI.

> **Status: alpha / work in progress.** Not yet released. Interfaces and data formats
> may change.

> **License: not yet chosen.** Until a license is added, all rights are reserved — this
> repository is private and not for redistribution.

## What it does

- **Proxy + HTTPS interception** — capture traffic on `127.0.0.1:8080`; decrypt only
  the hosts you allowlist (others are tunnelled untouched). The root CA is created only
  when you click Generate, stored DPAPI-protected, and never installed into any trust store.
- **HTTP history** — searchable, filterable, with a request/response inspector. Credentials
  are redacted at the storage boundary. Export to HAR. Clear with one button.
- **Intercept** — hold, edit, forward or drop requests and responses.
- **Target** — site map, scope rules, match & replace.
- **Replay** — edit and resend a request; per-tab attempt history; side-by-side diff.
- **Fuzzer** — Sniper / Cluster bomb with payload positions.
- **Decoder / Comparer** — local encode/decode and text diff.
- **Scanner** — passive checks across captured traffic; content discovery.
- **Drop AI** — bring your own model and key; secrets redacted before anything is sent.
- **Fingerprint & challenge handling** — browser header presets, a cookie jar, and an
  embedded browser to solve interactive challenges on sites **you are authorized to test**.

Everything stays on your machine. The app makes no analytics or pingback calls.

## Authorized use only

DropSuite is for testing systems you own or have **written permission** to test. Using it
to probe or bypass protections on systems you do not control may be illegal. You are
responsible for how you use it.

## Build from source

Requires Rust (stable) and Node.js. From the repository root:

```sh
# Frontend (needed before any Tauri build)
cd frontend && npm install && npm run build && cd ..

# Run the tests
cargo test --workspace

# Build the desktop app + installer (output under target/release/bundle/nsis)
node frontend/node_modules/@tauri-apps/cli/tauri.js build
```

The installer is currently unsigned, so Windows SmartScreen will warn on first run
(More info → Run anyway).

## Layout

- `crates/dropsuite-core` — the engine (proxy, HTTPS interception, CA, replay, intruder,
  scope, cookies, challenge detection, storage).
- `crates/dropsuite-app` — the Tauri desktop app (IPC commands, engine setup).
- `crates/dropsuite-desktop` — headless dev daemon with an HTTP bridge for UI work in a browser.
- `crates/dropsuite-cli` — CLI tools, including a local mock upstream for testing.
- `frontend/` — React + Vite UI.
- `docs/` — architecture, security model, and the Indonesian testing guides
  (`PANDUAN-TESTING.md`, `PANDUAN-UJI-CHALLENGE.md`).
