# Contributing to DropSuite

DropSuite is a free alternative to the workflows other proxies lock behind a
paid tier, and it stays that way because people pitch in. Code, docs, tests, a
good bug report, or a better wordlist, all of it helps.

> DropSuite is for authorized testing and education only. Please keep examples,
> issues and test targets to systems you own or have written permission to test
> (or deliberately vulnerable practice targets such as OWASP Juice Shop).

## Getting set up

Requires Rust (stable) and Node.js. From the repository root:

```sh
# Frontend (needed before any Tauri build)
cd frontend && npm install && npm run build && cd ..

# Run the tests
cargo test --workspace

# Build the desktop app + installer
node frontend/node_modules/@tauri-apps/cli/tauri.js build
```

## How the project is laid out

- `crates/dropsuite-core`: the engine (proxy, HTTPS interception, CA, replay,
  intruder, scope, cookies, challenge detection, storage). No GUI dependency.
- `crates/dropsuite-app`: the Tauri desktop app (IPC commands, engine setup).
- `crates/dropsuite-desktop`: headless dev daemon with an HTTP bridge.
- `crates/dropsuite-cli`: CLI tools, including a local mock upstream.
- `frontend/`: React + Vite UI.
- `docs/`: architecture specification and visual assets.

## Before you open a pull request

- `cargo test --workspace` passes (green), and `npm run build` (or
  `npx tsc --noEmit`) in `frontend/` is clean.
- New behavior comes with a test where it reasonably can.
- Keep the security guarantees intact: the destination policy, credential
  redaction, and the "nothing leaves the machine unless the operator sends it"
  rule (see `SECURITY.md`).

### If you add a Tauri command

Register it in **all three** places, or it fails at runtime with "not allowed
by ACL" (the Rust tests do not catch this, because they call the core directly):

1. `crates/dropsuite-app/src/main.rs`: `generate_handler![...]`
2. `crates/dropsuite-app/build.rs`: the commands list
3. `crates/dropsuite-app/capabilities/main-window.json`: `"allow-<name>"`

### Style notes

- Save all source files as UTF-8 (no BOM).
- Match the surrounding code; keep changes focused.
- Describe what changed and why in the PR, and how you tested it.

## Reporting bugs

Open an issue with steps to reproduce, what you expected, and what happened.
For **security** problems, do not open a public issue, see `SECURITY.md`.
