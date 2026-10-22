# DropSuite P2 handoff

For the next agent continuing DropSuite P2 release work. Last updated 2026-10-20.

## 1. Where things stand

P2 security hardening is completed, packaged, and verified. A new **release candidate (RC1) has completed packaged-app verification** (`accept.mjs` 33/33, `replay_blocked.mjs` 10/10). The RC is ready for the next release review (`verify/RELEASE-REVIEW.md`), but it has **NOT been approved for distribution**.

| Item | State | Evidence / Status |
|---|---|---|
| `cargo test --workspace` | 125 passed, 0 failed, 0 ignored | Verified in build logs (`logs/cargo-test.log`); not rerun in packaged-app pass |
| `npm run build` (frontend) | exit 0, current source | Verified in build logs (`logs/frontend-build.log`); not rerun in packaged-app pass |
| Packaged executable extraction | Verified successfully | Differed from built exe by exactly 3 bytes in `.rdata` (`__TAURI_BUNDLE_TYPE_VAR_UNK` -> `NSS`); restoring marker yields exact built exe SHA-256 (`verify/logs/extract.log`, `verify/logs/extract-independent.log`) |
| Desktop acceptance (`accept.mjs`) | 33 passed, 0 failed, 0 skipped | Verified successfully on extracted RC executable; exit 0 (`verify/logs/accept.log`, `verify/accept-run/results.json`) |
| Replay acceptance (`replay_blocked.mjs`) | 10 passed, 0 failed, 0 skipped | Verified successfully on extracted RC executable; exit 0 (`verify/logs/replay.log`, `verify/replay-run/*.png`) |
| Environment & artifact integrity | Verified successfully | Pre-run and post-run snapshots are byte-identical (`Compare-Object` empty); real app data, trust stores, and processes untouched |
| Old installer `91df079730082afee3a3ecbd3fdaad7a29648b23f5717089af41bf1f0ef08f0b` | Obsolete, must not ship | Verified unchanged; predates P2 fixes; backed up at `guard/` |
| Installer lifecycle (install/uninstall) | Not tested in this pass | Pending release review; installer was deliberately not executed |
| Code signing | Not tested in this pass | Binaries are `NotSigned`; pending release decision |
| Package completeness (NSIS payload) | Partially verified | Packaged `dropsuite.exe` verified; remaining 10 NSIS payload blocks not individually inspected |
| Distribution readiness | Pending release review | NOT approved for distribution |

Decisions are made by the user, in English briefs with numbered sections and a required final decision line (for example `READY FOR …` / `BLOCKED — …`). Work in bounded passes: do what the brief asks, report exact commands, exit codes and test counts, and never claim a check that was not run.

## 2. Project map

- Root: `C:\Users\Fraxzu\Downloads\rea_software`. **Not a Git repository**: there is no `git diff`. Before editing, copy files you will touch to your scratchpad so you can diff and restore byte-for-byte (`cmp`).
- `crates/dropsuite-core`: the engine (proxy, HTTPS interception, CA, Replay, sanitization, storage).
- `crates/dropsuite-app`: the Tauri desktop app (IPC commands in `src/commands.rs`, engine setup in `src/engine.rs`).
- `crates/dropsuite-desktop`: headless dev daemon with an HTTP bridge (`127.0.0.1:8081`) for UI work in a browser.
- `crates/dropsuite-cli`: CLI tools, including `mock_upstream`.
- `frontend/`: React + Vite UI. `npm run build` runs `tsc && vite build` into `frontend/dist`, which Tauri embeds.
- `docs/ARCHITECTURE.md`, `docs/SECURITY.md`: the documented contracts. Keep them in step with any behavior change.

## 3. Security model (what the code guarantees, and where)

### Destination policy (`crates/dropsuite-core/src/proxy.rs`)
- One rule set, `is_restricted_destination(SocketAddr)`, used by ordinary HTTP forwarding, CONNECT (blind tunnel and interception), every request inside an intercepted TLS session, and Replay.
- **Refused:** unspecified, multicast, IPv4 link-local `169.254.0.0/16` (includes `169.254.169.254`), IPv6 link-local `fe80::/10`, and exactly `100.100.100.200` (Alibaba) and `fd00:ec2::254` (AWS IPv6 IMDS).
- **Equivalent forms are judged as their IPv4 address:** IPv4-mapped (`::ffff:a.b.c.d`), legacy IPv4-compatible (`::a.b.c.d`), and the well-known NAT64 prefix `64:ff9b::/96`. Network-specific NAT64 prefixes are deliberately not decoded.
- **Allowed:** loopback and private networks (RFC 1918, `100.64.0.0/10`, IPv6 ULA) except the exact endpoints above.
- **How:** the host is resolved once (`resolve()`); every address is checked; one bad answer refuses the request; the connection goes only to those checked addresses (no second DNS lookup).
- **Proxy only:** port 25 is refused for CONNECT and plain HTTP. Requests to the proxy's own listener get `508` (`is_own_listener`, all loopback spellings).
- `canonical_ip` keeps `::1` and `::` as IPv6 (an earlier bug turned `::1` into `0.0.0.1`).
- The HTTPS **interception allowlist never permits a refused destination**; it only decides decrypt versus blind tunnel. Replay does not use it.

### Replay (`crates/dropsuite-core/src/replay.rs`)
- Sends one request directly (never through the listener), no redirects, no retries.
- Applies the destination policy; a refusal is error kind `blocked`, shown as "Not sent: restricted address" (`frontend/src/workspaces/ReplayWorkspace.tsx`).
- Has no port 25 rule (an open product decision, section 9).
- `https://` verifies against Mozilla roots (`webpki-roots`); `ReplayOptions::tls_roots` is for tests only, the app always passes none.

### CA contract (decided by the user on 2026-10-20: explicit only)
- A root CA exists **only after the user clicks Generate Root CA**. `HttpsInterception::ca_material()` loads from disk via `CaManager::load()` and never generates.
- Without a CA (fresh install or after Remove), an allowlisted CONNECT fails closed: `502` with "HTTPS interception needs a root CA…", and no CA is created.
- Remove deletes the CA files and drops the CA and cached leaves from memory; interception stays off until Generate.
- The key is stored DPAPI-protected (`root-ca.key.dpapi`); export returns the public PEM only. The app never installs trust anywhere.

### Allowlist parsing (`crates/dropsuite-core/src/allowlist.rs`)
A bare IPv6 entry (`::1`, as the panel displays the default list) is accepted as a host with no port. Before this fix, saving the default list failed with "Invalid host in: ::1" and saved lists were reset on restart.

### Test seams (production defaults are off)
- `ProxyEngine::set_resolver_override` (`ResolverOverride`): deterministic name resolution.
- `ProxyEngine::set_connect_gate` (`ConnectGate`): deny-only check after the policy and before any socket opens.
- `ProxyEngine::outbound_connect_attempts()`: counts connect attempts.
- `replay::send_with(req, opts, &NetworkSeams { resolver, connect_gate })`; `replay::send` uses none.

## 4. Safety rules (non-negotiable)

- **Never contact a real metadata endpoint** or arbitrary external hosts. Policy tests use the resolver override plus the loopback-only connect gate, so even a regression cannot open a non-loopback socket.
- **Never disable a security check to test it.** To show a test catches a bug, run it against unfixed code with the gate in place, or restore the old line temporarily on loopback-only tests, then restore and `cmp`.
- **Never touch Windows or browser trust stores.** In tests, trust the CA per connection only (Node `ca:` option, rustls root store).
- **Never use real app data** (`%APPDATA%\com.dropsuite.desktop`, `%LOCALAPPDATA%\com.dropsuite.desktop`). Always run the app with `DROPSUITE_DATA_DIR` set to a scratch folder.
- **Do not write the clipboard:** the "Export Public CA" button copies to it. Call the `export_ca_certificate` IPC command instead.
- **Preserve artifacts:** never overwrite an installer or exe without first making a hash-verified copy. No commit, push, sign, publish or deploy.
- The app is single-instance: the harnesses abort if DropSuite is already running. Do not kill the user's own instance.

## 5. Everyday commands

Run from the project root in Git Bash.

```sh
# Frontend (needed before any Tauri build; tauri.conf has no beforeBuildCommand)
(cd frontend && npm run build)

# Tests
cargo test --workspace
cargo test -p dropsuite-core --test destination_policy_test --test https_interception_test --test replay_test --test proxy_loop_test

# Release exe only, into target/release (overwrites target/release/dropsuite.exe: back it up first)
node frontend/node_modules/@tauri-apps/cli/tauri.js build --no-bundle
```

**Windows file lock:** cargo sometimes fails with `os error 32` because the editor's Rust analyzer is building at the same time. Retry; do not clean the target directory.

**Escaping gotcha:** when writing Rust test strings through a Bash heredoc or Python, `\r\n` can turn into real line breaks. Prefer the Edit/Write tools for files containing escapes, and check with `grep -c $'\r'`.

## 6. Building a release candidate in isolation

Tauri puts output under Cargo's target directory (`<target>/release/bundle/nsis/`), and there is no `.cargo` config, so `CARGO_TARGET_DIR` isolates the whole build.

```sh
# 1. Prove the override is honoured (must print the isolated path)
CARGO_TARGET_DIR='C:\Users\Fraxzu\Downloads\dropsuite-rc\<name>\target' cargo metadata --format-version 1 --no-deps | python -c "import sys,json;print(json.load(sys.stdin)['target_directory'])"

# 2. Back up the existing installer (verify the hash of the copy), then mark it read-only during the build
#    (PowerShell: Set-ItemProperty <path> -Name IsReadOnly -Value $true; clear it afterwards)

# 3. Build exe + NSIS installer
CARGO_TARGET_DIR='C:\Users\Fraxzu\Downloads\dropsuite-rc\<name>\target' node frontend/node_modules/@tauri-apps/cli/tauri.js build
```

A cold build takes several minutes; run it in the background.

## 7. Verifying the packaged app

Tools and verification results are located at `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\`.

### `extract_packaged.py`: get the exe out of the installer without running it
```sh
python -I tools/extract_packaged.py target/release/bundle/nsis/DropSuite_0.1.0_x64-setup.exe target/release/dropsuite.exe verify/extracted/dropsuite.exe
```
Decodes the NSIS solid LZMA stream, writes the block whose size equals the built exe, and verifies differing bytes:
- **Verification Result**: Verified successfully (`verify/logs/extract.log`). Packaged exe differs from built exe by exactly 3 bytes at span `0xa489f2..0xa489f4` in `.rdata`.
- **Marker comparison**: Built exe contains `__TAURI_BUNDLE_TYPE_VAR_UNK`; packaged exe contains `__TAURI_BUNDLE_TYPE_VAR_NSS` (patched by Tauri bundler during makensis).
- **Independent verification**: Restoring the marker reproduced the built exe hash `aaec723b9994bc2d1e546612be33187074d44ac4469a67405c08b9abf8095cf5` exactly (`equal True`). Confirmed independently via `cmp -l` (`verify/logs/extract-independent.log`).
- **Limitation**: Only the application binary block (block 8) was extracted and verified; the remaining 10 NSIS payload blocks were not individually inspected.

### `accept.mjs`: desktop acceptance over CDP
```sh
cd verify/accept-run && EXE='C:/Users/Fraxzu/Downloads/dropsuite-rc/p2-rc1/verify/extracted/dropsuite.exe' \
  GUARDED='C:/Users/Fraxzu/Downloads/rea_software/target/release/bundle/nsis/DropSuite_0.1.0_x64-setup.exe;C:/Users/Fraxzu/Downloads/dropsuite-rc/p2-rc1/target/release/bundle/nsis/DropSuite_0.1.0_x64-setup.exe' \
  EXPECT_VERSION=0.1.0 node accept.mjs
```
- Launches `EXE` with an isolated data folder (`./data`), listener port 18790, WebView2 DevTools on port 9256. Local fixtures only (HTTP, TCP echo, and a self-signed `localhost` TLS origin).
- Drives the real UI (Listener settings panel, Start/Stop, Generate/Remove CA, allowlist field) and the same IPC commands the UI uses (`window.__TAURI_INTERNALS__.invoke`).
- **Check Count Discrepancy Clarification**: The test harness defines and executed **33 checks** (all 33 passed, 0 failed, 0 skipped, exit 0). The earlier documentation reference to "34 checks" was a discrepancy: the harness contains a catch-all block `catch (e) { check('X', 'script ran', false, ...) }` which records an `X` failure only if the script terminates abnormally due to an unhandled exception. In a standard, successful run, `X` is never triggered; exactly 33 checks are executed.
- **Summary of the 33 Passed Checks**:
  - `V1`: Starts and reports version 0.1.0 (window title and PE metadata).
  - `C0`, `C0b`: Fresh profile starts with no CA; without a generated CA, allowlisted CONNECT gets 502 with hint and creates no CA.
  - `H8`, `H9`: Default allowlist (with `::1`) saves back unchanged from the panel; restored to default from panel.
  - `L1`–`L5`: Default listener address is loopback (`127.0.0.1`) and uneditable; started from UI, bound to `127.0.0.1` only; reachable on loopback, refused on LAN (`ECONNREFUSED`); no bind-address setting exists in UI or config; own-listener requests refused with 508.
  - `H1`–`H7`: Permitted HTTP request reaches fixture with real values (200 OK); request appears in History; History record redacts secrets (`[REDACTED]`); SQLite files (`db`, `wal`, `shm`) hold no secrets; diagnostic log holds no secrets; restricted destinations refused with 403; non-allowlisted CONNECT acts as blind tunnel.
  - `C1`–`C3`: Generate CA from UI: status active, fingerprint shown, private key stored DPAPI-protected; Export: one certificate, no private key block, SHA-256 fingerprint matches; CA not installed in any Windows certificate store.
  - `I1`–`I4`: Allowlisted CONNECT: client trusting exported CA gets leaf for localhost signed by app CA; upstream with self-signed cert fails closed (502, origin never served); client not trusting CA fails TLS handshake; failed interception creates no History record.
  - `C4`–`C8`: Remove CA from UI: status absent and CA files deleted; after removal, allowlisted CONNECT fails closed (502) and creates no CA; regenerate from UI produces new distinct fingerprint consistent across UI and files; proxy signs with regenerated CA; zero Windows certificate stores modified during CA lifecycle.
  - `Z1`–`Z4`: Real app data untouched; executable under test and all guarded files unchanged; trust stores unchanged; no DropSuite process left running.
- **Evidence**: Execution log at `verify/logs/accept.log`, results at `verify/accept-run/results.json`, UI screenshots at `verify/accept-run/c-ca-regenerated.png` and `h-history.png`.

### `replay_blocked.mjs`: Replay success and refusal UX
```sh
cd verify/replay-run && EXE='C:/Users/Fraxzu/Downloads/dropsuite-rc/p2-rc1/verify/extracted/dropsuite.exe' node replay_blocked.mjs
```
- **Verification Result**: 10 passed, 0 failed, 0 skipped (exit 0).
- **Checks Performed**: Replay workspace opens; Success shows status 200 and no alert; Connection refused shows "Connection refused" status and explanatory message; TLS failure keeps existing presentation (not "restricted address"); Blocked `http://0.0.0.0:9/` shows row and title "Not sent: restricted address" and destination rule message; Blocked `http://224.0.0.1/` shows row and title "Not sent: restricted address" and multicast rule message; Attempts history verified; Real app state untouched; No DropSuite process left.
- **Evidence**: Log at `verify/logs/replay.log`, UI screenshots at `verify/replay-run/1-success.png`, `2-tls.png`, and `3-blocked.png`.

HTTPS capture **success** cannot be shown in the app with local fixtures, because the upstream check correctly rejects a self-signed origin. It is covered by `successful_tls_interception_and_capture` and the rest of `https_interception_test`.

### System Integrity Snapshots (`snapshot.ps1`)
- Snapshots taken immediately before and after acceptance and replay execution:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File verify/scripts/snapshot.ps1 verify/logs/snapshot-before.txt
  # [execution of accept.mjs and replay_blocked.mjs]
  powershell -NoProfile -ExecutionPolicy Bypass -File verify/scripts/snapshot.ps1 verify/logs/snapshot-after.txt
  ```
- **Integrity Result**: Verified byte-identical (`Compare-Object` returned 0 diffs). Confirmed:
  - Artifact hashes and read-only flags identical across all 8 monitored files.
  - Real application directories (`%APPDATA%\com.dropsuite.desktop`, `%LOCALAPPDATA%\com.dropsuite.desktop`) completely untouched.
  - Windows certificate stores (`Cert:\`) and Firefox NSS store (`cert9.db`) untouched; zero DropSuite certificates installed.
  - Zero background `dropsuite` processes left running.

## 8. Verification outcome and remaining release review

### Completed Actions
1. **Extraction and comparison**: Packaged binary extracted without installer execution. Verified 3-byte difference in `.rdata` representing only the expected `__TAURI_BUNDLE_TYPE_VAR_` marker.
2. **Acceptance testing**: Desktop acceptance passed 33/33; Replay acceptance passed 10/10.
3. **Integrity audit**: Confirmed zero impact on system state, certificate stores, and user data. Old installer `91df079730082afee3a3ecbd3fdaad7a29648b23f5717089af41bf1f0ef08f0b` preserved and unchanged.

### Release Status: NOT Approved for Distribution
The packaged RC has completed functional acceptance, but has **NOT** been approved for release. It is now subject to the release review documented in [verify/RELEASE-REVIEW.md](file:///c:/Users/Fraxzu/Downloads/rea_software/verify/RELEASE-REVIEW.md).

Outstanding items for the release review:
1. **Installer lifecycle**: A controlled installation and uninstallation procedure must be executed in an isolated environment (sandbox/VM) before any public distribution.
2. **Code signing**: Application and installer binaries are currently unsigned (`NotSigned`). Release requires Authenticode signing with an RFC 3161 timestamp.
3. **Package completeness**: The remaining 10 NSIS payload blocks (plugins, bitmap, uninstaller templates) must be safely audited.
4. **Build & test provenance**: Formal reproduction of the frontend build and 125 workspace unit/integration tests.
5. **Product decisions**: Formal stakeholder review of open decisions and accepted limitations (port 25, link-local, TLS presentation, IPv4-only, metadata list, security certification).

## 9. Open decisions and accepted limitations

### Pending a Release Decision
- **Port 25 in Replay:** The proxy listener refuses port 25 for plain HTTP and CONNECT tunnels (`crates/dropsuite-core/src/proxy.rs`). Replay (`crates/dropsuite-core/src/replay.rs`) currently does not refuse port 25. Aligning Replay with the proxy listener requires a product decision.
- **Link-local devices in Replay:** `169.254.0.0/16` is unconditionally refused by destination policy with no override. Adding an exception for embedded/IoT testing requires a product decision.
- **TLS failure presentation in Replay:** Shows generic "✕ Failed" status and "Not sent" title; the detailed TLS handshake failure reason is displayed in the message body.

### Known Accepted Product Limitations
- **App listener is IPv4 only:** `BIND_IP = "127.0.0.1"` is hard-coded in `crates/dropsuite-app/src/engine.rs`. Dual-stack and IPv6 listeners (`::1`) work at the core engine level but are not exposed or selectable in the desktop UI.
- **Fixed metadata endpoint list:** Refuses link-local `169.254.0.0/16` (including `169.254.169.254`), plus specific cloud metadata endpoints `100.100.100.200` (Alibaba) and `fd00:ec2::254` (AWS IPv6 IMDS). Non-link-local metadata endpoints for other cloud providers are not statically enumerated.
- **No production security certification:** No formal external third-party security audit or certification has been performed or claimed.

## 10. Artifact manifest (SHA-256) and evidence locations

### Complete Artifact Hashes
Full 64-character SHA-256 hashes must be preserved without abbreviation:

| Artifact | Path | Full SHA-256 |
|---|---|---|
| RC installer (new, verified package) | `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\target\release\bundle\nsis\DropSuite_0.1.0_x64-setup.exe` | `e94694b39ee24414b11d48d0db9dbca90d3368fb4235c80d0412befe5cf1bcd6` |
| RC built exe (installer input) | `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\target\release\dropsuite.exe` | `aaec723b9994bc2d1e546612be33187074d44ac4469a67405c08b9abf8095cf5` |
| RC extracted packaged exe (verified) | `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\extracted\dropsuite.exe` | `211aaf9fc59f2a21e6371467c3e163c1857470bc2b618cd209053424c32c5547` |
| Old installer (obsolete, do not ship) | `C:\Users\Fraxzu\Downloads\rea_software\target\release\bundle\nsis\DropSuite_0.1.0_x64-setup.exe` | `91df079730082afee3a3ecbd3fdaad7a29648b23f5717089af41bf1f0ef08f0b` |
| Old installer backup | `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\guard\OLD-OBSOLETE-DropSuite_0.1.0_x64-setup.exe.91df0797` | `91df079730082afee3a3ecbd3fdaad7a29648b23f5717089af41bf1f0ef08f0b` |
| Repo standalone exe (pre-CA-fix, 31/31 acceptance) | `C:\Users\Fraxzu\Downloads\rea_software\target\release\dropsuite.exe` | `632eae00dd01b25984598bebfdf90edcc0e7a13003147d13d573b561cee9b73f` |
| Scratchpad exe backup (acc) | `C:\Users\Fraxzu\AppData\Local\Temp\claude\c--Users-Fraxzu-Downloads-rea-software\52dcf540-8e7a-473f-a871-f2b5e89327f5\scratchpad\acc\dropsuite.exe.879958b2` | `879958b20ad7bac4dfa775253853615ea29fd4f0dd80690ab5513ccd63ca4324` |
| Scratchpad exe backup (ui) | `C:\Users\Fraxzu\AppData\Local\Temp\claude\c--Users-Fraxzu-Downloads-rea-software\52dcf540-8e7a-473f-a871-f2b5e89327f5\scratchpad\ui\dropsuite.exe.before` | `fd64a6580f72a2313e1483522a8786d273d77fdafa24fa31aab8c8d7feff4e25` |

### Verification Evidence and Reproduction Locations
- **Reproduction commands**: `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\COMMANDS.md`
- **Verification logs** (`C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\logs\`):
  - `extract.log`: Stream extraction, marker comparison, restoration check.
  - `extract-independent.log`: Independent `cmp -l` byte difference and Python verification.
  - `accept.log`: Full console output of the 33 desktop acceptance checks.
  - `replay.log`: Full console output of the 10 Replay acceptance checks.
  - `snapshot-before.txt`: Complete pre-run system, cert store, file, and process state.
  - `snapshot-after.txt`: Complete post-run system, cert store, file, and process state (byte-identical to before).
  - `tools-sha256.txt`: SHA-256 hashes of verification scripts and fixtures.
- **Acceptance run outputs** (`C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\accept-run\`):
  - `results.json`: Machine-readable results for all 33 acceptance checks.
  - `app.log`: DropSuite process log during desktop acceptance run.
  - `c-ca-regenerated.png`: Screenshot confirming UI CA regeneration and status.
  - `h-history.png`: Screenshot confirming HTTP history and secret redaction.
- **Replay run outputs** (`C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\replay-run\`):
  - `app.log`: DropSuite process log during Replay acceptance run.
  - `1-success.png`: Screenshot of successful request (status 200).
  - `2-tls.png`: Screenshot of TLS handshake failure presentation.
  - `3-blocked.png`: Screenshot of destination policy block ("Not sent: restricted address").
- **Verification tools & fixtures**:
  - `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\tools\extract_packaged.py`
  - `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\tools\accept.mjs`
  - `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\tools\replay_blocked.mjs`
  - `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\tools\origin-cert.pem` / `origin-key.pem`
  - `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\verify\scripts\snapshot.ps1`
- **Build provenance logs** (`C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\logs\`):
  - `tauri-build.log`: Release candidate compilation and NSIS packaging log (exit 0).
  - `cargo-test.log`: Full 125-test workspace test suite log (exit 0).
  - `frontend-build.log`: TypeScript check and Vite build log (exit 0).

## 11. What changed in P2 (for review)

| File | Change |
|---|---|
| `crates/dropsuite-core/src/proxy.rs` | Shared `resolve()`; test seams; port 25 on plain HTTP; `canonical_ip` keeps `::1`/`::`; exact metadata endpoints; NAT64 decoding; 502 with a hint when no CA exists |
| `crates/dropsuite-core/src/replay.rs` | Destination policy before connect; `blocked` error kind; `send_with` / `NetworkSeams` |
| `crates/dropsuite-core/src/ca.rs` | `CaError::NotGenerated`; load-only `CaManager::load()` |
| `crates/dropsuite-core/src/https.rs` | `ca_material()` never generates |
| `crates/dropsuite-core/src/allowlist.rs` | Bare IPv6 entries parse; `bare_ipv6_entries_round_trip` test |
| `crates/dropsuite-core/tests/destination_policy_test.rs` | New, 15 tests |
| `crates/dropsuite-core/tests/https_interception_test.rs` | Connect gate on all proxies, explicit CA generation in setup, rebinding, Replay HTTPS, CA-contract tests (24 total) |
| `crates/dropsuite-core/tests/replay_test.rs` | Replay destination-policy tests (9 total) |
| `frontend/src/workspaces/ReplayWorkspace.tsx` | `blocked: 'Not sent: restricted address'` |
| `docs/ARCHITECTURE.md`, `docs/SECURITY.md` | HTTPS Replay, test roots, destination policy (§6), CA generation and removal contract |
