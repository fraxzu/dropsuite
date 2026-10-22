# DropSuite P2 RC1 — Release Review and Outstanding Decisions

Last updated: 2026-10-20  
Release Target: DropSuite 0.1.0 (P2 RC1)  
Package Under Review: `C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1\target\release\bundle\nsis\DropSuite_0.1.0_x64-setup.exe`  
Distribution Status: **NOT APPROVED FOR DISTRIBUTION — PENDING RELEASE REVIEW**

---

## Executive Summary & Verification Context

The DropSuite P2 RC1 packaged executable has completed non-destructive verification:
- **Desktop Acceptance (`accept.mjs`)**: 33 passed, 0 failed, 0 skipped (exit 0).
- **Replay Acceptance (`replay_blocked.mjs`)**: 10 passed, 0 failed, 0 skipped (exit 0).
- **Binary Extraction & Comparison**: The packaged executable extracted from the NSIS installer differs from the built executable by exactly 3 bytes in `.rdata` representing the expected Tauri bundle-type marker (`__TAURI_BUNDLE_TYPE_VAR_UNK` -> `__TAURI_BUNDLE_TYPE_VAR_NSS`). Restoring the marker yields the exact SHA-256 of the built executable (`aaec723b9994bc2d1e546612be33187074d44ac4469a67405c08b9abf8095cf5`).
- **System Integrity Parity**: Pre-run and post-run snapshots (`snapshot.ps1`) are byte-identical (0 diffs). Real application directories (`%APPDATA%\com.dropsuite.desktop`, `%LOCALAPPDATA%\com.dropsuite.desktop`), Windows certificate stores (`Cert:\`), Firefox NSS store (`cert9.db`), and running processes remained completely untouched.
- **Obsolete Installer Preservation**: The pre-P2 obsolete installer `91df079730082afee3a3ecbd3fdaad7a29648b23f5717089af41bf1f0ef08f0b` remains unchanged and quarantined at `guard/`.

**Current Status Classification**:
- **Verified successfully**: Standalone binary extraction, bundle marker comparison, 33/33 desktop acceptance checks, 10/10 Replay checks, and system integrity snapshot parity.
- **Not tested in this verification pass**: Installer lifecycle (installation/uninstallation execution), code signing, and full installer package inspection (remaining 10 NSIS payload blocks).
- **Pending a release decision**: Code signing strategy, installer execution validation, Replay port 25 behavior, and Replay link-local handling.
- **Known accepted product limitations**: IPv4-only application listener, fixed metadata endpoint list, generic TLS failure presentation in Replay, and absence of external security certification.

---

## Area A: Installer Lifecycle

### 1. Objective and Scope
Design a controlled, reproducible, and non-destructive installation and uninstallation test for `DropSuite_0.1.0_x64-setup.exe`. The test must validate complete installer lifecycle behavior (filesystem changes, shortcuts, registry uninstall entries, certificate store isolation, and process termination) while strictly preventing modification of the user's normal DropSuite installation or application data.

> [!IMPORTANT]
> **Boundary Rule**: The installer was **NOT** executed during the P2 RC1 verification pass and must **NOT** be executed until this controlled test protocol is reviewed and authorized.

### 2. Risk Analysis and Data Isolation
Tauri's default Windows NSIS configuration generates a per-user installer:
- **Default install target**: `%LOCALAPPDATA%\Programs\DropSuite\`
- **Default data directories**:
  - `%APPDATA%\com.dropsuite.desktop` (configuration, SQLite database `dropsuite.db`, WAL/SHM files, CA keys)
  - `%LOCALAPPDATA%\com.dropsuite.desktop` (WebView2 user profile cache, EBWebView directory)
- **Default registry path**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DropSuite`
- **Default shortcuts**:
  - `%USERPROFILE%\Desktop\DropSuite.lnk`
  - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\DropSuite.lnk`

#### Isolation Strategy (Two Options)
1. **Option 1 (Recommended — Virtualized Sandbox)**:
   Run the installation and uninstallation test inside an ephemeral Windows Sandbox (`.wsb` configuration) or clean virtual machine. The installer executable is mapped read-only into the sandbox. The host environment, user profile, registry, and application data are completely isolated by hypervisor boundaries.
2. **Option 2 (Host-Controlled Isolated Test)**:
   If tested on the host system:
   - **Pre-flight Data Backup**: Copy existing `%APPDATA%\com.dropsuite.desktop` and `%LOCALAPPDATA%\com.dropsuite.desktop` to an external backup location (e.g., `guard/user-data-backup/`).
   - **Environment Variable Redirection**: If running non-silently or launching the installed app, enforce `DROPSUITE_DATA_DIR` pointing to an isolated scratch folder.

### 3. Step-by-Step Test Procedure

#### Phase 1: Pre-Install Baseline Snapshot
Record full baseline state to `verify/logs/installer-baseline.txt`:
```powershell
# 1. Capture registry state
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall |
  Get-ItemProperty | Select-Object PSChildName, DisplayName, DisplayVersion, UninstallString |
  Sort-Object DisplayName | Out-File verify/logs/pre-install-registry.txt

# 2. Capture shortcut state
Get-ChildItem "$env:USERPROFILE\Desktop\*.lnk", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\*.lnk" |
  Select-Object FullName, Length | Out-File verify/logs/pre-install-shortcuts.txt

# 3. Capture running processes
Get-Process -Name dropsuite -ErrorAction SilentlyContinue

# 4. Capture certificate store state
powershell -NoProfile -ExecutionPolicy Bypass -File verify/scripts/snapshot.ps1 verify/logs/pre-install-snapshot.txt
```

#### Phase 2: Controlled Installation Execution
Run the installer in non-interactive/silent mode:
```cmd
DropSuite_0.1.0_x64-setup.exe /S
```
*(Wait for the installer process to terminate and verify return code 0).*

#### Phase 3: Post-Install State Audit
Verify all of the following assertions:
1. **Installed Binary Identity**:
   - Location: `%LOCALAPPDATA%\Programs\DropSuite\dropsuite.exe`
   - Hash Assertion: SHA-256 must match `211aaf9fc59f2a21e6371467c3e163c1857470bc2b618cd209053424c32c5547` (the verified extracted executable hash).
2. **Uninstaller Binary Present**:
   - Location: `%LOCALAPPDATA%\Programs\DropSuite\Uninstall DropSuite.exe`
3. **Shortcuts Created**:
   - Verify Start Menu shortcut `%APPDATA%\Microsoft\Windows\Start Menu\Programs\DropSuite.lnk` points to `%LOCALAPPDATA%\Programs\DropSuite\dropsuite.exe`.
   - Verify Desktop shortcut `%USERPROFILE%\Desktop\DropSuite.lnk` (if created) points to the same target.
4. **Registry Uninstall Entry Created**:
   - Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DropSuite`
   - Verify: `DisplayName` = "DropSuite", `DisplayVersion` = "0.1.0", `Publisher` = "DropSuite", `InstallLocation` = `%LOCALAPPDATA%\Programs\DropSuite`, `UninstallString` points to the uninstaller.
   - Verify no unauthorized startup keys (`Run`, `RunOnce`) or shell extensions are registered.
5. **Certificate Store Isolation**:
   - Verify zero certificates were added to `Cert:\CurrentUser` or `Cert:\LocalMachine`. The installer must never inject root CA certificates.
6. **Process State**:
   - Verify no DropSuite background process was spawned automatically without user action.

#### Phase 4: Controlled Uninstallation Execution
Execute the uninstaller silently:
```cmd
"%LOCALAPPDATA%\Programs\DropSuite\Uninstall DropSuite.exe" /S
```
*(Wait for uninstaller process termination).*

#### Phase 5: Post-Uninstall State Audit
Verify complete, clean removal:
1. **Filesystem Cleanup**:
   - Directory `%LOCALAPPDATA%\Programs\DropSuite\` must be completely deleted or empty.
2. **Shortcut Cleanup**:
   - Desktop and Start Menu `.lnk` files must be completely removed.
3. **Registry Cleanup**:
   - Registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DropSuite` must be completely deleted.
4. **Certificate Store Invariance**:
   - Re-run `snapshot.ps1`; diff against pre-install snapshot must show 0 certificate store differences.
5. **Application Data Handling**:
   - Confirm whether user data in `%APPDATA%\com.dropsuite.desktop` was retained (standard Windows convention) or removed, and verify against product policy.
   - Restore pre-flight backup to guarantee 100% data integrity.

---

## Area B: Code Signing

### 1. Current State
All RC binaries and packaging containers are currently **unsigned**:
- `DropSuite_0.1.0_x64-setup.exe`: Status = `NotSigned`
- `dropsuite.exe` (built binary): Status = `NotSigned`
- `dropsuite.exe` (packaged binary): Status = `NotSigned`

Verification evidence:
```powershell
Get-AuthenticodeSignature -FilePath '...\DropSuite_0.1.0_x64-setup.exe'
# Status: NotSigned
```

### 2. Release Signing Requirements
Before public release or distribution to end users, Windows SmartScreen and enterprise endpoint policies require Authenticode digital signatures.

#### Certificate Specifications
- **Certificate Type**: Standard Code Signing Certificate or Extended Validation (EV) Code Signing Certificate issued by a publicly trusted Certification Authority (e.g., DigiCert, Sectigo, GlobalSign) or Azure Trusted Signing identity.
- **Key Storage**: EV certificates mandate FIPS 140-2 Level 2+ hardware storage (USB token, HSM, or cloud KMS).

#### Two-Stage Signing Pipeline
Because Tauri packages `dropsuite.exe` into an NSIS solid LZMA stream, signing must occur in two distinct stages:
1. **Inner Application Signing**: `dropsuite.exe` must be signed *before* NSIS packaging so that the binary extracted onto user systems is trusted.
   - Tauri hook: Configured in `tauri.conf.json` bundle settings or pre-NSIS build step.
2. **Outer Installer Signing**: `DropSuite_0.1.0_x64-setup.exe` must be signed *after* makensis completes.

#### Timestamping Specification
Signatures must include an RFC 3161 compliant timestamp to ensure validity after certificate expiration:
- Digest Algorithm: SHA-256 (`/fd SHA256` and `/td SHA256`)
- Public Timestamp Authority: `http://timestamp.digicert.com` or `http://timestamp.sectigo.com`

### 3. Verification Commands
When a signing pipeline is established, verification must follow this procedure:
```cmd
:: 1. Sign using signtool (Windows SDK)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 <CertThumbprint> <TargetFile>

:: 2. Verify signature and timestamp
signtool verify /pa /v <TargetFile>

:: 3. PowerShell Authenticode check
powershell -Command "Get-AuthenticodeSignature <TargetFile> | Format-List Path, Status, StatusMessage, SignerCertificate, TimeStamperCertificate"
```
*Expected Pass Result*: `Status: Valid`, certificate chains to a trusted root CA, timestamp certificate is present and valid.

> [!NOTE]
> No signing certificate was available, configured, or invented for this verification pass. Signing remains an open release blocker.

---

## Area C: Package Completeness (NSIS Payload Inspection)

### 1. Verification Scope and Uninspected Contents
The packaged installer `DropSuite_0.1.0_x64-setup.exe` contains a solid raw-LZMA1 compressed payload of 14,543,520 bytes divided into **11 blocks**.

During the P2 RC1 verification pass:
- **Block 8** (`dropsuite.exe`, 14,318,080 bytes) was extracted, verified against the built executable, and tested through the acceptance harnesses.
- **The remaining 10 blocks (225,440 bytes total)** were **not individually inspected or verified**.

#### Detailed Inventory of the 10 Uninspected Blocks
| Block Index | Size (Bytes) | Format | Contents / Component Reference | Description |
|---|---|---|---|---|
| Block 0 | 73,416 | Binary / Data | NSIS Instruction Header | NSIS script logic, string table, file layout instructions |
| Block 1 | 12,288 | PE DLL | `System.dll` | Standard NSIS System API plugin (Win32 calls) |
| Block 2 | 26,494 | Bitmap | `BM` header | Installer Modern UI banner/header bitmap graphic |
| Block 3 | 9,728 | PE DLL | `nsDialogs.dll` | Standard NSIS custom UI dialog plugin |
| Block 4 | 34,304 | PE DLL | `nsis_tauri_utils.dll` | Tauri-specific NSIS helper DLL (webview detection, process kill) |
| Block 5 | 7,680 | PE DLL | `StartMenu.dll` | Standard NSIS Start Menu shortcut folder plugin |
| Block 6 | 5,632 | PE DLL | `LangDLL.dll` | Standard NSIS multi-language dialog plugin |
| Block 7 | 15,360 | PE DLL | `NSISdl.dll` | Standard NSIS HTTP downloader plugin |
| Block 8 | 14,318,080 | PE Exe | `dropsuite.exe` | **Verified application binary** (acceptance passed 33/33) |
| Block 9 | 13,956 | Binary / Data | Uninstaller Data | Uninstaller configuration, icons, and string tables |
| Block 10 | 26,538 | Binary / Stub | `NullsoftInst` | NSIS uninstaller stub header template |

### 2. Proposed Safe Verification Method (Without Installing)
To verify package completeness safely without executing the installer:
1. **Automated Multi-Block Extraction**:
   Extend `extract_packaged.py` to extract all 11 blocks into an isolated verification directory (`verify/extracted-blocks/`).
2. **Plugin Hash Verification**:
   Compare the hashes of standard NSIS plugins (`System.dll`, `nsDialogs.dll`, `StartMenu.dll`, `LangDLL.dll`, `NSISdl.dll`) against clean reference binaries from the official NSIS 3.x distribution.
3. **Tauri Helper Audit**:
   Verify `nsis_tauri_utils.dll` against the official Tauri CLI bundler release artifacts (`@tauri-apps/cli`).
4. **NSIS Script Bytecode Disassembly**:
   Use 7-Zip (`7z x -t# DropSuite_0.1.0_x64-setup.exe`) or `nsis-debugger` to extract the embedded NSIS `.nsi` script / bytecode. Audit all operations:
   - Verify registry operations only write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\DropSuite`.
   - Verify filesystem operations write only to `%LOCALAPPDATA%\Programs\DropSuite\` and standard shortcut paths.
   - Confirm absence of bundled third-party bloatware, telemetry, or network-calling pre-install hooks.

---

## Area D: Build and Test Provenance

### 1. Existing Build and Test Records
During the isolated build phase (`dropsuite-rc/p2-rc1/`), the following compilation and test passes succeeded:
- **Frontend Build (`frontend-build.log`)**:
  - Command: `tsc && vite build`
  - Result: 1,610 modules transformed, output in `dist/` (HTML: 0.51 kB, CSS: 32.35 kB, JS: 255.89 kB), built in 1.71s, exit 0.
- **Workspace Test Suite (`cargo-test.log`)**:
  - Command: `cargo test --workspace`
  - Result: **125 passed, 0 failed, 0 ignored** across `dropsuite-core`, `dropsuite-app`, `dropsuite-desktop`, and integration test suites, exit 0.
- **Tauri Bundle Build (`tauri-build.log`)**:
  - Command: `CARGO_TARGET_DIR=... node frontend/node_modules/@tauri-apps/cli/tauri.js build`
  - Result: Built release executable, patched bundle marker `nsis`, ran makensis, produced `DropSuite_0.1.0_x64-setup.exe` (3.67 MiB), exit 0.

### 2. Packaging Pass Rationale
These unit and workspace tests were **not rerun** during the packaged-app verification pass. This was deliberate:
- The packaged-app pass focused exclusively on verifying the packaged artifact (`DropSuite_0.1.0_x64-setup.exe`) and extracted binary behavior under end-user conditions via CDP.
- Rerunning unit tests during packaged verification would risk contaminating target directories, introducing file-lock races with background IDE analyzers, and invalidating existing authoritative logs.

### 3. Exact Reproduction Commands
To independently reproduce the entire build and test provenance from source in a future controlled pass:
```sh
# Working directory: C:\Users\Fraxzu\Downloads\rea_software (in Git Bash)

# 1. Compile frontend assets
(cd frontend && npm run build)

# 2. Run the complete workspace unit and integration test suite (125 tests)
cargo test --workspace

# 3. Run targeted P2 core security and policy integration test suites
cargo test -p dropsuite-core \
  --test destination_policy_test \
  --test https_interception_test \
  --test replay_test \
  --test proxy_loop_test

# 4. Reproduce isolated release candidate build
CARGO_TARGET_DIR='C:\Users\Fraxzu\Downloads\dropsuite-rc\p2-rc1-rebuild\target' \
  node frontend/node_modules/@tauri-apps/cli/tauri.js build
```

---

## Area E: Open Product Decisions and Accepted Limitations

The following items are carried forward from Section 9 of the project handoff, classified by operational status:

### 1. Pending Release Decisions

#### A. Port 25 Behavior in Replay
- **Context**: In `crates/dropsuite-core/src/proxy.rs`, the proxy listener explicitly refuses port 25 for both plain HTTP and CONNECT tunnels to prevent spam/relay abuse. In `crates/dropsuite-core/src/replay.rs`, `replay::send_with` enforces the destination policy (blocking link-local, multicast, loopback exemptions, and metadata endpoints) but does **not** enforce a port 25 refusal rule.
- **Impact**: A user could issue an HTTP/SMTP request to port 25 via Replay, whereas the same request sent through the proxy listener would receive an immediate block.
- **Decision Required**: Should Replay enforce the same port 25 restriction as the proxy listener?
- **Remediation Cost**: Minimal. Adding one conditional check in `replay::send_with` and an associated unit test.

#### B. Link-Local Behavior in Replay
- **Context**: The destination policy unconditionally blocks IPv4 link-local addresses (`169.254.0.0/16`, including standard cloud IMDS `169.254.169.254`) and IPv6 link-local addresses (`fe80::/10`). There is no provision for user overrides.
- **Impact**: Security testers attempting to use Replay against local embedded/IoT devices or ad-hoc hardware operating on link-local auto-configuration cannot do so.
- **Decision Required**: Should DropSuite maintain an absolute block on link-local destinations in Replay, or should an explicit, user-acknowledged override mechanism be designed for embedded security workflows?

#### C. Generic TLS-Failure Presentation in Replay
- **Context**: When a TLS handshake fails during Replay (e.g., untrusted self-signed certificate, invalid content type), the UI row displays "✕ Failed" and the panel title displays "Not sent". The detailed technical diagnostic message (e.g., `TLS handshake with 127.0.0.1:62736 failed: received corrupt message...`) is rendered only inside the message body.
- **Decision Required**: Is this generic failure presentation acceptable for the initial 0.1.0 release, or should the UI title and row status reflect specific TLS error categories?

### 2. Known Accepted Product Limitations

#### D. IPv4-Only Application Listener
- **Context**: `BIND_IP = "127.0.0.1"` is hard-coded in `crates/dropsuite-app/src/engine.rs`.
- **Status**: The underlying `dropsuite-core` engine fully supports IPv6 binding (`::1`), as verified in core integration tests. However, dual-stack binding or user-selectable listener IP addresses are not exposed in the desktop UI settings.
- **Classification**: Accepted product limitation for v0.1.0.

#### E. Fixed Metadata Endpoint List
- **Context**: Destination policy statically refuses link-local `169.254.0.0/16` (protecting AWS/GCP/Azure/DigitalOcean default IMDS), plus specific non-link-local metadata endpoints: Alibaba Cloud (`100.100.100.200`) and AWS IPv6 IMDS (`fd00:ec2::254`).
- **Status**: Non-link-local metadata endpoints for smaller or specialized cloud providers, if any exist, are not enumerated in the static rule set.
- **Classification**: Accepted architectural limitation.

#### F. Absence of Production Security Certification
- **Context**: DropSuite has undergone thorough automated unit, integration, and CDP acceptance testing, but has not undergone a formal external third-party penetration test, SOC2 audit, or common criteria certification.
- **Classification**: Accepted product status; must not be claimed or advertised as formally certified.

---

## Release Review Decision Matrix & Sign-Off Checklist

| Review Area | Prerequisite / Condition | Current State | Decision / Action Required |
|---|---|---|---|
| **Acceptance Suite** | 33 desktop checks + 10 Replay checks pass | **PASSED** (33/33, 10/10) | Verified; authoritative logs preserved |
| **Integrity Audit** | Zero system changes; obsolete installer untouched | **PASSED** (0 diffs) | Verified; snapshot parity confirmed |
| **Package Extraction** | Packaged exe differs only by bundle marker | **PASSED** (3 bytes in `.rdata`) | Verified; restored binary matches built exe |
| **Installer Lifecycle** | Controlled install/uninstall without data loss | **NOT TESTED** | Authorize sandbox/VM lifecycle test protocol (Area A) |
| **Code Signing** | Valid Authenticode signature & RFC 3161 timestamp | **UNSIGNED** (`NotSigned`) | Decide on EV/Standard certificate provisioning (Area B) |
| **Package Completeness** | Safe audit of 10 remaining NSIS payload blocks | **PARTIALLY INSPECTED** | Execute offline multi-block audit (Area C) |
| **Build Provenance** | Reproduce 125 workspace tests & frontend build | **LOGGED (NOT RERUN)** | Execute reproduction commands in release pass (Area D) |
| **Product Decisions** | Align Replay port 25, link-local, and TLS UX | **PENDING DECISION** | Product owner sign-off on open behaviors (Area E) |

---

## Final Recommendation

```
DISPOSITION: RC1 FUNCTIONALLY VERIFIED — NOT APPROVED FOR DISTRIBUTION
NEXT STEP: EXECUTE CONTROLLED INSTALLER LIFECYCLE AUDIT (AREA A) AND RESOLVE CODE SIGNING (AREA B)
```
