# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

DropSuite ships as a Tauri v2 desktop app on Windows (WebView2) and Linux (WebKitGTK, distributed as `.deb`, `.rpm`, `.AppImage`, and Arch `dropsuite-bin` PKGBUILD). Its design language is the app's own and does not follow the native OS look. The UI communicates with the Rust capture engine in-process over Tauri IPC (`invoke`).

## Users

The primary user is the **bug bounty hunter**: a solo researcher working on their own machine, often for long sessions spent mapping and probing a target's HTTP surface. They are cost-sensitive, and many come from Burp Suite Community Edition, where the workflows they depend on are throttled or locked behind Pro. They know HTTP, proxies and web vulnerability classes well. What they need from the tool is speed, trust in the captured evidence, and no friction between seeing a request and acting on it.

No secondary audiences (consultancies, AppSec teams, learners) are confirmed. Don't design for them unless they're added here.

## Product Purpose

DropSuite is an intercepting web security testing platform. It sits between the hunter's browser and the target, then captures, stores, inspects, replays, fuzzes, scans, and audits HTTP/HTTPS traffic. It exists so that a full professional workflow is available without a licence fee and without sending anything off the machine.

Success means a hunter can run an entire engagement in DropSuite, from proxying and history through repeating, fuzzing, scanning, and reporting, without reaching for a paid tool.

## Positioning

Two claims, held together:

1. **Free, with no paywalled core.** The workflows other tools reserve for a paid tier, such as unthrottled fuzzing, a full repeater and a persistent project history, are free and open source under the MIT License. There is no feature gate and no rate limit.
2. **Local-first, zero telemetry.** All traffic and history live in a local SQLite file (`history.db`). The app makes no analytics calls, pingbacks or remote calls of its own, and it binds to `127.0.0.1` unless the operator explicitly asks otherwise.

Rust performance and the AI-assisted audit are real capabilities, but they are not the positioning. Don't lead with them.

## Operating Context

- The hunter points a browser or HTTP client at the proxy listener (default `127.0.0.1:8080`) or opens the built-in isolated Embedded Browser (`Open Browser` / Bot-Challenge solver) directly from DropSuite, and browses the target. Traffic shows up in HTTP History live.
- The UI talks to the embedded Rust engine over Tauri IPC (`invoke`).
- Sessions are long and history grows large. The design target is tens of thousands of rows without the UI freezing.
- The work is keyboard-heavy: `j`/`k` to move between rows, `/` to search, `Esc` to clear the selection.
- Captured evidence (requests, responses, timings) feeds into the hunter's bug bounty report, with `.har` export built in.

## Capabilities and Constraints

**Shipped:**
- HTTP/1.1 forward proxy and HTTPS MITM interception on loopback (`127.0.0.1`) with dynamic per-host leaf certificates (`rcgen`/`rustls`), allowlist scoping, and Root CA PEM export.
- Isolated Embedded Browser & Bot-Challenge solver (`WebView2` on Windows, `WebKitGTK` on Linux) that trusts only DropSuite-minted leaves for their exact host and harvests clearance cookies + User-Agent into the session Cookie Jar.
- SQLite (WAL) persistence that survives restarts, with credential redaction at the persistence boundary (P1.6) plus on-demand unredacted viewing/replay.
- HTTP History table with search, method/status filtering, capture timeline, request/response split inspector (Raw, Headers, Body, Params, Hex), and `.har` export.
- Repeater with multi-tab request editing, persistent attempt history, and response diffing.
- Intruder supporting Sniper, Battering Ram, Pitchfork, and Cluster Bomb modes with configurable concurrency and delay.
- Active Scanner (`active_scan`) and Cookie Jar / Header Presets applied across Repeater, Intruder, and Scanner.
- Drop AI contextual assistant (OpenAI-compatible and Anthropic endpoints, streaming SSE, tool-assisted HTTP analysis).

**Technical constraints:**
- The core engine (`dropsuite-core`) has no GUI dependency.
- SQLite is bundled (`rusqlite` bundled).
- The project is clean-room. No PortSwigger code, bytecode or assets are used. Behaviour comes from public RFCs (9110/9112) and public documentation.
- Licence: MIT (`LICENSE`).

## Brand Commitments

- The name **DropSuite** is final.
- **Keep clear of Burp and PortSwigger.** No trade dress, layout mimicry, colour scheme, iconography or naming that could be confused with Burp Suite or PortSwigger.
- Voice: technical, plain and precise, written for an expert. No marketing tone inside the tool.

## Evidence on Hand

- `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` and `docs/P0_REA_FINDINGS.md` (the clean-room analysis).
- `docs/P1_TEST_REPORT.md` and `docs/P1_LIVE_INTEGRATION_REPORT.md`: real pass/fail results from live runs.
- `LICENSE` (MIT License) and multi-platform packaging (`packaging/arch/PKGBUILD`, `.github/workflows/build.yml`).
- **Absent, so don't fabricate:** user counts, testimonials, community size, performance benchmarks (the 50,000-row figure is a design target, not a measurement), throughput numbers, comparisons with competitors.

## Product Principles

1. **Nothing leaves the machine unless the operator sends it.** Every outbound action is explicit and visible. Local-first is a promise, not just a setting.
2. **Never gate the workflow.** No feature should feel like a teaser for a paid tier, and no throttles, nags or upsell surfaces.
3. **Evidence is sacred.** What was captured is shown exactly as it went over the wire, and anything the tool changes (redaction, decoding, prettifying) is labelled as changed.
4. **Speed at the hunter's pace.** It stays keyboard-first and dense, and it never blocks on a large history. Getting from a request to acting on it takes as few steps as possible.
5. **Its own identity.** DropSuite earns its place on its own terms, not as a reskin of the incumbent.
