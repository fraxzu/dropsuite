# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

DropSuite ships as a Tauri desktop app: a native window hosting the React UI in a system webview (WebView2 on Windows). Its design language is the app's own and does not follow the native OS look. During development the same UI runs in a browser against the local daemon.

## Users

The primary user is the **bug bounty hunter**: a solo researcher working on their own machine, often for long sessions spent mapping and probing a target's HTTP surface. They are cost-sensitive, and many come from Burp Suite Community Edition, where the workflows they depend on are throttled or locked behind Pro. They know HTTP, proxies and web vulnerability classes well. What they need from the tool is speed, trust in the captured evidence, and no friction between seeing a request and acting on it.

No secondary audiences (consultancies, AppSec teams, learners) are confirmed. Don't design for them unless they're added here.

## Product Purpose

DropSuite is an intercepting web security testing platform. It sits between the hunter's browser and the target, then captures, stores, inspects and (in later phases) replays and fuzzes HTTP traffic. It exists so that a full professional workflow is available without a licence fee and without sending anything off the machine.

Success means a hunter can run an entire engagement in DropSuite, from proxying and history through repeating, fuzzing and reporting, without reaching for a paid tool.

## Positioning

Two claims, held together:

1. **Free, with no paywalled core.** The workflows other tools reserve for a paid tier, such as unthrottled fuzzing, a full repeater and a persistent project history, are free and open source. There is no feature gate and no rate limit.
2. **Local-first, zero telemetry.** All traffic and history live in a local SQLite file (`dropsuite.db`). The app makes no analytics calls, pingbacks or remote calls of its own, and it binds to `127.0.0.1` unless the operator explicitly asks otherwise.

Rust performance and the AI-assisted audit are real capabilities on the roadmap, but they are not the positioning. Don't lead with them.

## Operating Context

- The hunter points a browser or HTTP client at the proxy listener (default `127.0.0.1:8080`) and browses the target. Traffic shows up in HTTP History live.
- The UI talks to the local desktop daemon over a loopback API (`127.0.0.1:8081`), which is origin-restricted.
- Sessions are long and history grows large. The design target is tens of thousands of rows without the UI freezing.
- The work is keyboard-heavy: `j`/`k` to move between rows, `/` to search, `Esc` to clear the selection.
- Captured evidence (requests, responses, timings) feeds into the hunter's bug bounty report. Export to `.har`, Markdown and JSON is planned.

## Capabilities and Constraints

**Shipped (P1, verified in `docs/P1_LIVE_INTEGRATION_REPORT.md`):**
- An HTTP/1.1 forward proxy on loopback that supports GET, POST, PUT, DELETE, HEAD, OPTIONS and PATCH.
- SQLite (WAL) persistence that survives daemon restarts.
- An HTTP History table with substring search, a method filter and a status filter.
- A detail inspector with a request tab and a response tab, showing headers, body and duration.
- A proxy start/stop toggle and a status display.
- Redaction of credentials at the persistence boundary (P1.6): headers, cookies, secret query parameters and secret JSON/form fields, in parsed headers and raw messages alike.

**Roadmap (`docs/ROADMAP.md`):**
- P2: HTTPS interception (dynamic CA via rcgen/Rustls, CA export guide) and Repeater (parameter editor, response diff).
- P3: Intruder (Sniper, Battering Ram, Pitchfork, Cluster Bomb; throughput metrics).
- P4: AI-assisted contextual audit (local Ollama or cloud LLMs; IDOR, auth bypass and token leaks; PoC generation).
- P5: Nuclei templates, OAST via Interactsh, and exports.

**Technical constraints:**
- The engine (`dropsuite-core`) has no GUI dependency and also runs headless through `dropsuite-cli`.
- No external C DLLs (SQLite is bundled).
- The project is clean-room. No PortSwigger code, bytecode or assets are used. Behaviour comes from public RFCs (9110/9112) and public documentation.

**Undecided:**
- The licence has not been chosen. Don't state one anywhere.
- Decided in P1.6: history is sanitized at storage time and stays that way. Future Replay will take credentials explicitly per session and keep them in memory only, never persisted by default (see docs/SECURITY.md).

## Brand Commitments

- The name **DropSuite** is final.
- **Keep clear of Burp and PortSwigger.** No trade dress, layout mimicry, colour scheme, iconography or naming that could be confused with Burp Suite or PortSwigger. Tool names like "Intruder" and "Repeater" are used in the roadmap. Whether to keep them is an open naming question, so don't bake them deeper into branded UI without confirming.
- Voice: technical, plain and precise, written for an expert. No marketing tone inside the tool.

## Evidence on Hand

- `docs/ARCHITECTURE.md`, `docs/ROADMAP.md` and `docs/P0_REA_FINDINGS.md` (the clean-room analysis).
- `docs/P1_TEST_REPORT.md` and `docs/P1_LIVE_INTEGRATION_REPORT.md`: real pass/fail results from a live Windows 11 run.
- **Absent, so don't fabricate:** user counts, testimonials, community size, performance benchmarks (the 50,000-row figure is a design target, not a measurement), throughput numbers, comparisons with competitors, licence, logo or other brand assets.

## Product Principles

1. **Nothing leaves the machine unless the operator sends it.** Every outbound action is explicit and visible. Local-first is a promise, not just a setting.
2. **Never gate the workflow.** No feature should feel like a teaser for a paid tier, and no throttles, nags or upsell surfaces.
3. **Evidence is sacred.** What was captured is shown exactly as it went over the wire, and anything the tool changes (redaction, decoding, prettifying) is labelled as changed.
4. **Speed at the hunter's pace.** It stays keyboard-first and dense, and it never blocks on a large history. Getting from a request to acting on it takes as few steps as possible.
5. **Its own identity.** DropSuite earns its place on its own terms, not as a reskin of the incumbent.
