# DropSuite Development Roadmap

**DropSuite:** Open-Source, High-Performance Web Security Testing Platform

---

## Phase Overview

```mermaid
gantt
    title DropSuite Engineering Roadmap
    dateFormat  YYYY-MM
    section Core Development
    P0: Clean-Room REA Analysis           :done,    des1, 2026-10, 2026-10
    P1: HTTP Proxy & History MVP           :done,    des2, 2026-10, 2026-11
    P2: HTTPS Interception & Repeater      :active,  des3, 2026-11, 2026-12
    P3: High-Speed Intruder Engine         :         des4, 2026-12, 2027-01
    P4: AI-Native Contextual Audit         :         des5, 2027-01, 2027-02
    P5: Nuclei Engine & OAST (Interactsh)  :         des6, 2027-02, 2027-03
```

---

### P0 — Clean-Room Analysis & Architecture (Status: COMPLETED ✅)
* Static forensic inspection of reference binary `burpsuite_windows-x64_v2026_9_2.exe`.
* Authenticode digital signature and Install4J marker verification.
* Selection of decoupled **Rust (Tokio) + SQLite + React (Impeccable Style)** stack.
* Architecture specification (`docs/ARCHITECTURE.md`) and REA findings report (`docs/P0_REA_FINDINGS.md`).

---

### P1 — Working MVP: Proxy & HTTP History (Status: IN PROGRESS ⏳)
* **Target:** Functional vertical slice running on Windows.
* **Core Features:**
  * Asynchronous HTTP proxy listener on `127.0.0.1:8080`.
  * Real-time request and response forwarding.
  * Embedded SQLite persistence (`dropsuite.db`) preserving full session across restarts.
  * Virtualized HTTP History table with search, status filtering, and sorting.
  * Raw Request and Response inspector panel.
  * Impeccable dark theme with JetBrains Mono typography.
  * Automated test harness verifying concurrent request capture and persistence.

---

### P2 — HTTPS Interception & Repeater (Status: COMPLETED / READY FOR MANUAL REVIEW ✅)
* Dynamic TLS certificate generation via `rcgen` / `rustls` (ECDSA P-256).
* Windows DPAPI private key protection at rest (`root-ca.key.dpapi`, CurrentUser scope).
* Rust-enforced exact host allowlist with transparent blind tunnel fallback for non-allowlisted targets.
* Separate upstream TLS session with strict hostname and certificate chain verification (`webpki-roots`).
* User-controlled CA certificate export (`.pem`) & trust setup guide in Settings.
* Replay tool updated with upstream TLS support.
* Comprehensive regression and negative test suite (9 TLS integration tests, 91 total workspace tests passing).

---

### P3 — High-Speed Intruder Engine (Future)
* Asynchronous fuzzing engine using Tokio green threads.
* Sniper, Battering Ram, Pitchfork, and Cluster Bomb attack patterns.
* Real-time payload throughput metrics (requests per second, latency percentiles).

---

### P4 — AI-Native Contextual Security Audit (Future)
* Integration with local LLMs (Ollama) and cloud APIs (Gemini/Claude).
* Contextual business-logic vulnerability detection (IDOR, Auth bypass, Token leaks).
* Automated Proof-of-Concept (PoC) generation.

---

### P5 — Community Ecosystem & Integrations (Future)
* Nuclei engine integration for community vulnerability template execution.
* Open-source OAST integration via Interactsh client.
* Export to standard formats (`.har`, Markdown report, JSON).
