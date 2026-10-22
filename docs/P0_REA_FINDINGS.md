# P0: Reference Executable & REA Investigation Findings

**Project:** DropSuite — Open-Source Web Application Security Testing Platform  
**Target Reference:** `burpsuite_windows-x64_v2026_9_2.exe`  
**Date:** October 15, 2026  
**Status:** Complete (Evidence-Based Clean Room Analysis)

---

## 1. Reference Executable Verification

The reference executable provided in the working directory was inspected statically and forensically without execution:

* **File Name:** `burpsuite_windows-x64_v2026_9_2.exe`
* **File Size:** `436,325,392 bytes` (~416.11 MiB)
* **SHA-256 Digest:**  
  `866101D7317C8E7F0456F6C9516AD71D8AD24085A3DB0ABE5A55F03C4A25BE0F`
* **Authenticode Digital Signature:** **VALID / VERIFIED**
  * **Subject:** `CN=PortSwigger Ltd, O=PortSwigger Ltd, L=Knutsford, C=GB`
  * **Issuer:** `CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1`
  * **Serial Number:** `0897229648F71EEAF60F6663D7DBFF17`
  * **Validity:** June 4, 2025 to June 4, 2028
  * **Thumbprint:** `61E0C4B02C5A6AD9A6045FCDCECF006D3FEA87C2`

---

## 2. Binary Packaging & Decompilation Boundary

Binary header inspection identified specific markers in the initial segment:
* `install4j` (multi-platform Java installer builder)
* `Java` runtime marker
* `jvm.dll` loader integration

### Technical Implications
1. **Packaging Architecture:**  
   The binary is not a native C/C++ compiled application. It is an **Install4J native Windows PE 64-bit bootstrapper/wrapper**. Its primary role is to extract an embedded OpenJDK/JRE environment and unpack the core proprietary Java archive (`burp.jar`).
2. **Decompiler Boundaries:**  
   Standard native binary decompilation (Ghidra, IDA Pro, Hopper) would merely disassemble the Install4J runtime bootstrap stub and extraction routines, without touching the application business logic.
3. **Clean-Room Engineering Mandate:**  
   Per project policy and copyright compliance, no proprietary code or bytecode will be extracted, disassembled, or reproduced. DropSuite will be implemented strictly clean-room based on the public specifications of RFC 9110 (HTTP Semantics) and RFC 9112 (HTTP/1.1), matching the functional behavior observed in standard proxy workflows.

---

## 3. Reference Feature Analysis & DropSuite Implementation Approach

### A. Proxy Listener Architecture

* **Observed / Documented Reference Behavior:**
  * Binds to a local loopback port (default `127.0.0.1:8080`).
  * Accepts standard HTTP forward-proxy requests (`GET http://example.com/path HTTP/1.1`) and HTTPS tunnel requests (`CONNECT host:port HTTP/1.1`).
  * Decouples the network socket thread from the presentation/UI thread.
  * Captures requests before transmission to the remote server and responses before delivery back to the client browser.
* **Evidence Source:** PortSwigger public documentation, RFC 9110 / RFC 9112.
* **Confidence Level:** High (Standard protocol specification).
* **DropSuite P1 Approach:**
  * Implement an asynchronous Tokio TCP listener bound strictly to `127.0.0.1`.
  * Parse raw HTTP/1.1 request lines, headers, and body streams using `httparse` / Hyper.
  * Forward the request to the upstream target and pipe the response back to the client.
  * Disallow external network binding (`0.0.0.0`) in P1 for security.

---

### B. Traffic Inspection & Representation

* **Observed / Documented Reference Behavior:**
  * **HTTP History Table Columns:**
    * ID / Sequence ordinal (integer)
    * HTTP Method (`GET`, `POST`, `PUT`, `DELETE`, etc.)
    * Host / Target origin (e.g. `http://localhost:3000`)
    * URL Path & Query parameters
    * Response Status Code (`200 OK`, `404 Not Found`, etc.)
    * Response Content-Length (bytes)
    * MIME / Content-Type (`application/json`, `text/html`, etc.)
    * Timestamp / Duration
  * **Inspector Panel:**
    * Side-by-side or stacked tabs for Request and Response.
    * Raw view showing verbatim HTTP headers and payload body.
* **DropSuite P1 Approach:**
  * Represent each captured transaction as a canonical `TransactionRecord`:
    ```rust
    pub struct TransactionRecord {
        pub id: i64,
        pub method: String,
        pub url: String,
        pub host: String,
        pub path: String,
        pub request_headers: Vec<(String, String)>,
        pub request_body: Vec<u8>,
        pub status_code: u16,
        pub response_headers: Vec<(String, String)>,
        pub response_body: Vec<u8>,
        pub content_type: Option<String>,
        pub duration_ms: u64,
        pub timestamp: i64,
    }
    ```
  * In the React frontend, render via a virtualized table supporting search by URL, method, status code, and headers.

---

### C. Project Management & Data Persistence

* **Observed / Documented Reference Behavior:**
  * Community Edition stores history exclusively in volatile RAM; shutting down the application permanently discards all captured traffic.
  * Professional Edition persists data into proprietary `.burp` project files.
* **DropSuite P1 Approach:**
  * Provide **permanent, local-first persistence** using an embedded **SQLite** database (`dropsuite.db`).
  * Automatically persist metadata and transaction bodies.
  * On application startup, reload existing session history from SQLite.
  * Users will never lose their captured traffic upon closing the application.

---

## 4. Summary & Transition to P1 Implementation

The investigation confirms that DropSuite should implement an independent, decoupled architecture:
1. `dropsuite-core`: Rust library containing the Tokio proxy listener and SQLite persistence.
2. `dropsuite-cli`: Test harness for headless integration testing.
3. `dropsuite-desktop`: Tauri 2 GUI wrapping the core engine.
4. `frontend`: React + TypeScript UI adhering to Impeccable dark-mode design principles.
