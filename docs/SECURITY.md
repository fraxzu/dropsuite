# DropSuite Security: Captured-Traffic Persistence (P1.6)

## Root cause (fixed in P1.6)

Before P1.6, `proxy.rs` redacted the **parsed** header list, but stored `request_body` and `response_body` as the **complete raw wire messages** (`raw_request.to_vec()`, `raw_response.to_vec()`). Those raw blobs kept `Authorization`, `Cookie` and `Set-Cookie` in clear text. `storage.rs` inserted whatever it was given, and `GET /api/history/:id` returned it, so the clear text reached SQLite (including the WAL), the API and the Inspector's Raw view.

Secret query parameters (for example `?api_key=`) were also stored in `url` and `path`.

The P1 integration report's redaction check (test 11) passed because it inspected the parsed headers, not the raw blobs.

## Persistence boundary

All redaction lives in `crates/dropsuite-core/src/sanitize.rs`. Its single entry point, `sanitize_record`, is applied:

- **In the proxy:** once, before a captured transaction is stored or broadcast to the interface.
- **On write:** inside `StorageManager::insert_transaction`, so no caller can persist an unsanitized record.
- **On read:** in `get_transaction_by_id` and `list_summaries`, so rows written before P1.6 cannot reach the API or UI.

The sanitizer is idempotent. Forwarded traffic is never modified: the proxy forwards the original bytes, and only the captured copy is sanitized. Regression tests check this byte-for-byte.

## Policy

| Location | Rule |
|---|---|
| `Authorization`, `Proxy-Authorization` | The scheme is kept for known schemes (Basic, Bearer, Digest, …), e.g. `Bearer [REDACTED]`. Otherwise the whole value becomes `[REDACTED]`. |
| `Cookie` | Cookie names are kept; every value becomes `[REDACTED]`. |
| `Set-Cookie` | The cookie name and its attributes (Path, Domain, HttpOnly, …) are kept; the value becomes `[REDACTED]`. |
| Other headers | The value becomes `[REDACTED]` when the name contains `token`, `secret`, `password`, `apikey`, `session`, `csrf`/`xsrf`, `credential`, `signature`, `authorization`/`authentication`, `cookie`, `jwt`, `bearer` or `privatekey`, or is exactly `auth`, `key`, `sid`, `pass`, `pwd`, `pin`, `otp` or `sig`. Names are compared case-insensitively with punctuation ignored. `Access-Control-*` headers are exempt. |
| Headers with unrecognised names (P2 M2 hardening) | URLs in the value get the request-target rules (for example `X-Callback: …?access_token=…`, `Link: <…?api_key=…>`). A value written as an authorization credential keeps its scheme and loses the credential: `Bearer`, `Negotiate`, `NTLM`, `DPoP` or `GNAP` followed by one token68 of at least 8 characters, `Basic` followed by base64 that decodes to `user:password`, `Digest` or `AWS4-HMAC-SHA256` followed by parameters. Tokens in these documented formats are replaced wherever they appear in the value: JWT/JWS/JWE (`eyJ…` header, 3 or 5 base64url parts), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab `glpat-`, Slack `xox?-`/`xapp-`, Stripe secret/restricted keys and `whsec_`, Google `AIza…`, AWS access key IDs `AKIA`/`ASIA`, `sk-…` secret keys, npm `npm_`, Hugging Face `hf_`, PyPI, DigitalOcean `dop_v1_`, Shopify `shpat_`/`shpss_`, SendGrid `SG.…`. Each needs its documented alphabet and minimum length. Folded continuation lines get the same rules. |
| `Referer`, `Location`, `Content-Location` | Secret query and fragment parameters are redacted. |
| Request target, `url`, `path` | Userinfo is redacted. Query parameters and `#fragment` parameters (implicit-grant tokens) whose names match the rule above are redacted. A fragment is read as a hash route (`#/cb?key=…`, parameters after its own `?`) only when the part before that `?` holds no `=`. Otherwise the whole fragment is read as parameters, so `#access_token=…&next=/x?y=1` is redacted (fixed after a regression in the P2 M2 hardening). The same rule applies to URLs in `Referer`/`Location`/`Content-Location`, JSON string values, form values, unrecognised headers and readable bodies. Names are also checked after repeated percent-decoding (`tok%2565n`). |
| Plain-text, HTML, XML, script and other readable bodies (P2 M2 hardening) | Each run of text delimited by whitespace, quotes or angle brackets is read as a possible URL. Its userinfo, and query or fragment parameters that the request-target rules would redact, have their value replaced; every other byte is kept. HTML character references (`&amp;`, `&#38;`, `&#x3F;`, `&quest;`, `&equals;`, …) and script escapes (`&`, `\x26`, `\/`) count as the character they encode. `&ampkey=` (no `;`, read either way by browsers) counts as sensitive if either reading is. A malformed reference such as `&#xZZ;token=` is judged by the name rules, not skipped. Names containing script punctuation (`(){},:`) are not treated as URL parameters, so minified code such as `a?b:c&&(x.token=y)` is kept. |
| JSON bodies | The value of every key matching the rule is replaced with `"[REDACTED]"`, at any depth; objects and arrays are replaced whole. Formatting and key order are kept byte-for-byte. Truncated values are redacted to the end of the text. JSON is recognised by its shape, whatever the declared Content-Type: `curl -d` labels JSON as form-urlencoded (fixed during the P1.6 rollout). |
| URLs and query strings inside JSON values | Keys and string values are compared after JSON unescaping (`\uXXXX` escapes including surrogate pairs, `\/`, `\"`), so `"password"` counts as `password`. A string value shaped like a URL or query string gets the request-target rules. That covers a server echoing `"query":"?api_key=…"`, including with escaped delimiters such as `&`. Stringified JSON inside a string is redacted like JSON. Only values that changed are re-encoded; everything else keeps its bytes. An undecodable escape in a key, or in a value that carries `=`, fails closed (P2 M1/M2). |
| Nested and percent-encoded URLs | A parameter whose own name is harmless is replaced with `[REDACTED]` when its percent-decoded value holds a URL, query string or JSON with a secret, for example `next=%2Fcb%3Ftoken%3D…`. This applies in request targets, `Referer`/`Location`, form bodies and JSON values. Nesting is followed four levels deep (P2 M2). |
| Form-urlencoded bodies | Parameters matching the rule are redacted. |
| Chunked bodies | Decoded, redacted, and stored as a single chunk only when something changed. |
| Duplicate headers, any letter case, folded lines | Each line is handled independently. Folded continuations of a sensitive header are redacted. |
| Malformed head lines | A line that is not a valid `name: value` header is replaced with `[REDACTED: unparsed header line]`, never stored as-is, and so are folded continuation lines after it (P2 M2 hardening). |
| Bare non-HTTP captures | Treated as a body, using the JSON and form rules above. |

Header names, auth schemes, cookie names, status lines, methods, hosts, non-secret parameters and body fields are kept, so history stays useful for diagnosis.

## Residual risks (not covered)

- **Unrecognised names:** a secret under a name the rules do not recognise is kept unless it has one of the documented credential formats listed above. Examples: an opaque random string in `X-Custom: <random>`, `{"data":"<token>"}`, or a bare `Basic` credential without its scheme. A random string cannot be told apart from an ID or a hash, and DropSuite does not guess by entropy. Credential-format recognition applies to header values only, not to bodies. Query parameters echoed inside JSON string values, escaped or not, percent-encoded nested URLs, and URLs in plain-text and HTML bodies are covered since P2 M2.
- **URLs in free text:** only parameter values in URL contexts (after `?` or `#`) and userinfo are redacted. A bare `token=…` in prose, or `key: value` text, is kept. A redacted value runs to the next `&` or delimiter, so trailing punctuation (`)`, `,`, `.`) directly after a secret is removed with it. Parameter names containing script punctuation are skipped, as described above.
- **Ambiguous fragments:** a fragment such as `#/cb=1?key=…`, whose route part itself holds `=`, is read as parameters. The secret is still removed, but the whole value after the first `=` is replaced, `?key` included. A fragment written without any `=` (`#/cb?key`) is kept as written.
- **Replay (P2 M1/M2):** Replay tabs, their editors and their response history live in memory only (at most 12 tabs, with 20 sanitized response snapshots each), and they are discarded when the app closes. Each snapshot keeps the response and the request as sent, both sanitized like history with bodies capped at 16 KB; values typed into the editor are never kept in a snapshot. Comparison works on these snapshots only, never on omitted bodies. The editors and responses live in memory only. They are never written to SQLite, settings, logs or WebView storage, and the end-to-end test scans every file of an isolated run for a typed token. The log records only method, destination host and port, status, size and duration. History placeholders (`[REDACTED]`, omission summaries) are refused by the editor and again by the engine, so a stand-in is never sent as a real value.
- **Uninspectable bodies are not stored (P1.7).** Compressed, binary or non-UTF-8, multipart and badly framed bodies are replaced by an omission record (see below). The residual cost is diagnostic: their content is not available in history.
- **Readable text in other formats:** XML, HTML, GraphQL and plain-text bodies are stored. URLs in them get the query rules (P2 M2 hardening), but the JSON and form field rules do not apply, so a secret inside them under any other structure (an XML element, a GraphQL argument, a JavaScript variable) is kept.
- **Large bodies are not stored (P1.8).** Forwarding has no size limit, but a body larger than 16 KB is replaced by an omission record with its length and SHA-256. No part of it is kept, so its content is not available in history. Before P1.8 the proxy read only the first 16 KB of each message and forwarded and stored that fragment.
- **Not secret detection:** the policy is name-based, plus a fixed list of distinctive credential formats in header values. It does not detect secrets by entropy, and new or private token formats are not recognised.
- **Rows captured before this change:** reads apply the current policy, so the API and UI never show them. Their stored bytes keep whatever the policy at capture time kept until `dropsuite_db redact` is run (see below). `redact` has no per-record or dry-run mode: it rewrites every row the current policy changes, which `dropsuite_db audit` counts beforehand. Run it only with a current build. On 2026-10-18 the development database held one such row, a public test PNG stored before P1.7, which reads already omit. It has not been remediated.
- **Logs:** the desktop app's local log (`logs/dropsuite.log`, at most about 3 MiB) and the daemon logs never include captured headers, bodies, cookies, tokens or URLs. Upstream failures name only host and port. A panic message is cut to 200 characters; a panic inside third-party code could still word something unexpected.
- **Proxy credentials (P1.9):** `Proxy-Authorization` is removed before a request goes to the origin, and so are userinfo in the URL's Host and the other hop-by-hop fields. In history the captured request still shows the field, with its value redacted.

## Existing databases (before P1.6)

Rows captured before P1.6 keep clear-text raw messages on disk until they are remediated. Reads are already sanitized, so the API and UI no longer show them.

**Audit (read-only, prints counts only):**

```
dropsuite_db audit dropsuite.db
```

On 2026-10-16 the development database held 33 records. Six of them contained redactable raw data (5 raw requests, 5 raw responses). No URL, path or parsed-header leaks were found.

**Rollout record (2026-10-16), approved by the owner:**
1. Capture stopped and the pre-P1.6 daemon (PID 19676) ended.
2. A Windows DPAPI-encrypted backup (current user only, no plaintext copy) was created and round-trip verified.
3. The remediation ran offline and rewrote 6 records. A post-check byte scan then found one further leak: a JSON body that `curl -d` had labelled as form-urlencoded. The sanitizer was fixed, a regression test added, and the remediation re-run; it rewrote 1 more record.
4. Final state: integrity OK, all records kept, 0 records the audit would change, and 0 unredacted Authorization, Cookie, Set-Cookie or JSON token/password values in the `.db`, `-wal` and `-shm` files.
5. The daemon was rebuilt and restarted. 14/14 live checks passed with synthetic secrets, and persistence was confirmed across a further restart.
6. The encrypted backup was deleted after verification.

Copies outside the database were not touched. These include the pre-redesign review screenshots in `.impeccable/review/`, which show a synthetic test token.

**Remediation (opt-in, destructive, with the daemon stopped):**

```
dropsuite_db redact dropsuite.db --i-understand
```

This rewrites each affected row with the current policy, without deleting history. It runs with `PRAGMA secure_delete = ON`, then `wal_checkpoint(TRUNCATE)`, `VACUUM`, and a final checkpoint. A regression test verifies on a temporary database that no marker remains in the `.db`, `-wal` or `-shm` file afterwards.

A SQL `UPDATE` alone is not enough: the old bytes survive in WAL frames, free pages and unvacuumed pages. Even the full procedure cannot reach copies outside the database file, such as backups, filesystem snapshots or Windows File History, cloud-sync copies, SSD wear-levelling remnants, or file-system slack. Where those matter, the safer remediation is to export what you need and delete the old database files and their copies.

## Fail-closed storage for uninspectable bodies (implemented in P1.7)

A body is stored only when DropSuite can decode and inspect it as UTF-8 text, applying the JSON and form rules. A truncated capture that ends mid-character still counts as text.

These are replaced by an omission record, in every stored, served, logged or broadcast form:

- compressed bodies (`Content-Encoding` other than `identity`);
- binary or non-UTF-8 bodies, images and other media included;
- `multipart/*` bodies;
- undecodable chunked framing;
- bodies larger than the 16 KB capture limit (P1.8). The record carries the full observed length and the SHA-256 of the complete body (de-chunked), computed while streaming;
- bodies whose transfer stopped before completion (P1.8). The record carries the length seen so far and no hash, and no fragment is stored.

The record looks like this:

```
[DropSuite: body not stored] reason=content-encoding gzip is not decoded; content-type=application/json; length=83 bytes; sha256=<hex>
```

The SHA-256 is omitted for bodies under 64 bytes, because a hash of a short secret could be confirmed by guessing. Forwarded traffic is unchanged, and the Inspector explains each omission.

Possible next steps, not implemented:

1. **Decode, then sanitize:** decode gzip, deflate and br in `dropsuite-core`, so compressed JSON and form bodies fall under the existing rules. This covers the most common case: compressed API responses.
2. **Parse more formats:** parse `multipart/form-data` and apply the field-name rule to each part's `name`.
3. **Explicit opt-in:** a per-project opt-in, with a clear warning, to store uninspectable bodies as captured. Media is deliberately not treated as credential-free.

## Future Replay boundary (design only, not implemented)

- **Sanitized history:** history stays sanitized by default. Replay loads a sanitized request and never depends on persisted plaintext credentials.
- **Explicit credentials:** credentials are supplied explicitly per replay session, either by the user typing them or by a "use credentials from this live capture" action that copies them from in-memory traffic before sanitization.
- **In-memory only:** they are held in memory only, scoped to that Replay tab, and never written to SQLite, logs, exports or broadcasts. Sending re-applies them to the outgoing request only.
- **Opt-in persistence:** any persistent credential store would be a separate, opt-in feature with OS-level protection (Windows DPAPI or Credential Manager). It is never the default.

---

## HTTPS Interception Architecture (P2)

### 1. Local Root CA & Private Key Protection
- **Generation:** Unique ECDSA P-256 root certificate, stored in `ca/` within the OS application data folder. It is created only when the user clicks **Generate Root CA**; the proxy never creates one on its own. Without a CA, a CONNECT to an allowlisted host fails closed with `502` ("HTTPS interception needs a root CA") and is not tunneled.
- **Key Protection at Rest:** The private key is encrypted using **Windows DPAPI** (`CryptProtectData`, `CurrentUser` scope) and saved to `root-ca.key.dpapi`. It is never written in plaintext, never logged, and never included in diagnostics, databases, or version control. On non-Windows platforms, restrictive file permissions (`0600`) are applied as fallback.
- **Key Export:** The private key material is strictly unexportable through the application API or UI. Only the public root certificate (`root-ca.pem`) can be exported.
- **Removal:** The root CA files (`root-ca.pem`, `root-ca.key.dpapi`, `root-ca.meta.json`, `root-ca.params.json`) can be deleted on demand via Settings or file removal. Removal also drops the CA and cached leaf certificates from memory, so the old CA is never used again. Interception then stays off (allowlisted CONNECTs get `502`) until the user generates a new CA, which has a new key that nothing trusts yet.

### 2. Allowlist-Gated Interception
- **Rust-Enforced:** The allowlist is strictly enforced at the proxy layer (`dropsuite-core/src/proxy.rs`), not just the UI.
- **Default Scope:** Loopback development targets only (`localhost`, `127.0.0.1`, `::1`).
- **Owner-Controlled:** Users may explicitly add authorized domains (e.g. `lumens.my.id:443`). No broad wildcards.
- **Transparent Tunnel Fallback:** CONNECT requests for non-allowlisted hosts are tunneled blindly as raw TCP bytes: they are **not decrypted**, and **zero traffic** from them is recorded into SQLite history.

### 3. Leaf Certificate Issuance & Caching
- **Per-Host Leaf Generation:** Dynamically generated short-lived leaf certificates (7-day validity) signed by the DropSuite CA.
- **SAN & EKU:** Exact Subject Alternative Names (DNS name or IP address SAN) with `serverAuth` Extended Key Usage and `digitalSignature` Key Usage.
- **In-Memory Cache:** Cached in memory and reused until near expiry.

### 4. Upstream TLS Verification
- **Dual Connections:** Client-to-proxy TLS termination is strictly separate from proxy-to-origin TLS.
- **Strict Verification:** Outbound TLS to origin servers always verifies certificate chains and hostnames against Mozilla trusted roots (`webpki-roots`). DropSuite never disables TLS verification, never ignores hostname mismatches, and never adds its own CA to the upstream trust anchor.
- **Failure Handling:** Invalid upstream certificates, expired certificates, or hostname mismatches trigger immediate termination with `502 Bad Gateway`.
- **Test Roots:** `HttpsInterceptConfig::upstream_roots` and Replay's `ReplayOptions::tls_roots` replace the Mozilla roots only when a caller passes certificates. Tests do so per call; the app always passes none.
- **Replay:** `https://` Replay uses the same strict verification (Mozilla roots, hostname of the URL) and never trusts the DropSuite CA. A failed check returns a `tls` error before anything is sent.

### 5. Decrypted Data Sanitization
- All decrypted HTTPS traffic passes through the existing `sanitize_record` pipeline before entering SQLite persistence or frontend broadcast. Authorization headers, session cookies, passwords, and API keys are redacted identically to plain HTTP traffic.

### 6. Destination Policy (proxy and Replay)
- **Where:** ordinary HTTP forwarding, CONNECT (blind tunnel and interception), every request inside an intercepted session, and Replay. One rule set (`is_restricted_destination` in `dropsuite-core/src/proxy.rs`) serves all of them.
- **How:** the host is resolved once and every returned address is checked before any connection; one restricted answer refuses the request. The connection goes only to the checked addresses, never to the name again.
- **Refused:** unspecified, multicast, IPv4 link-local (`169.254.0.0/16`, including `169.254.169.254`), IPv6 link-local (`fe80::/10`), and the cloud metadata endpoints `100.100.100.200` and `fd00:ec2::254`. IPv4-mapped, legacy IPv4-compatible and well-known NAT64 (`64:ff9b::/96`) forms are judged as the IPv4 address they carry; network-specific NAT64 prefixes are not decoded.
- **Allowed:** loopback and private networks (RFC 1918, `100.64.0.0/10`, IPv6 unique-local) stay reachable for local testing, except the exact endpoints above.
- **Independent of the allowlist:** the interception allowlist only decides whether an allowed CONNECT is decrypted or tunneled blind; it never permits a refused destination. Replay does not use the allowlist.
- **Loops and SMTP:** the proxy refuses requests addressed to its own listener (`508`) and refuses port 25 for CONNECT and plain HTTP forwarding. Replay refuses the running listener (`loop`) but has no port 25 rule.
- **Replay errors:** a refused destination is reported as `blocked` and shown as "Not sent: restricted address", with the destination, the resolved address and the rule that refused it.


### 7. Embedded Browser Zero-Install Trust Boundary (WebView2)
- **Zero OS Modification:** Embedded WebView2 browser traffic is routed through the local proxy (WebviewWindowBuilder::proxy_url), without installing DropSuite's Root CA into the Windows System Certificate Store (certutil / Windows Root Store).
- **Leaf Cache Verification (Anti-Spoofing):**
  - Trust decisions in ICoreWebView2ServerCertificateErrorDetectedEventHandler are evaluated against LeafCache, an in-memory Arc<RwLock<LeafCache>> shared with HttpsInterception.
  - Rather than checking for the mere presence of DropSuite's Root CA in the presented chain (which could be forged by a malicious upstream server on blind tunnels), the handler checks that the presented leaf's SHA-256 fingerprint exists in DropSuite's actively minted leaves.
  - The leaf's private key never leaves memory and is signed exclusively by DropSuite's DPAPI-protected CA key.
- **Strict Host-Binding & URL Normalization:**
  - The request host is extracted strictly from RequestUri() via WHATWG URL parsing (extract_host_from_uri).
  - Immune to userinfo spoofing (e.g., https://spoof@evil.com/ parses to evil.com). Custom ports, paths, queries, fragments, and trailing dots are stripped and normalized to lowercase.
  - Cross-host leaf replay (e.g. presenting a lumens.my.id leaf when navigating to evil.com) is rejected (CANCEL).
- **Fail-Closed Error Precedence:**
  - Dangerous certificate errors (COMMON_NAME_IS_INCORRECT, EXPIRED, REVOKED) are caught first and unconditionally cancelled (CANCEL).
  - Only COREWEBVIEW2_WEB_ERROR_STATUS_CERTIFICATE_IS_INVALID (status 5, Windows Schannel untrusted root) is eligible for ALWAYS_ALLOW, and only when fingerprint and host-binding match.
  - Poisoned locks or unexpected errors fail closed (CANCEL).
- **Data Directory & Session Isolation:**
  - The embedded browser runs with an isolated data directory (data_directory: .../embedded-browser), ensuring ALWAYS_ALLOW certificate overrides are confined strictly to that test browser session and never leak into the main DropSuite application or system browser.
  - Starting the window at bout:blank ensures the COM event handler is fully registered before the first navigation occurs.
