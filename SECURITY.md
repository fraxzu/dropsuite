# Security

## Reporting a vulnerability

Please report security problems in DropSuite **privately**, through GitHub's
private vulnerability reporting (the repository's **Security** tab →
**Report a vulnerability**), not in a public issue. Tell what an attacker could
do, and how to reproduce it. You will hear back, and be credited in the fix
unless you prefer not to.

Note the difference between a flaw *in DropSuite* and a finding you made *with*
DropSuite against some target: the second is between you and that target's
owner, not a DropSuite vulnerability.

## What DropSuite protects

- **Your captured traffic stays local.** History lives in a local SQLite file.
  The app makes no analytics or pingback calls; it only talks to a host when
  you send a request, open the update check, or when you point a tool at it.
- **Credentials are redacted at the storage boundary.** Passwords, bearer
  tokens, session cookies and configured secrets are masked before they are
  written to disk, so the saved history does not keep the real values.
- **The root CA is explicit and never installed anywhere.** A CA exists only
  after you click Generate. Its private key is stored encrypted with Windows
  DPAPI; export returns the public certificate only. DropSuite never writes to
  the Windows or any browser trust store.
- **A single destination policy guards every outbound tool.** Proxy, intercept,
  Replay and Fuzzer all refuse unspecified, multicast and link-local addresses
  (including cloud metadata endpoints such as `169.254.169.254`), with the host
  resolved once and the connection pinned to the checked addresses.
- **API keys for Drop AI are stored protected at rest** and never logged; what
  is sent to a model is previewed and redacted first.

See `docs/SECURITY.md` for the detailed model and where each guarantee lives in
the code.

## What it cannot protect

- **DropSuite is a testing tool; you are responsible for how you use it.** It
  will send whatever you tell it to send. Use it only against systems you own
  or have written permission to test.
- **A root CA you generate is powerful.** While it exists, DropSuite can decrypt
  the HTTPS hosts on your allowlist. Trust it only in a browser profile you use
  for testing, and remove it when you are done.
- **Drop AI talks to the endpoint you configure.** If you point it at a
  third-party model, your prompt leaves your machine to that provider — review
  the preview before you send.
- **An unsigned installer** will warn on Windows SmartScreen until the release
  is code-signed. Verify the SHA-256 of what you download.

## Supported versions

DropSuite is in early development (0.x). Fixes land on the latest version;
please test against the newest release before reporting.
