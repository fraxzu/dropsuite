# Fingerprint, challenge handling and the cookie jar

Bot protection scores a request on things DropSuite used to lose by default. This document
covers what the app now does about it, and the exact limits.

## What each piece does

**Header presets** (`dropsuite-core::header_preset`) supply one complete browser header set —
User-Agent, client hints and fetch metadata all agreeing on the same browser and platform.
Presets fill only names the request does not already carry, so a typed header always wins.
`Host`, `Cookie`, `Content-Length` and `Content-Type` are never supplied by a preset.

**Cookie jar** (`dropsuite-core::cookies`, table `cookies`) keeps cookies the target hands out,
scoped per host with the RFC 6265 domain, path and `Secure` rules, and refuses `__Host-` and
`__Secure-` prefix violations. Replay and Fuzzer attach matching cookies unless the request
already has a `Cookie` header. Values are stored raw: redaction applies to history, not to a jar
that must replay the real value.

**Challenge detection** (`dropsuite-core::challenge`) labels a response as a challenge, with the
vendor and kind, when a vendor marker is present. The Replay panel and Fuzzer result rows show it,
so a 403 that never reached the application is not read as an application answer.

**Challenge browser** (`open_challenge_browser`) opens the embedded WebView2 window with the host
temporarily removed from the interception allowlist, so the proxy tunnels its TLS and the page
keeps the WebView2 fingerprint. The allowlist entry returns when the window closes.
`import_challenge_cookies` copies the window's cookies into the jar.

## Using it

1. Send the request. If it comes back as a challenge, the banner names the vendor.
2. Press **Open browser** and finish the check in the window.
3. Press **Import cookies**, then send again.

For checks that are not interactive, a preset alone is often enough — set one under listener
settings before sending.

## Limits

- Detection is conservative by design: a vendor marker is required, so a plain application 403 is
  not mislabelled. A challenge page that carries no marker can still be missed.
- Harvested cookies stay bound to the address and the WebView2 fingerprint that solved them.
  Replaying from rustls can still be refused on strict sites until HTTP/2 and ClientHello mimicry
  land.
- The challenge browser needs HTTPS interception configured (the proxy owns the CA), because the
  window always goes through the listener.
- Turnstile and managed challenges cannot be solved without a browser engine; that is why the
  window exists.

## Test coverage

`crates/dropsuite-core/tests/challenge_apply_test.rs` covers preset filling, preset/typed-header
precedence, cookie attachment and matching, explicit `Cookie` precedence, off-preset byte
equality, challenge detection and the request snapshot. Unit tests live in `cookies`,
`challenge`, `header_preset`, `storage` (persistence, upsert, purge) and `platform` (date
round-trip against the jar parser).

## HTTP/2 upstream

Replay and Fuzzer offer `h2` first in ALPN and speak h2 when the destination selects it
(`dropsuite-core::http2`). Connection-only fields are dropped, `Host` becomes `:authority`, and
the response is captured under the same limits as HTTP/1.1. A destination that answers with
`http/1.1` is unaffected.

Current scope: the leg **DropSuite to the destination** for Replay and Fuzzer. Intercepted proxy
traffic still negotiates `http/1.1` upstream, and the browser-to-DropSuite leg stays HTTP/1.1.
Traffic that goes through the challenge window is tunneled, so it already keeps real browser h2
end to end.
