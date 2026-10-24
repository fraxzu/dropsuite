# Security policy

## Reporting a vulnerability in DropSuite

Use GitHub's **private** vulnerability reporting on this repository (the
**Security** tab → **Report a vulnerability**), not a public issue. Include what
an attacker could achieve and the steps to reproduce it. We aim to reply
quickly and will credit you in the fix unless you ask us not to.

## Is it a DropSuite bug, or a finding you made *with* DropSuite?

DropSuite is a security tool, so these two get confused a lot:

- **A DropSuite vulnerability** is a flaw in the app itself — for example, it
  leaks a stored credential it was supposed to redact, decrypts a host you never
  allowlisted, opens a connection the destination policy should have refused, or
  an installer/auto-update problem. **Report these here.**
- **A finding you made against some website using DropSuite** is between you and
  that site's owner. That is not a DropSuite vulnerability — please do not file
  it here, and only test targets you are authorized to test.

## The flaws we care about most

Anything that breaks one of DropSuite's promises:

- captured history or credentials escaping redaction on disk;
- the root CA private key leaving its DPAPI-protected storage, or trust being
  installed into any store;
- an outbound connection the destination policy should refuse (loopback,
  link-local, cloud metadata such as `169.254.169.254`);
- the app contacting the network when the operator did not ask it to;
- installer or auto-update tampering.

## Using DropSuite responsibly

DropSuite does exactly what you tell it. A root CA you generate can decrypt your
allowlisted HTTPS hosts for as long as it exists — trust it only in a browser
profile you keep for testing, and remove it when you are done. Drop AI sends
your prompt to the endpoint you configure, so review the preview before you
send. Installers are unsigned for now, so verify the published SHA-256 of what
you download.

## Supported versions

DropSuite is in early (0.x) development. Fixes land on the newest release;
please reproduce against it before reporting.
