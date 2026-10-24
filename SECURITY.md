# Security policy

## Found a problem?

If you have found a security flaw in DropSuite, tell us in private first. Use
the **Security** tab on this repository → **Report a vulnerability** (GitHub's
private reporting) rather than opening a public issue. Describe what someone
could do with the flaw and how to reproduce it. We will get back to you, and
you will be credited in the fix unless you would rather stay anonymous.

Please give us a reasonable chance to ship a fix before writing about it
publicly.

## A bug in DropSuite, or something you found with it?

Because DropSuite is itself a testing tool, it is worth being clear:

- If **DropSuite behaves unsafely**, it keeps a secret it was meant to hide,
  reaches a host it should have refused, mishandles the root CA, or ships a bad
  installer or update, that is a bug in DropSuite. Report it here.
- If you **found an issue in some website while using DropSuite**, that belongs
  to that website's owner, not to this project. Report it to them, and only
  test things you are allowed to test.

## What matters most to us

Reports that show DropSuite breaking one of its own rules get priority:

- stored history or credentials that should have been masked but were not;
- the root CA private key leaving its protected storage, or trust being added
  to any certificate store;
- traffic going somewhere the destination policy is supposed to block;
- the app reaching the network when nobody asked it to;
- a tampered installer or update.

## Your side of it

DropSuite only does what you point it at. Remember that a root CA you create can
read your allowlisted HTTPS traffic until you remove it, that Drop AI sends your
prompt to whatever endpoint you set, and that an unsigned installer should be
checked against its published SHA-256.

## Versions

DropSuite is early software (0.x). Please reproduce on the latest release before
reporting; fixes go there first.
