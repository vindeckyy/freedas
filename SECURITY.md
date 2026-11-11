# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | Current; security fixes land here first |

## Reporting

Please do not file a public issue for a vulnerability.

Report through **GitHub private vulnerability reporting** on the
[repository security page](https://github.com/vindeckyy/freedas/security/advisories/new).
If that channel is unavailable, open an issue with the details withheld
and ask for a private contact.

Include: the `freedas` version, your OS and arch, the exact command or
config that triggers the behavior, the expected versus actual result, and
a sanitized repro (run with `FREEDAS_LOG=debug` and
`freedas export --sanitize` where useful). Do not include credentials.

## In scope

These surfaces are security-sensitive; bugs in them get treated as
vulnerabilities:

- **Permission scanner**: bypasses that let a command write outside the
  project, read a denied secret, or run a denied operation.
- **Sandbox escapes**: tool subprocess code that escapes `sandbox-exec` or
  `bwrap` and reaches the filesystem or network outside the policy.
- **Path handling**: `..` escapes, symlink escapes, or path confusion
  that crosses an `external_directory` boundary.
- **SSRF in `webfetch`**: reaching private, link-local, loopback, or cloud
  metadata addresses.
- **Webhook signatures**: `freedas-review` accepting unsigned, replayed,
  or malleable GitHub deliveries.
- **Plugin trust**: WASM/JS plugins escaping their sandbox, or a process
  plugin running without hash approval.
- **Relay auth**: forging `hello`, replaying frames, or connecting
  without a valid token.
- **Credential handling**: keys, tokens, or `.env` contents leaking into
  logs, transcripts, exports, or the control plane.

## Out of scope

- Social engineering or issues that require the user to approve a prompt
  they were explicitly asked about (that is the permission system working).
- Bugs in upstream provider APIs, model behavior, or content the model
  generates.
- Issues that require physical access to a machine that already has the
  binary running.
- Denial-of-service against `freedas serve` on a public interface (the
  server binds localhost by default; `--allow-remote` is opt-in and is
  documented to require `FREEDAS_SERVER_TOKEN`).

## Disclosure

We aim to acknowledge within 7 days and to ship a fix or a documented
workaround within 90 days. Please give us the 90 days before public
disclosure.
