# Security and privacy

## Local first

Sessions, config, memory, credentials, snapshots, and usage live on your
machine under the data/state/config dirs (`freedas debug paths`). There is no
telemetry (`telemetry` defaults to `false` and has no implementation). Code
leaves the machine only inside the prompt sent to the selected model provider,
or to a control plane/gateway you configured.

## Credentials

- Stored in `<data>/credentials.json`, mode 0600, never printed by `mcp debug` or `providers list`.
- Environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …) are read first; stored keys are the fallback.
- The `bash` tool clears the environment for every command and re-adds only an allowlist; provider keys and tokens can never reach a shell the model wrote.
- Sensitive reads (`.env`, `*.env.*`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `.aws/credentials`) ask by default.
- `freedas export --sanitize` redacts secrets, home paths, and env values from a session export.
- Logs and memory records pass through the redactor before storing.

## Path and write safety

- Paths resolve with `canonicalize`; `..` escapes and symlinks that leave the project are rejected unless an `external_directory` rule allows them.
- Writes go to a temp file in the same directory, fsync, atomic rename, fsync on the directory; permissions are preserved.
- Before `write`/`edit`, the file's content hash must match the last read; a changed file returns a stale-read error until you re-read it.
- Shadow-git snapshots exclude `.git`, build outputs, and `.freedas` internals and never touch the real index or HEAD.

## Shell and network

- The shell scanner is fail-closed: unresolvable dynamic constructs ask. See [Permissions](./permissions.md).
- The catastrophic deny list (`rm -rf /`, `mkfs`, `dd of=/dev/*`, fork bombs, power commands, `kill -9 1`, `chown -R /`) denies in every mode; only an explicit non-`*` bash allow rule overrides.
- `webfetch` rejects private/loopback/link-local IPs, cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), and IPv4-mapped IPv6 forms; redirects re-check the target; response is capped at 5 MiB.
- `webfetch` and `websearch` have their own permission actions.

## OS sandbox

When active, `bash` runs inside `sandbox-exec` (macOS) or `bubblewrap` (Linux): writes limited to the project and temp dirs, reads limited to the project plus system/toolchain paths, no network unless `sandbox.network = "allow"`, cleared environment, process-group kill on cancel. Details and flags in [Permissions](./permissions.md#os-sandbox-layering) and [Configuration](./configuration.md).

`FREEDAS_EXPERIMENTAL_SANDBOX=false` (or `MIDAS_EXPERIMENTAL_SANDBOX=false`) opts out; `FREEDAS_SANDBOX_ALLOW_ALL_READS=1` relaxes read filtering on macOS where `sandbox-exec` rejects filtered profiles.

## Server and remote surfaces

- `freedas serve` binds loopback; non-loopback requires `--allow-remote` plus `FREEDAS_SERVER_TOKEN` or `FREEDAS_SERVER_PASSWORD`; non-loopback `Host` headers are rejected on a loopback bind.
- `freedas-relay-server` refuses a non-loopback bind without `--token`; the relay is outbound-only.
- `freedas-control`, `freedas-gateway`, `freedas-review`, `freedas-relay-server`, and `freedas-sandbox-runner` all run on your own infrastructure; provider credentials never leave them to the CLI.
- GitHub webhooks verify `X-Hub-Signature-256` and record delivery ids against replay.
- Tokens: CLI login tokens are hashed (SHA-256) and revocable; sandbox and GitHub tokens are short-lived and scoped.

## Plugins and MCP

- WASM plugins have no WASI or host imports.
- JS plugins run in QuickJS under memory and time caps with only the `freedas` global.
- Process plugins are trusted executables; they run only after `FREEDAS_PLUGIN_TRUST=1` records the file hash, and again when the hash changes. Environment is cleared except a small allowlist.
- MCP servers get the same permission rules as built-in tools (`<server>_<tool>` actions), a 5 MiB/timeout budget, and OAuth tokens stored like provider credentials.

## Audit and retention

- The control plane writes an `audit_log` for auth, token create/revoke, workspace changes, review posts, and sandbox start/stop.
- `freedas session delete` removes the session, messages, parts, snapshots, and local usage rows.
- Review records keep findings (they are posted to GitHub) but not the diff or transcript; sandbox rows keep identifiers, status, timing, and a bounded failure reason.
