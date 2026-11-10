# Troubleshooting

Symptom → cause → fix. Error strings below are the real ones; grep the code for
more with `grep -rn "your message" crates/`.

## Startup and config

- **`config: <path>: invalid "model" ...: expected provider/model or freedas/auto`**
  The `model` key must be `freedas/auto`, `freedas/auto-cheap`, or
  `provider/model` with exactly one `/`. Fix the key or remove it.
- **`config: missing environment variable VAR`**
  A `{env:VAR}` substitution could not resolve. Export the variable or replace
  the value with a literal.
- **`config: file escapes config directory: <path>`** / **`config: absolute {file:} paths not allowed`**
  `{file:...}` operands must stay under the config file's directory.
- **`config: ...: <error>`** at startup
  The JSONC file failed to parse. Run `freedas debug paths` to see which file
  loaded and fix the JSON. Diagnostic commands still work; `run`/TUI refuse.
- **`Interactive UI requires a TTY. Use freedas run "task" for headless runs.`**
  You piped input or ran without a terminal. Use `freedas run` or
  `freedas --help`.
- **A project `freedas.json` is ignored**
  `FREEDAS_DISABLE_PROJECT_CONFIG=1` is set, or `FREEDAS_CONFIG` points at one
  file (it replaces all layers). `export` the right variables.

## Sessions and tools

- **`auto-rejecting bash: <command>`** in a headless run
  The command matched an `ask` rule and `--auto`/`bypass` was not active, or
  you used `--manual`. Add a permission rule, run with `--auto`, or answer in
  the TUI. Exit code 3 means at least one action was blocked.
- **`stale_read` / `file changed since last read`**
  Another writer touched the file after the model read it. Re-read the file,
  then retry the edit.
- **`file outside project root: <path>`**
  The path escaped the project (or an allowed `external_directory` rule).
  Move the file or add a permission rule; a never-ask `deny` always fails.
- **`sandbox-mode-on-unavailable` / exit code 5**
  `sandbox.mode = "on"` but neither `sandbox-exec` (macOS) nor `bwrap` (Linux)
  is available. Install the backend or switch to `auto`/`off`.
- **`standalone worktree is unavailable: not in a git repository`**
  `--worktree` needs a git checkout. Run inside a repo.
- **`cancelled` in the transcript**
  The run was interrupted (Ctrl+C, `/exit`, abort). The session is kept;
  resume with `-c` or `freedas run -c`.

## Models and providers

- **`provider credentials not found for <provider>`**
  `freedas providers login <provider>`, or set the env var. `freedas models`
  shows what the current credentials can call.
- **`budget exceeded` / exit code 4**
  The workspace wallet or budget rejected the call at the gateway. Top up or
  switch `freedas workspace use` to a funded workspace.
- **`no model selected`** / **`model is required`**
  The request reached the gateway with an empty `model`. Set `model` in
  config or pass `-m`.
- **`no upstream credential configured for provider <provider>`**
  The gateway has no key for the routed provider; pass `--provider-key
  provider=key` or the provider's env var on the gateway host.
- **`gateway missing`** / **`missing provider id`**
  `freedas` provider calls reach `FREEDAS_GATEWAY_URL`; start `freedas-gateway`
  or unset the provider.

## Permissions and MCP

- **A command denies no matter what**
  Check `freedas` diagnostics: `/debug` in the TUI prints the rules that
  matched. The catastrophic deny list wins everywhere except an explicit
  non-`*` bash allow.
- **`mcp error: failed to initialize mcp session`** / server `error` in `mcp list`
  The server failed its handshake. `freedas mcp debug <name>` prints the last
  error (no credentials). Re-auth with `freedas mcp auth <name>` or fix the
  command/URL in config.
- **A skill or command does not appear**
  Its name collides with a built-in, or the file was not discovered. See the
  discovery order in [Skills](./skills.md) and the reserved list in
  [Slash commands](./slash-commands.md).
- **`plugin requires approval: set FREEDAS_PLUGIN_TRUST=1 to record <hash>`**
  A process plugin changed or is new. Re-export `FREEDAS_PLUGIN_TRUST=1` to
  trust the shown hash, then run again.
- **`plugin has no usable entry (wasm/js/process)`**
  The spec points at a directory or package with no `plugin.wasm`, `main`
  JS/TS file, or `manifest.json` with `process.cmd`.

## Server, web, relay

- **`serve requires FREEDAS_SERVER_TOKEN or FREEDAS_SERVER_PASSWORD for remote bind`**
  You passed a non-loopback `--hostname` without credentials. Add a token or
  bind `127.0.0.1` (or use `--allow-remote` with a token set).
- **Browser did not open on `freedas web`**
  It only opens on a TTY. Copy the printed URL (`http://127.0.0.1:<port>/`)
  manually.
- **`relay socket missing ... start freedas relay start`**
  `share`/`unshare`/`stop` talk to the daemon over its socket; start it with
  `freedas relay start`.
- **`relay disabled; run freedas providers login freedas`**
  No control-plane token. Log in, then `freedas relay start`.
- **`relay loop must run on a single-threaded runtime`**
  The daemon detected it was started on a multi-threaded runtime; this is an
  internal error, report it.
- **Relay keeps reconnecting**
  `freedas relay status` prints `last error`. A revoked token shows an auth
  error; re-login. A `ws://` URL on the public internet is insecure; use
  `wss://` (the daemon allows `ws://` only for local tests).

## Headless and exit codes

- **Exit 3** - a permission was blocked without an answer; see `auto-rejecting` on stderr.
- **Exit 5** - `sandbox.mode = "on"` and no backend is installed.
- **Exit 2** - a flag conflict, such as `--auto` with `--manual`, or `--fork` without `--continue`/`--session`.
- **`--fork requires --continue or --session`**
  You passed `--fork` without resuming anything.

## Where to look

- `freedas debug paths` - every directory in use (config, data, state, cache, logs).
- `/debug` in the TUI - config paths, provider status, MCP/LSP status, last error.
- `RUST_LOG=freedas=debug` - session runner logs to stderr.
- `~/.local/share/freedas/freedas.db` - sessions, messages, parts, usage; inspect with `sqlite3`.
