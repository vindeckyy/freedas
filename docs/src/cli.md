# CLI reference

Everything below matches `freedas --help` and each subcommand's `--help`.

## `freedas [project]`

Start the terminal UI in the project (default current directory).

| Flag | Behavior |
|---|---|
| `-c, --continue` | Resume the most recent session |
| `-s, --session <id>` | Resume a specific session |
| `--fork` | Fork the resumed session first (requires `-c` or `-s`) |
| `--worktree [name]` | Run inside a git worktree |
| `--agent <id>` | Primary agent |
| `-m, --model <provider/model>` | Pin the model |
| `--variant <name>` | Reasoning variant |
| `--auto` | Approve asks that are not denied (conflicts with `--manual`) |
| `--manual` | Ask before every action (conflicts with `--auto`) |
| `-V, --version` | Print version |

`fd` is the same invocation when the installer added the shell function.
Non-TTY invocations print `Interactive UI requires a TTY. Use freedas run
"task" for headless runs.` and exit 0.

## `freedas run <task>`

Run one task headlessly and print the result.

| Flag | Behavior |
|---|---|
| `--format text\|json` | Output format (default `text`) |
| `-f, --file <path>` | Attach a file's contents (repeatable) |
| `--attach <url>` | Run against a remote server |
| `--title <title>` | Session title |
| `--worktree [name]` | Create a worktree first |
| `-c, --continue` / `-s, --session <id>` / `--fork` | Session resume/fork |
| `--agent <id>` / `-m, --model` / `--variant <name>` | Agent/model pin |
| `--auto` / `--manual` | Permission mode |

See [Headless runs](./headless.md) for the JSONL events and permission
semantics.

## `freedas attach <url>`

Connect a live read-only transcript view to a running `freedas serve`.
`-c`/`--session` picks the target session.

## `freedas pr <number>`

Check out a pull request (`gh pr checkout`, else `git fetch
pull/<n>/head:pr-<n>`) and start the TUI in the checkout.

## `freedas session <command>`

- `list` - recent sessions in this project (`id`, `status`, `agent`, `title`).
- `delete <id>` - delete a session and its snapshot trees.
- `fork <id> [--at <message>]` - fork a session at a message.
- `rename <id> <title>` - rename a session.

## `freedas export [id]`

Write a session as JSON to stdout (or `--output <path>`). `--sanitize` redacts
secrets. `freedas import <file>` imports a session JSON file, remapping
colliding ids.

## `freedas stats`

Local token and cost statistics. `--days <n>` filters by age, `--tools` lists
tool calls and durations, `--models` groups by recorded model (including
`freedas/auto`), `--project <path>` scopes to one project. See
[Stats](./stats.md).

## `freedas sync [apply]`

- `freedas sync` - print the import plan; `apply` writes it.
- `--json` - machine-readable plan/result.
- `--dir <path>` - scan another root.
- `--memory <file|->` - import memory records instead of a sync plan.

See [Import and sync](./import-sync.md).

## `freedas agent <command>`

- `create` - interactive or flag-driven custom agent. Flags: `--global`, `--id`, `--description`, `--mode`, `--model`, `--permission "action:resource=effect"` (repeatable).
- `list` - every active agent with mode and description.

## `freedas skill <command>`

- `list [--local] [--auto]` - registry skills, local skills, or learned skills.
- `push <name> [--dir <path>]` - package and upload a skill.
- `pull <name> [--global] [--force]` - download and extract a skill.
- `forget <id>` - delete a local skill.

## `freedas mcp <command>`

- `list` - configured servers, state, tool/prompt counts.
- `add <name> --url <url>` / `add <name> -- <command...>` - write the config entry.
- `auth <name>` - OAuth or token credential.
- `logout <name>` - remove the credential.
- `debug <name>` - connect and list tools/prompts.

## `freedas plugin [module] [command]`

- `freedas plugin <module> [--global]` - install an npm package or local plugin file.
- `list` - configured specs.
- `remove <name>` - remove a spec and installed package.
- `update [name]` - refresh installed npm plugins.

## `freedas models [--json]`

List catalog models the current credentials can actually call (provider
enabled and key present).

## `freedas providers <command>`

- `login [provider]` - interactive key prompt, env fallback, or the control-plane device flow for `freedas` when `FREEDAS_CONTROL_URL` is set.
- `list` - stored credentials.
- `logout [provider]` - remove one credential, or all provider credentials when no name is given (MCP/relay/control entries are kept).

## `freedas workspace <command>`

- `list` - workspaces from the control plane (`slug`, `name`, `role`); also caches org settings for config precedence.
- `use <slug>` - set the billing workspace in global config.

## `freedas web [--port <n>]`

Serve the web UI at `http://127.0.0.1:<port>/` (default 4096) and open the
browser on a TTY.

## `freedas serve`

Start the headless HTTP server.

| Flag | Behavior |
|---|---|
| `--port <n>` | Default `server.port` (4096) |
| `--hostname <host>` | Default `server.hostname` (`127.0.0.1`) |
| `--cors <origin>` | Allowed origin (repeatable) |
| `--allow-remote` | Permit non-loopback bind; requires `FREEDAS_SERVER_TOKEN` or `FREEDAS_SERVER_PASSWORD` |

See [Local server](./server.md).

## `freedas acp`

Agent Client Protocol server over stdio. See [ACP](./acp.md).

## `freedas relay <command>`

- `start [--foreground]` - daemonize the outbound relay connection.
- `stop` - stop the daemon.
- `share <sessionID>` / `unshare <sessionID>` - expose or hide a session.
- `status` - connection state and shared sessions.

## `freedas router <command>`

- `explain --last` - the last router decision's inputs and choice.
- `stats` - per-class attempts, successes, failures, cost.

## `freedas memory <command>`

- `list` - recall up to 50 records.
- `show <id>` / `forget <id>` - inspect or delete a record.
- `export` - write all records to stdout.

## `freedas rules`

Print the another-harness rule set verbatim. See
[Using Freedas from another harness](./another-harness.md).

## `freedas bench run`

Run a benchmark suite. Flags: `--suite <path>` (required), `--repeat <n>`
(default 1), `--router <mode>` (accepted, currently unused), `--model <ref>`,
`--json`. Each task directory provides `task.yaml` with `id`, `prompt`,
`repo`, `base_branch`, and `tests/` exit-code checks; the runner checks out
the repo, runs the agent with `--auto`, and reports pass/fail plus a summary.

## `freedas debug [what]`

Print resolved paths: config, data, state, cache, bin, project, db, logs,
snapshots, worktrees, plans. `debug db` and `debug config` print just that
path.

## `freedas upgrade [version]`

Download and install a release (default `latest`); verifies SHA-256 and keeps
`freedas.previous`. `FREEDAS_RELEASE_BASE` points at a mirror.

## `freedas uninstall`

Remove the binary, PATH line, and data/state/cache after confirmation.
`--keep-config`, `--keep-data`, `--yes`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error |
| 2 | Usage error (bad flag combination) |
| 3 | Permission blocked without an answer (`freedas run`) |
| 4 | Budget exceeded |
| 5 | `sandbox.mode = "on"` but no sandbox backend available |

## Environment variables

| Variable | Effect |
|---|---|
| `FREEDAS_HOME` | Relocate the home reference (`~`) |
| `FREEDAS_CONFIG` | One config file replaces system/global/org/project layers |
| `FREEDAS_CONFIG_DIR` | Config directory (default `~/.config/freedas`) |
| `FREEDAS_DATA` | Data directory (default `~/.local/share/freedas`) |
| `FREEDAS_STATE` | State directory (default `~/.local/state/freedas`) |
| `FREEDAS_CACHE` | Cache directory (default `~/.cache/freedas`) |
| `FREEDAS_DB` | Session database path |
| `FREEDAS_DISABLE_PROJECT_CONFIG=1` | Skip project-layer config |
| `FREEDAS_MODEL` | Override `model` for one run |
| `FREEDAS_EXPERIMENTAL_SANDBOX=false` | Opt out of the OS sandbox |
| `FREEDAS_SANDBOX_ALLOW_ALL_READS=1` | macOS sandbox: allow all reads |
| `FREEDAS_SERVER_TOKEN` / `FREEDAS_SERVER_PASSWORD` / `FREEDAS_SERVER_USERNAME` | Server auth |
| `FREEDAS_CONTROL_URL` | Control-plane base URL for device login, workspaces, and the skill registry |
| `FREEDAS_API_URL` | Control-plane fallback for the skill registry |
| `FREEDAS_GATEWAY_URL` | `freedas` provider's gateway base URL (default `http://127.0.0.1:8081/v1`) |
| `FREEDAS_RELAY_URL` / `FREEDAS_RELAY_TOKEN` | Relay WebSocket and token |
| `FREEDAS_REGISTRY` | Skill registry override |
| `FREEDAS_NPM_REGISTRY` | npm registry mirror for plugin install |
| `FREEDAS_PLUGIN_TRUST=1` | Record a process plugin's hash (first load or after change) |
| `FREEDAS_RELEASE_BASE` | Release mirror for install/upgrade |
| `FREEDAS_TEST_PROVIDER=fake` | Offline fake provider for tests |
| `FREEDAS_TUI_TIMING=1` | Print TUI startup stage timings to stderr |
| `FREEDAS_DUMP_REQUEST=1` | Fake provider: print system/message/tool byte sizes per request |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `OPENCODE_API_KEY` | Provider credentials |

