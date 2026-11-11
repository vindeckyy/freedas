# Permissions

Every tool call resolves to one of three effects: `allow`, `ask`, or `deny`.
Rules are `(action, resource, effect)` triples; the last matching rule wins.

## Actions

Tool permission actions:

| Action | Tools / operations |
|---|---|
| `read` | `read`, `glob`, `grep`, `todo`, `memory`, `lsp`; also file operands of read-like shell commands (`cat`, `less`, `head`, `rg file`, …) |
| `edit` | `write`, `edit`, `patch`, `apply_patch` |
| `bash` | `bash` and the command names the shell scanner extracts |
| `external_directory` | paths outside the project root |
| `webfetch` | `webfetch` |
| `websearch` | `websearch` |
| `task` | `task` (subagent) |
| `skill` | `skill` |
| `question` | `question` |
| `browser` | `browser` |
| `<server>_<tool>` | each MCP tool, in its sanitized bridged name |

## Rule matching

- The resource is a whole-string glob: `*` matches zero or more characters including `/`, `?` matches one.
- A bash pattern ending in ` *` also matches the bare command (so `git push *` covers `git push` and `git push --force`).
- The last matching rule wins; config rules are followed by agent rules appended at the end, so an agent can tighten or loosen what the config set.
- For an operation touching several resources, any `deny` denies; otherwise any `ask` asks; otherwise allow.

## Default rules

```jsonc
[
  { "action": "*", "resource": "*", "effect": "allow" },
  { "action": "read", "resource": "*.env", "effect": "ask" },
  { "action": "read", "resource": "*.env.*", "effect": "ask" },
  { "action": "read", "resource": "*.env.example", "effect": "allow" },
  { "action": "read", "resource": "*.env.sample", "effect": "allow" },
  { "action": "read", "resource": "*.pem", "effect": "ask" },
  { "action": "read", "resource": "*.key", "effect": "ask" },
  { "action": "read", "resource": "*id_rsa", "effect": "ask" },
  { "action": "read", "resource": "*credentials.json", "effect": "ask" },
  { "action": "read", "resource": "*.aws/credentials", "effect": "ask" },
  { "action": "external_directory", "resource": "*", "effect": "ask" },
  { "action": "browser", "resource": "*", "effect": "ask" },
  { "action": "question", "resource": "*", "effect": "allow" }
]
```

A user `permission` block in any config file is appended after these
defaults, so the built-ins still apply to things you did not mention.

## Permission modes

`permission_mode` in config picks the default behavior:

| Mode | Behavior |
|---|---|
| `auto` (default) | Asks prompt (headless: auto-rejected) |
| `bypass` | Asks are approved automatically; deny rules still block |
| `ask` | Everything asks, even actions an allow rule would permit |

`--auto` forces `bypass`, `--manual` forces `ask`, for one session or run; the
flags conflict. The TUI's `/permissions` picker changes and saves the mode.
In headless runs there is nobody to answer, so an ask prints
`auto-rejecting <action>: <resource>` on stderr and the run exits 3 if it was
blocked.

## Approval and remembered rules

In the TUI an ask opens a dialog: allow once, allow always, or deny
(`a`/`A`/`d`). Allow always appends a rule to the global config
(`~/.config/freedas/freedas.json`, or the `.jsonc` variant if that is the
loaded file) so the same action/resource never asks again. ACP and the web UI
surface the same three choices through `session/request_permission` and the
permission API; remembered rules from ACP are session-scoped.

## Shell scanner

The `bash` tool never executes a command before it is scanned. The scanner
extracts:

- every simple command (argv), including pipelines, `&&`, `||`, `;`, subshells, and background jobs;
- `cd` targets (so later relative paths resolve);
- write targets from `>`, `>>`, `tee`, `cp`, `mv`, `rm`, `mkdir`, `touch`, `chmod`, `chown`, `dd`;
- read targets from read-like commands (`cat`, `bat`, `grep`, `rg`, `head`, `tail`, `less`, `more`, `source`, `wc`, `sort`, `uniq`, `cut`, `strings`, `file`, `diff`, `cmp`, `nl`, `od`, `xxd`, `tac`), which then follow the `read` rules - `cat .env` asks exactly like the read tool.

Dynamic constructs the scanner cannot resolve statically fail closed: the
command is `ask` unless an explicit bash rule already covers it. Markers
include `$(…)`, backticks, `$[…]`, `<<<`, `eval`, `sh -c`, `bash -c`, `env`,
`xargs`, `find -exec`, `git -c`, `rg --pre`, `sed -e`, and `-c`/` -e` invocations
of `python`, `node`, `perl`, `ruby`. A path that cannot be resolved
(unexpandable `~` or `$VAR`) also asks.

## Catastrophic deny list

These patterns deny regardless of mode, detected through wrappers and quoting:
`rm -rf /` and `rm -rf /*`, `mkfs`-style device writes (`dd of=/dev/…`),
`shutdown`, `reboot`, `halt`, `poweroff`, `killall`, `kill -9 1`,
`chown -R /`, and the `:(){ :|:& };:` fork bomb. The only override is an
explicit non-`*` `bash` allow rule naming the command - `--auto` alone never
overrides.

## OS sandbox layering

The permission engine is the first gate; the OS sandbox is the second. When
the sandbox is active (`sandbox.mode` `on`, or `auto` with headless), `bash`
runs inside `sandbox-exec` (macOS) or `bubblewrap` (Linux) with:

- reads limited to the project, system/toolchain paths, and temp dirs;
- writes limited to the project and temp dirs;
- network denied unless `sandbox.network = "allow"`;
- a cleared environment plus an allowlist (provider keys never reach the shell).

The sandbox contains the process; permission rules still decide whether it
runs at all. If no backend is installed, `auto` mode falls back to permission
prompts with a warning; `sandbox.mode = "on"` refuses with exit code 5.
Windows has no sandbox backend; use WSL.
