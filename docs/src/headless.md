# Headless runs

`freedas run "<task>"` runs one task without the TUI and prints the result to
stdout. It uses the same session runner, permissions, router, standards gate,
and snapshot machinery as interactive mode.

## Options

```
freedas run [OPTIONS] <TASK>
```

| Flag | Behavior |
|---|---|
| `--format text\|json` | `text` (default) prints the final message; `json` prints one JSONL event per line |
| `--file, -f <path>` | Append a file's contents to the prompt (repeatable) |
| `--attach <url>` | Run against a remote `freedas serve` and stream its events |
| `--title <title>` | Name the session |
| `--worktree [name]` | Create a worktree first (requires a git repo) |
| `--continue, -c` | Continue the most recent session in the project |
| `--session, -s <id>` | Continue a specific session |
| `--fork` | Fork the session before prompting (requires `--continue` or `--session`) |
| `--agent <id>` | Primary agent for the run |
| `--model, -m <provider/model>` | Pin the model |
| `--variant <name>` | Reasoning variant for the model |
| `--auto` | Approve asks that are not denied |
| `--manual` | Ask before every action (rejected without a TTY) |

`--auto` and `--manual` conflict.

## Input

Besides the task argument, `-f/--file` appends each file as
`--- <path> ---\n<contents>`, and piped stdin is appended as
`--- stdin ---\n<contents>`. Piped stdin is input, not an answer channel:
permission asks in a non-TTY run are rejected.

## Permissions headless

An `ask` with nobody to answer is auto-rejected. Each rejection prints
`auto-rejecting <action>: <resource>` to stderr and is collected in the
result's `blocked` array. `--auto` approves asks; explicit `deny` rules and
the catastrophic deny list still block. `--manual` has no one to ask either,
so headless it behaves like the default.

The local OS sandbox is required for headless runs: `auto` mode sandboxes
headless by default, and with no backend available a headless `bash` call
fails instead of falling back to unsandboxed execution — there is nobody to
approve the risk. Install `sandbox-exec`/`bwrap`, set `sandbox.mode = "off"`,
or `FREEDAS_EXPERIMENTAL_SANDBOX=false` to run bare.

## JSON events

`--format json` emits one event per line:

```json
{"type":"session.started","sessionID":"ses_...","timestamp":1760000000000}
{"type":"message.part.delta","sessionID":"ses_...","text":"..."}
{"type":"message.part.delta","sessionID":"ses_...","part":{"type":"reasoning","text":"..."}}
{"type":"message.part.updated","sessionID":"ses_...","messageID":"msg_...","part":{"type":"text","text":"..."}}
{"type":"usage","sessionID":"ses_...","provider":"anthropic","model":"claude-sonnet-4-5","inputTokens":123,"outputTokens":45,"costUSD":0.0012}
{"type":"session.marker","sessionID":"ses_...","marker":"bash"}
{"type":"tool.result","sessionID":"ses_...","tool":"bash","ok":false,"output":"no sandbox backend; refusing unsandboxed exec"}
{"type":"permission.asked","sessionID":"ses_...","permissionID":"perm_0","action":"read","resource":".env"}
{"type":"permission.replied","sessionID":"ses_...","permissionID":"perm_0","response":"reject"}
{"type":"session.error","sessionID":"ses_...","error":"cancelled"}
{"type":"session.completed","sessionID":"ses_...","completed":true,"timestamp":1760000000000}
{"type":"result","sessionID":"ses_...","text":"final answer","completed":true,"blocked":[]}
```

`completed` means the runner finished without a terminal error; `blocked`
lists auto-rejected actions. A run that recovered from a rejected tool still
reports `completed: true` but exits 3 when `blocked` is non-empty.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (including runs that recovered from a rejected tool) |
| 1 | Runtime error |
| 2 | Usage error (for example `--fork` without `--continue`/`--session`, or `--worktree` with `--attach`) |
| 3 | One or more permission asks were auto-rejected |
| 4 | Budget exceeded (`FreedasError::BudgetExceeded`) |
| 5 | `sandbox.mode = "on"` but no sandbox backend is available |

## `--attach`

`freedas run --attach http://127.0.0.1:4096 "<task>"` creates the prompt on a
running server and mirrors its SSE events to the same text or JSONL output.
`--worktree` cannot be used with `--attach` (a worktree is a local checkout;
the server owns its cwd). Server authentication uses the same bearer/basic
scheme as any client; see [Local server](./server.md).

## Examples

```bash
freedas run "add a test for the rate limiter" --auto
freedas run "explain the cache module" --format json | jq -r '.text' | tail -1
echo "the diff follows" | git diff | freedas run "review this diff" -f -
```
