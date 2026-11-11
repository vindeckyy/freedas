# ACP

`freedas acp` runs an Agent Client Protocol server over stdio so an editor or
IDE (Zed and other ACP clients) can drive Freedas. It is newline-delimited
JSON-RPC 2.0 on stdin/stdout.

## Methods

| Method | Behavior |
|---|---|
| `initialize` | Advertise capabilities |
| `session/new` | Create a session (`cwd`, `agent`, `model`); `agent` must be a known id or the call errors |
| `session/load` | Resume an existing session |
| `session/prompt` | Admit a prompt; `session/update` notifications stream text, reasoning, tool calls, and permission requests while the client waits. The response carries `finishReason`: `complete`, `permission`, or `cancelled`. One prompt per session at a time; a second is rejected while the first is in flight |
| `session/cancel` | Cancel the current run |
| `session/set_mode` | Switch the agent |
| `session/set_model` | Pin a model or return to `auto` |
| `fs/read_text_file` | Permission-gated read |
| `fs/write_text_file` | Permission-gated write |
| `terminal/create` | Spawn a terminal (permission-gated, sandboxed where available) |
| `terminal/output` | Read buffered output; `exitStatus` is set once the process is over |
| `terminal/wait_for_exit` | Wait for the process |
| `terminal/kill` | Kill the process |
| `terminal/release` | Release without killing |

At most 32 terminals may run at once. The cap counts running processes only:
a terminal whose process has ended holds nothing back, so it never blocks a
new one, and the newest finished terminals stay readable until they are
evicted.

The server keeps at most 64 sessions. Nothing ever closes an ACP session, so
when the limit is reached the oldest idle session - no prompt running, no
permission parked - is forgotten instead of refusing the next request. A
session with a prompt in flight is never evicted.

A request without a `sessionID` gets a `Session::fallback` rooted at the
server's cwd.

## Permissions

Anything that would `ask` inside Freedas becomes a
`session/request_permission` request to the client with allow-once /
allow-always / reject options. The client has 10 minutes to answer; a timeout
rejects. "Allow always" is session-scoped: the rule is remembered for the
rest of that session, not written to disk.

## Config

The ACP server loads config the same way the CLI does, including
`FREEDAS_DISABLE_PROJECT_CONFIG=1` to skip project-layer config.
