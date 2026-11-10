# Local server

`freedas serve` runs the axum HTTP server that the TUI, web UI, ACP, and
relay all share. `freedas web` is `serve` plus opening the browser.

## Binding and auth

```bash
freedas serve                                # http://127.0.0.1:4096
freedas serve --port 4500
freedas serve --hostname 0.0.0.0 --allow-remote   # needs a token, see below
freedas serve --cors http://localhost:3000 --cors https://app.example.com
```

- Default bind is `127.0.0.1`, port `server.port` (default 4096).
- A non-loopback `--hostname` is refused without `--allow-remote` **and** one of `FREEDAS_SERVER_TOKEN` or `FREEDAS_SERVER_PASSWORD`; the server exits with an error otherwise.
- On loopback, requests whose `Host` header is not loopback are rejected (HTTP/1.0 requests without a Host pass).

Authentication (both optional, env-configured):

- `FREEDAS_SERVER_TOKEN` - accept `Authorization: Bearer <token>`.
- `FREEDAS_SERVER_PASSWORD` - accept HTTP Basic with username `freedas` (override with `FREEDAS_SERVER_USERNAME`).

When neither is set, the server is unauthenticated - safe on loopback only.
Comparisons are constant-time.

## Endpoints

All JSON, camelCase.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Web UI (static SPA) |
| GET | `/global/health` | `{"healthy": true, "version"}` |
| GET | `/doc` | OpenAPI document |
| GET | `/global/event` | SSE global events |
| GET | `/event` | SSE session events |
| GET | `/project` | List projects |
| GET | `/project/current` | Current project |
| GET | `/path` | cwd, root, data dirs |
| GET | `/vcs` | branch, default branch, status |
| GET/PATCH | `/config` | Read / update effective config |
| GET | `/agent` | Agents |
| GET | `/provider` | Providers |
| GET | `/provider/auth` | Auth methods |
| PUT | `/auth/{id}` | Set a credential |
| GET/POST | `/mcp` | MCP status / add server |
| GET | `/command` | Commands |
| GET | `/lsp` | LSP status |
| GET | `/formatter` | Formatter status |
| GET | `/find` | Text search (`?pattern=`) |
| GET | `/find/file` | File search (`?query=`) |
| GET | `/find/symbol` | LSP symbols (`?query=`) |
| GET | `/file` | List files (`?path=`) |
| GET | `/file/content` | Read file (`?path=`) |
| GET | `/file/status` | Tracked file status |
| GET/POST | `/session` | List / create sessions |
| GET | `/session/status` | Session statuses |
| GET/DELETE/PATCH | `/session/{id}` | Details / delete / rename |
| GET | `/session/{id}/children` | Child sessions |
| GET | `/session/{id}/todo` | Todos |
| GET | `/session/{id}/message` | List messages |
| POST | `/session/{id}/message` | Prompt and wait (`{"text","auto"}`) |
| POST | `/session/{id}/prompt_async` | Prompt without waiting |
| POST | `/session/{id}/command` | Run a slash command (`{"name","args"}`) |
| POST | `/session/{id}/shell` | Run a shell command through the permission-checked bash tool |
| POST | `/session/{id}/init` | Create/update `AGENTS.md` |
| POST | `/session/{id}/fork` | Fork at a message |
| POST | `/session/{id}/abort` | Cancel the run |
| GET | `/session/{id}/usage` | Tokens and cost |
| GET | `/session/{id}/diff` | Working-tree diff, per-file stat, untracked list |
| GET | `/session/{id}/status` | Status |
| POST | `/session/{id}/summarize` | Compact the transcript |
| POST | `/session/{id}/revert` | Undo the last turn (`{"redo": true}` re-applies) |
| POST | `/session/{id}/unrevert` | Redo |
| POST | `/session/{id}/permissions/{perm}` | Reply to a permission ask |
| GET | `/session/{id}/message/{messageID}` | One message |

## SSE events

`GET /event` streams typed events: `server.connected`, `session.created`,
`session.updated`, `session.deleted`, `session.status`, `message.updated`,
`message.part.updated`, `message.removed`, `permission.asked`,
`permission.replied`, `todo.updated`, `gate.started`, `gate.passed`,
`gate.failed`, `usage.updated`, `relay.status`, `mcp.status`, `lsp.status`,
`error`. Each carries `id`, `timestamp`, and `sessionID` where applicable.

## Clients

- `freedas attach <url>` - a live read-only transcript view of a running server.
- `freedas run --attach <url> "<task>"` - send a prompt and stream events.
- `freedas web` - the SPA served by this server at `/`.
- `freedas acp` - an ACP client in a separate process speaks to the same session runner.
- `freedas-relay-server` mirrors these events outward; see [Relay](./relay.md).
