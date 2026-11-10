# Web UI

`freedas web` starts the local server and prints the URL:

```bash
freedas web              # http://127.0.0.1:4096/
freedas web --port 4500
```

With a TTY it also opens the browser (macOS `open`). The page is a static
single-page app served by `freedas-server` at `/`; the same HTML backs the
control plane dashboard and the relay dashboard.

The plan's WASM app is a rendering detail: this is a zero-build SPA calling
the same JSON and SSE API, with the same routes and behavior.

## Pages

| Route | Contents |
|---|---|
| `#/` | Sessions list and the current session transcript |
| `#/session/:id` | Live transcript, prompt composer, permission replies, diff view, stop, usage |
| `#/history` | Older sessions |
| `#/new` | Project, agent, model, first prompt |
| `#/settings` | Config browser |
| `#/models` | Catalog, providers, auth |
| `#/agents` | Built-in and custom agents |
| `#/skills` | Installed and learned skills; registry push/pull |
| `#/mcp` | Servers, status, tools |
| `#/plugins` | Installed plugins |
| `#/memory` | List, search, forget, export |
| `#/usage` | Tokens and cost by model/day |
| `#/reviews` | PR review records from the control plane |
| `#/sandboxes` | Cloud sandbox lifecycle |
| `#/workspaces` | Personal and org workspaces, wallet, budgets |
| `#/relay` | Machines and shared sessions |

## What a session page can do

- Send prompts (with an explicit auto-approve toggle); the composer also accepts `/command` input.
- Watch the transcript stream over SSE; tool calls collapse under the "freedas" role.
- Answer permission asks (allow once / always / deny).
- Stop a run; view the working-tree diff including agent-created files; undo/redo the last turn.
- See token and cost totals.

The SPA never talks to providers directly; every model call goes through the
server. On the control plane it is served at `/`, `/me`, and `/org/<slug>`
and routes by hash.
