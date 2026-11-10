# Architecture

Freedas is a Rust workspace of 31 crates. One `freedas` binary plus five
service binaries (`freedas-control`, `freedas-gateway`, `freedas-review`,
`freedas-sandbox-runner`, `freedas-relay-server`). The CLI and TUI are
clients of the same in-process server: `freedas` starts the server and
attaches the TUI, `freedas serve` runs it alone, `freedas attach` connects a
second client, and `freedas run --attach` drives a remote server.

For the crate map, data flow, module responsibilities, and the session
runner's step loop, read [ARCHITECTURE.md](https://github.com/freedas/freedas/blob/main/ARCHITECTURE.md)
at the repository root. It is the authoritative document; this page only
summarizes.

## Key crates

| Crate | Role |
|---|---|
| `freedas` | CLI dispatch |
| `freedas-core` | Config, paths, ids, redaction, `PermissionMode` |
| `freedas-db` | SQLite (sessions, messages, parts, usage, memory, …) |
| `freedas-tools` | Built-in tool registry (`read`, `write`, `edit`, `bash`, `glob`, `grep`, `skill`, `todo`, `memory`, `question`, `task`, `webfetch`, `websearch`, `lsp`, `patch`, `apply_patch`, `browser`; MCP server tools appear as `<server>_<tool>`) |
| `freedas-permission` | Rule engine, shell scanner, catastrophic deny list |
| `freedas-sandbox` | `sandbox-exec` / `bwrap` profiles |
| `freedas-provider` | Provider adapters (openai, anthropic, google, openrouter, freedas, opencode-zen/go, ollama, groq, …) |
| `freedas-router` | Step classification, scoring, selection, escalation, learned stats |
| `freedas-catalog` | Model catalog and variants |
| `freedas-agent` | Built-in/custom agents, frontmatter merge |
| `freedas-skill` | Skill/command discovery, learner, registry packaging |
| `freedas-mcp` | rmcp client, OAuth, tool/prompt bridging |
| `freedas-plugin` | WASM (wasmtime), JS (QuickJS), process sidecars |
| `freedas-memory` | FTS5 recall, distillation |
| `freedas-sync` | Import sources, AGENTS.md markers, sync state |
| `freedas-server` | axum API, SSE bus, SPA assets |
| `freedas-tui` | ratatui app, pickers, permission dialog, config panel |
| `freedas-acp` | Agent Client Protocol server |
| `freedas-relay` | Outbound WSS client/daemon; `freedas-relay-server` the dashboard side |
| `freedas-standards` | Gate runner, review prompts |
| `freedas-git` | git CLI wrapper, worktrees |
| `freedas-lsp` | LSP diagnostics |
| `freedas-web` | Static SPA assets |
| `freedas-bench` | Benchmark task loading/running |
| `freedas-test-support` | Fake provider, fixtures |

Service crates: `freedas-control` (accounts, workspaces, wallet, reviews
queue, sandbox lifecycle, SCIM/OIDC, registry), `freedas-gateway`
(OpenAI-compatible proxy, metering, budgets, routing), `freedas-review`
(webhook worker, GitHub App), `freedas-sandbox-runner` (Docker/Kubernetes
jobs), `freedas-relay-server` (dashboard fanout).

## Boundaries

- The runner owns sessions; the server owns transport; the TUI/web/ACP/relay are views.
- Model calls go through `freedas-provider` directly or `freedas-gateway` when logged in to a control plane; tool subprocesses go through `freedas-sandbox`.
- The shell scanner (`freedas-permission`) is the security boundary for `bash`; the sandbox profile is the second layer.
- Control-plane state lives in Postgres; the CLI's own state lives in SQLite.
