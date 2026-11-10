# Architecture

Freedas is a Rust workspace (`crates/`, edition 2024, `resolver = "3"`). One
binary, `freedas`, plus five service binaries (`freedas-control`,
`freedas-gateway`, `freedas-review`, `freedas-sandbox-runner`,
`freedas-relay-server`). The CLI and TUI are clients of the same in-process
server: `freedas` starts the server and attaches the TUI, `freedas serve`
runs it alone, `freedas attach` connects a second client, and
`freedas run --attach` drives a remote server headlessly.

## Process and crate map

```
freedas (CLI dispatch)        crates/freedas
  freedas-tui                 crates/freedas-tui
  freedas-web (static SPA)    crates/freedas-web, assets served by freedas-server
  freedas-acp                 crates/freedas-acp
  freedas-relay (client)      crates/freedas-relay
        │
        ▼
freedas-server (axum, SSE)    crates/freedas-server
        │
        ▼
freedas-session (runner)      crates/freedas-session
   ├── freedas-provider       provider trait, OpenAI/Anthropic/Gemini/OpenCode
   ├── freedas-catalog        model catalog, pricing, capabilities, quality
   ├── freedas-router         per-step classification and model selection
   ├── freedas-tools          read/write/edit/patch/bash/glob/grep/todo/…
   ├── freedas-permission     rule engine + shell scanner
   ├── freedas-sandbox        macOS sandbox-exec / Linux bwrap
   ├── freedas-agent          built-in and Markdown agents
   ├── freedas-skill          skills, commands, registry
   ├── freedas-mcp            rmcp client (stdio and HTTP)
   ├── freedas-plugin         WASM + JS/TS + process plugin host
   ├── freedas-memory         recall / distill / import
   ├── freedas-sync           import sources, AGENTS.md merge, sync state
   ├── freedas-git            worktrees, diffs, shadow-git snapshots
   ├── freedas-lsp            LSP client
   ├── freedas-db             SQLite persistence
   └── freedas-standards      format/lint/test gate and review rubrics

Hosted services:
  freedas-control             workspaces, wallet, budgets, tokens, GitHub intake
  freedas-gateway             OpenAI-compatible proxy + freedas/auto routing
  freedas-review              GitHub App webhook consumer + review worker
  freedas-sandbox-runner      Docker / Kubernetes job runner
  freedas-relay-server        self-hosted remote-control relay
  freedas-bench               benchmark harness
  freedas-test-support        fake provider and fixtures
```

## Request flow (prompt to tool call)

1. `crates/freedas/src/cmd.rs` parses the CLI, resolves `Paths` (`crates/
   freedas-core/src/paths.rs`), opens `Db` (`crates/freedas-db/src/lib.rs`),
   and builds the effective `Config` (JSONC, layered system/global/project,
   env, flags; see `crates/freedas-core/src/config.rs`).
2. `Runner::run_task` in `crates/freedas-session/src/lib.rs` admits the
   prompt, creates the session/message/part rows, takes a shadow-git
   snapshot, and assembles context: system prompt, agent prompt,
   instructions, skills, memory recall, environment, tools, history.
3. The router (`crates/freedas-router/src/lib.rs`) classifies the step
   (Planning, Debug, Refactor, Feature, Review, Upgrade, TestWrite, Edit,
   Docs, Explore), computes a difficulty score, filters the catalog by
   capability and quality floor, and picks the cheapest capable model.
   `freedas/auto` means the router decided; a pinned model records the
   concrete id.
4. The provider stream (`crates/freedas-provider/src/lib.rs`) normalizes
   OpenAI-compatible, Anthropic, and Gemini SSE into `ChatEvent`s (text,
   reasoning, tool calls, usage). Retries, backoffs, and usage accounting
   happen here.
5. Tool calls are permission-checked (`crates/freedas-permission/src/lib.rs`)
   then sandboxed (`crates/freedas-sandbox/src/lib.rs`) before execution
   (`crates/freedas-tools/src/lib.rs`). Results append as tool parts and
   loop back into the model until it finishes.
6. The standards gate runs configured checks after edits; a failure appends
   a synthetic message asking the model to fix it, up to `max_attempts`.
7. Parts, usage, and tool timing persist to SQLite on every step; `undo`
   restores the snapshot, `redo` reapplies it.

## Data model

One SQLite database at `~/.local/share/freedas/freedas.db` (WAL, foreign keys
on). The schema lives in `crates/freedas-db/src/lib.rs` and covers:

- `projects`, `sessions`, `messages`, `parts`: the transcript tree;
- `permissions`: remembered rules and pending asks;
- `todos`: the per-session task list;
- `snapshots`: message-to-shadow-git-commit SHAs;
- `usage`, `tool_usage`: tokens, cost, and tool call counts;
- `memories` (+ `memories_fts` FTS5): cross-session memory;
- `router_stats`: per-(task class, model) attempt/success/cost learning;
- `sync_state`: per-source content hashes;
- `reviews`, `sandboxes`, `workspaces`, `users`, `memberships`, `budgets`,
  `wallet_ledger`, `api_tokens`: the control-plane record mirror.

Control-plane services use the same schema on PostgreSQL via `sqlx`
(`crates/freedas-control/src/lib.rs`, `main.rs` applies embedded migrations).

## Trust boundaries

- **Tool subprocesses** run under the OS sandbox (macOS `sandbox-exec`, Linux
  `bwrap`; `crates/freedas-sandbox/src/lib.rs`). Permission rules are the
  first gate, the sandbox the second; `--auto` never overrides a deny.
- **Provider credentials** are env-first, then `<data>/credentials.json` mode
  `0600` (`crates/freedas-provider/src/credentials.rs`). MCP tokens, relay
  tokens, and control-plane keys use the same store with their own names.
- **Plugins** are sandboxed by runtime: WASM has no WASI and is fuel/memory
  bounded, JS runs in a capped QuickJS context, and process plugins need a
  recorded hash (`crates/freedas-plugin/src/lib.rs`).
- **Relay** is outbound-only: the client opens a WebSocket to
  `freedas-relay-server`, which fans events out to dashboard subscribers. No
  inbound port is opened on the user's machine.
- **Control plane and gateway** (`freedas-control`, `freedas-gateway`) are
  optional services. The gateway meters workspace usage and routes
  `freedas/auto` to a provider without exposing provider credentials.
- **Review service** (`freedas-review`) verifies `X-Hub-Signature-256`, mints
  installation tokens, and records findings only; never diffs or
  transcripts.
- **Sandbox runner** (`freedas-sandbox-runner`) leases queued jobs from the
  control database, runs them in a non-root Docker container or Kubernetes
  Job, and tears them down.
