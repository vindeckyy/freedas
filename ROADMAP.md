# Roadmap

Status of the documented surface in this repository. "Shipped" means the
behavior exists and has tests; "next" and "later" are buckets, not dates.

## Shipped

- CLI skeleton with every documented top-level command (`freedas --help`),
  `--version`, `debug paths`, and exit codes.
- Interactive TUI: streaming transcript, tool cards, diffs, permission
  dialogs, session switcher, slash commands.
- Sessions: create, list, resume (`--continue` / `--session`), fork, rename,
  delete, export/import (JSON), Markdown export, `--sanitize`.
- Headless `freedas run` with `--format json` JSONL, stdin and `--file`
  attachments, `--worktree`, `--attach`, `--auto`, `--manual`, exit code 3
  on blocked permissions, `auto-rejecting` on stderr.
- Undo/redo: shadow-git snapshots per message and per write batch.
- Permissions: allow/ask/deny rules, whole-string globs, last-match-wins,
  remembered answers, shell scanner, catastrophic deny list.
- Local sandbox: macOS `sandbox-exec`, Linux `bwrap` (headless on by default,
  `FREEDAS_EXPERIMENTAL_SANDBOX=false` opts out).
- Providers: `openai` (OpenAI-compatible), `anthropic`, `google`/`gemini`,
  `openrouter`, `opencode-zen`, `opencode-go`, `freedas` (self-hosted
  gateway). API-key and env credential sources, stored at mode `0600`.
- Model catalog with pricing, capabilities, and quality priors; `freedas
  models`, `freedas models --json`.
- Per-step router: task-class classification, quality-floor filtering, cost
  selection, escalation, decision metadata, `router explain`, `router stats`.
- Agents: `build`, `plan`, `plan-quick`, `explore`, `general`, custom
  Markdown agents from `.freedas/agents/` and `~/.config/freedas/agents/`,
  merge/disable semantics, `agent create`/`list`.
- Skills and commands: `SKILL.md` discovery in all documented locations,
  `/skill-name` registration, `$ARGUMENTS`/`$1` expansion, `agent`/`model`/
  `subtask` frontmatter, `skill list|push|pull|forget`.
- MCP: `rmcp` client over stdio and HTTP, OAuth for remote servers,
  `mcp list|add|auth|logout|debug`, tools bridged as `<server>_<tool>`.
- Plugins: WASM (wasmtime, fuel/memory bounded, no WASI), JS/TS (QuickJS,
  memory/time capped), and process sidecars (trusted by recorded hash).
  Discovery in `.freedas/plugins/`, `plugin list|remove|update`.
- Sync/import: `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/`,
  `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`,
  `.claude/skills/`, `.agents/skills/`; managed `AGENTS.md` markers, skip
  state, dry-run, `--json`, `apply`.
- Memory: store/recall/distill/import, FTS5 search, `memory list|show|
  forget|export`.
- Git worktrees (`freedas --worktree`, `freedas run --worktree`) and
  `freedas pr <number>` checkout.
- Local server (`freedas serve`): session/message/permission/todo API, SSE
  event bus, OpenAPI at `/doc`, `freedas attach` connects a second client.
- Web UI (`freedas web`): static SPA served by `freedas-server`; sessions,
  transcript, prompt composer, permission replies, diff view.
- ACP server (`freedas acp`) over stdio.
- Relay (`freedas relay`): outbound WebSocket daemon, `share`/`unshare`/
  `status`, self-hosted `freedas-relay-server`.
- Local review rubrics: `/review`, `/standards-review`, `/standards-audit`,
  `/ui-review`, `/ui-audit`, `/code-standards`, `/ui-standards`.
- Standards gate: configured format/lint/test commands after edits, fix
  loop, `gate.passed`/`gate.failed` events.
- Control plane (`freedas-control`): workspaces, memberships, budgets,
  wallet ledger, tokens, GitHub webhook intake, usage ledger.
- Gateway (`freedas-gateway`): OpenAI-compatible proxy, `freedas/auto` and
  `freedas/auto-cheap` routing, workspace budget checks, usage metering.
- Review service (`freedas-review`): GitHub App webhook verification,
  installation-scoped checkouts, inline findings, check runs.
- Sandbox runner (`freedas-sandbox-runner`): leases `queued` rows, runs
  Docker or Kubernetes jobs, writes compute billing back to the wallet.
- Benchmark harness (`freedas bench run`): task-suite runner with
  `--router`/`--model` ablations and `--json` output.
- `freedas rules`: the another-harness rule set.

## Known gaps and limits

- **Native Windows is not a release target.** Windows users run inside WSL,
  which uses the Linux artifacts and sandbox.
- **The web UI is a zero-build static SPA**, not the Leptos WASM app the
  plan calls for. It serves the same routes and behavior through the same
  JSON/SSE API; switching to Leptos is a rendering swap, not an API change.
- **The local macOS sandbox depends on `sandbox-exec`,** which is
  deprecated but still present. If Apple removes it, the fallback is
  permission prompts with a warning.
- **Free-tier opencode models are pin-only.** They only answer the OpenCode
  client, so the router never picks them automatically; `--model
  opencode-go/<id>` still works.
- **The control-plane database is PostgreSQL-only.** The control, gateway,
  review, and sandbox-runner crates take `DATABASE_URL`/`--database-url`;
  there is no SQLite backend for those services. Integration tests that
  exercise them need a real PostgreSQL instance.
- **JS plugins run in QuickJS**, not a full Node.js runtime. Modules that
  need Node-specific APIs or native addons will not load.
- **The shell scanner is not a full shell interpreter.** It parses commands
  into an AST and resolves what it can; dynamic constructs it cannot
  resolve fall back to `ask` (or `deny` in `--auto` for destructive ones).
- **Embeddings for memory are not wired to a provider yet.** Recall uses
  FTS5 BM25 plus recency/confidence scoring.
- **`freedas upgrade` and the installer assume a release page** at the
  repository's GitHub releases URL; until one exists, `upgrade` reports
  "no release".

## Next

- Leptos WASM web app behind the existing `/api` + SSE surface.
- A second real provider adapter (OpenAI Responses API) once the catalog
  picks up models that require it.
- Memory embeddings when a configured provider is present.
- Release workflow (`cargo-dist`) and published installable artifacts.
- `freedas plugin` auth-provider and workspace-adapter surfaces.
- Kubernetes `kubectl apply --dry-run` coverage in e2e.

## Later

- Native Windows build (permission-only; sandbox still Linux/WSL).
- Stripe invoice rendering behind the existing wallet ledger.
- Control-plane OIDC/SCIM conformance tests against a live IdP.
- Router ablations reported by `freedas bench` in aggregate.
