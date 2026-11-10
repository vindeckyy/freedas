# Midas parity

Freedas reimplements the documented Midas surface as free, self-hosted
software. "Parity" means the same user-visible capability exists and behaves
the same way, with self-hosted replacements for Midas's hosted services. It
does not mean API compatibility with Midas servers or reuse of Midas code.
Midas paths (`midas.json`, `.midas/`, `MIDAS_*` env vars) are read as a
migration fallback and never written.

Status source of truth is `ROADMAP.md` at the repository root. "Partial"
below means the documented surface exists with a named limit; "not a target"
means the product deliberately does not implement it.

| Midas surface | Freedas implementation | Status |
|---|---|---|
| One-command install, no sudo, macOS/Linux/WSL | `install.sh`, `~/.freedas/bin/freedas`, `freedas upgrade`/`uninstall` | Partial: `install.sh` and upgrade path are in; release artifacts (cargo-dist builds, `latest.json` hosting) are not wired up |
| Interactive terminal UI | `freedas-tui` (ratatui/crossterm): streaming transcript, tool cards, diffs, permission dialogs, pickers, config panel | Implemented |
| Sessions, resume, fork, rename, delete, export, import | SQLite store, `/new`/`/sessions`/`/rename`/`/fork`/`/export`/`/move`, `session fork/rename/delete`, JSON export/import with `--sanitize` | Implemented |
| Undo/redo file edits | Shadow-git snapshots per message and per write batch; `/undo`, `/redo` | Implemented |
| Context compaction | Compaction on `small_model` at ~80% context and `/compact`; `compaction` parts, `kind=compaction` usage | Implemented |
| Plan modes | `plan`, `plan-quick` read-only agents; `/deep-plan`, `/quick-plan`; plan artifact writes under `plans/` | Implemented |
| Permissions | `freedas-permission` engine: allow/ask/deny, globs, remembered rules, agent rules, shell scanner, catastrophic deny list | Implemented |
| Local OS sandbox | `freedas-sandbox`: macOS `sandbox-exec`, Linux `bwrap`; headless on by default | Implemented (deprecated `sandbox-exec` noted) |
| Local memory | `freedas-memory`: FTS5 recall, distillation, `memory list/show/forget/export`, sync import | Implemented |
| Memory embeddings | Vector similarity | Not a target yet (FTS5 BM25 scoring only) |
| Agents and subagents | `freedas-agent`: `build`, `plan`, `plan-quick`, `explore`, `general`, custom frontmatter agents, `task` child sessions, merge/disable | Implemented |
| Skills and commands | `freedas-skill`: `SKILL.md` discovery in all documented dirs, `/skill-name`, `$ARGUMENTS`/`$1`, `agent`/`model`/`subtask` frontmatter | Implemented |
| Team skill registry | `freedas skill push|pull|list` against `freedas-control` | Implemented |
| MCP | `freedas-mcp` (`rmcp`): stdio + HTTP servers, OAuth, tools as `<server>_<tool>`, prompts as `/<server>:<prompt>`, `mcp list/add/auth/logout/debug` | Implemented |
| Plugins | `freedas-plugin`: WASM (wasmtime, no WASI, fuel/memory bounded), JS/TS (QuickJS), process sidecars (hash trust) | Implemented |
| Import/sync | `freedas-sync`: `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/`, `.windsurfrules`, `.clinerules`, copilot instructions, `.claude/skills`, `.agents/skills`; markers, hashes, dry-run | Implemented |
| Git worktrees | `--worktree`, `freedas run --worktree`, `freedas pr <n>` | Implemented |
| Headless `run` | `freedas run`: JSONL/text, stdin/file attachments, auto-reject, exit codes, `--attach`, `--worktree` | Implemented |
| Another-harness rule set | `freedas rules`, docs/another-harness.md | Implemented |
| Remote control relay | `freedas relay` daemon + `freedas-relay-server`: outbound WSS, `share`/`unshare`/`status`, dashboard prompt/interrupt/permission | Implemented |
| Cloud sandboxes | `freedas-sandbox-runner` (Docker and Kubernetes Job) + control-plane lifecycle/billing | Implemented |
| GitHub PR reviews | `freedas-review` + control plane: HMAC webhook, install tokens, inline comments, check run, dedupe by head SHA | Implemented |
| Workspaces, wallet, budgets, roles, teams | `freedas-control`: Postgres schema, ledger, budgets, memberships/teams | Implemented |
| SSO and SCIM | OIDC (`/auth/oidc/*`) and SCIM (`/scim/v2/Users`, `/Groups`) | Partial: endpoints exist; not conformance-tested against a live IdP |
| Payments | Manual credits in `wallet_ledger`; invoices generated from the ledger (`/invoices/generate`) | Partial: no card processor integration |
| CLI reference | Full `freedas --help` tree | Implemented |
| Slash commands | All documented commands plus `/model`, `/permissions`, `/config` | Implemented |
| Configuration | JSONC, `{env:}`/`{file:}`, documented precedence, `FREEDAS_DISABLE_PROJECT_CONFIG`, `FREEDAS_CONFIG` | Implemented |
| Security and data | Local-first, no telemetry, redaction, scoped tokens, sandbox egress deny | Implemented |
| Local web UI | `freedas web`: static SPA served by `freedas-server` | Partial: zero-build static app, not the Leptos WASM app; same JSON/SSE routes |
| ACP | `freedas acp` over stdio: initialize, session new/load/prompt/cancel, set_mode/set_model | Implemented |
| Stats | `freedas stats` + `/usage`: days, tools, models, project filters | Implemented |
| Benchmark harness | `freedas bench run --suite` with repeat, `--model`, `--json` | Partial: `--router <mode>` is accepted but not yet applied; no adapter suites bundled |
| Standards gate | `freedas-standards`: detected or configured commands, fix loop via synthetic messages, `gate.passed`/`gate.failed` | Implemented |
| Self-improvement | Skill learner (`auto-*` skills), router learned-quality stats | Implemented |
| Native Windows | - | Not a target; WSL only |
| OpenAI Responses API adapter | - | Not yet; OpenAI-compatible `/chat/completions` only |
| `freedas models update` remote catalog refresh | - | Not yet; catalog ships embedded |

## By area

- **Complete:** session lifecycle, TUI, permissions, sandbox, headless, agents, skills, commands, memory, sync, worktrees, MCP, plugins, server API/SSE, ACP, relay, local reviews, standards gate, control plane core (auth, workspaces, wallet, budgets, teams, invoices, registry, reviews queue, sandboxes lifecycle, relay presence), gateway, review service, sandbox runners.
- **Partial:** install packaging (no release pipeline yet), web UI rendering (static SPA), SSO/SCIM (untested against an IdP), payments (manual credits only), benchmark ablations (`--router` unused).
- **Not a target:** native Windows. **Not yet:** memory embeddings, OpenAI Responses API, remote catalog refresh.
