# Changelog

## 0.1.0

First public build of the free, self-hosted coding agent.

- Terminal UI with streaming transcript, tool output, permission prompts, and
  every documented slash command.
- `fd` shell keyword that opens the terminal UI (`install.sh` adds it).
- Sessions: new, resume, fork, rename, move, compact, undo/redo, export/import,
  Markdown export, clipboard copy, timestamps, reasoning toggle.
- Headless `freedas run` with JSONL output, attached files, piped stdin, and
  `auto-rejecting` reporting for blocked permissions.
- Providers: OpenAI-compatible, Anthropic, and Gemini, plus the self-hosted
  gateway; API-key credentials stored with mode 0600.
- Per-step router: task classification, cost/quality selection, escalation, and
  learned outcomes recorded per assistant message.
- Agents: `build`, `plan`, `plan-quick`, `explore`, `general`, plus custom
  Markdown agents that merge into or disable a built-in.
- Skills, commands, MCP servers, plugins, and local memory.
- Import from CLAUDE.md, GEMINI.md, Cursor, Windsurf, Cline, and Copilot, with
  managed AGENTS.md sections and per-source skip state.
- Git worktrees, PR checkout, and local diff review.
- Local server, web UI (sessions, streaming transcript, diff review including
  agent-created files, undo/redo), ACP server, and the outbound remote-control
  relay.
- OpenCode Zen and OpenCode Go providers: `freedas providers login opencode-zen`
  / `opencode-go`, model ids like `opencode-go/deepseek-v4.1-flash`; OpenAI-compatible
  streaming accumulates tool-call arguments across chunks.
- Self-hosted control plane: workspaces, wallet, budgets, sandbox lifecycle,
  and PR review records.
