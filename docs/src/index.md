# Freedas

Freedas is an open-source coding agent that runs in your terminal. It edits
your codebase, runs commands, reviews pull requests, and runs cloud sandboxes,
with per-step model routing, a standards gate, and local memory. Everything
runs on your machine or on services you host yourself.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/freedas/freedas/main/install.sh | bash
```

macOS and Linux, and Windows through WSL. No sudo required. See
[Installation](./install.md) for details.

## Start here

- [Quickstart](./quickstart.md) - install, sign in, import your existing setup, ship a change.
- [Workflows](./workflows.md) - feature, bug fix, tests, review, refactor.
- [Interactive mode](./interactive-mode.md) - the terminal UI and its keys.
- [Headless runs](./headless.md) - `freedas run` and JSONL events for scripts.
- [Configuration](./configuration.md) - `freedas.json`, permissions, agents, skills, MCP.
- [CLI reference](./cli.md) - every command and flag.
- [Slash commands](./slash-commands.md) - every `/command` in a session.
- [Feature parity](./parity.md) - what is implemented and current limits.
