# Quickstart

Install Freedas, start a session, and commit your first change. You need a
terminal and a project to work in.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/freedas/freedas/main/install.sh | bash
```

Then open a new terminal in a project and run:

```bash
cd your-project
freedas
```

## Sign in

Freedas works with a provider key. Either set an environment variable
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`,
`OPENCODE_API_KEY`, `DEEPSEEK_API_KEY`, …) or store one:

```bash
freedas providers login openai
```

The key is stored in `~/.local/share/freedas/credentials.json` (mode 0600). To
use the self-hosted gateway instead, see [Gateway](./gateway.md) and run
`freedas providers login freedas` with `FREEDAS_CONTROL_URL` pointing at your
control plane.

Inside a session, `/login` does the same thing.

## Import what you already have

```bash
freedas sync          # preview
freedas sync apply    # write the import
```

Freedas looks for CLAUDE.md, GEMINI.md, `.cursorrules`, `.cursor/rules/*.mdc`,
`.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, and skill
folders under `.claude/skills` and `.agents/skills`. Instructions merge into
`AGENTS.md` between `freedas:sync` markers; skills copy into `.freedas/skills`.
See [Import and sync](./import-sync.md).

## Make a change

Describe the change the way you would to a teammate:

```
Add input validation to the signup form, with tests, and run the suite.
```

Freedas edits the files it needs and runs checks. The TUI starts in `auto`
mode, which prompts on each ask; `--auto` (or `bypass` mode) approves asks
without prompting, and explicit `deny` rules and the catastrophic deny list
still block. Pass `--manual` to be asked every time, or change the mode with
`/permissions`. See [Permissions](./permissions.md).

## Review the diff

```
/review
```

`/undo` reverts the last message and its file edits; `/redo` puts them back.
Snapshots live outside the project in a shadow git repository, so your real
index and HEAD are never touched. A snapshot is captured lazily right before
a message's first file mutation; it is skipped (undo unavailable) when the
root contains the Freedas data directory or is too large to scan safely.

## Commit and open a pull request

```
Commit this with a clear message.
```

```
Open a pull request against main and describe what changed.
```

Freedas stages the change, writes the message, creates the branch, and opens
the pull request using `gh` when it is installed. `git push` and
`gh pr create` ask by default rules unless you have remembered an allow.

## Next

- [Interactive mode](./interactive-mode.md) - keys, dialogs, pickers.
- [Headless runs](./headless.md) - CI-friendly `freedas run` with JSONL output.
- [Plan mode](./plan-mode.md) - read-only deep and quick plans.
- [Agents](./agents.md) - custom agents and subagents.
