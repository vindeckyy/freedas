# Commands

A command is one Markdown file in `.freedas/commands/` or
`~/.config/freedas/commands/`. The file name (minus `.md`) is the slash
command; the body is the prompt.

```markdown
---
description: Add a changeset and open the release PR
agent: build
model: anthropic/claude-sonnet-4-5
subtask: true
---
Draft the release notes from the commits since the last tag.
Use $ARGUMENTS if the user named a version. First argument: $1.
```

## Frontmatter

- `description` - shown in the `/` completion menu.
- `agent` - run this command under another agent for this invocation.
- `model` - pin the model for this invocation.
- `subtask` - `true` runs it in a child session; the parent's context stays clean.

## Argument expansion

- `$ARGUMENTS` - the full argument string after the command name.
- `$1` … `$9` - individual whitespace-separated words.

`/release v1.4.0 notes` with the example above expands `$ARGUMENTS` to
`v1.4.0 notes` and `$1` to `v1.4.0`.

## Precedence

Built-in commands outrank everything: a command file named `help.md` or
`new.md` never registers. After that, command files outrank skills, which
outrank MCP prompts. See [Slash commands](./slash-commands.md) for the
built-in list and [Skills](./skills.md) for skill discovery.

The server resolves commands the same way through `POST /session/{id}/command`
with `{"name", "args"}`; `subtask: true` forks a child session server-side.
