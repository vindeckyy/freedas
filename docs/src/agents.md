# Agents

An agent is a named bundle of system prompt, mode, optional model pin, and
permission rules. `freedas agent list` prints what is active.

## Built-ins

| ID | Mode | Permissions | Purpose |
|---|---|---|---|
| `build` | primary | base config | Default coding agent: edit, run checks, show the diff |
| `plan` | primary | read-only | Deep Plan: `edit` denied, `rm *`/`git push *` denied, other `bash` asks |
| `plan-quick` | primary | read-only | Same rules as `plan` on a cheaper model tier |
| `explore` | subagent | `edit` deny, `bash` deny | Codebase search returning a file map |
| `general` | subagent | `task` deny | Research subagent that cannot spawn further subagents |

Start a session on another agent with `--agent <id>`, `/agents`, or `Tab`.
`default_agent` in config sets the initial one.

## Custom agents

A custom agent is a Markdown file in `.freedas/agents/` (project) or
`~/.config/freedas/agents/` (global). Nested paths become IDs
(`team/reviewer.md` → `team/reviewer`). The body is the system prompt;
frontmatter configures it:

```markdown
---
description: Review migrations for data loss
mode: subagent
model: anthropic/claude-sonnet-4-5
label: Migration Reviewer
permission:
  edit: deny
  bash:
    "*": ask
    "git push *": deny
---
You review database migrations. Flag any migration that drops a column,
rewrites a table, or cannot be rolled back.
```

Fields:

- `description` - shown in `agent list` and the picker.
- `mode` - `primary` (default), `subagent`, or `all`.
- `model` - `provider/model`; omitted inherits the router.
- `label` - display name in the UI.
- `disable: true` - removes a built-in with the same ID.
- `permission` - rules appended after config rules; last match wins.

A custom agent with the same ID as a built-in merges: scalars replace, the
prompt body replaces, permission rules append.

Create one interactively or non-interactively:

```bash
freedas agent create                                  # prompts
freedas agent create --id reviewer --mode subagent \
  --description "Review migrations" \
  --permission "edit:*=deny" --permission "bash:*=ask"
freedas agent create --global ...                     # writes to ~/.config/freedas/agents/
```

## Subagents

The `task` tool spawns a subagent in a child session with the target agent's
prompt, model, and permissions, the same credentials and workspace, and
`parent_id` pointing at the caller's session. Depth is limited by
`subagent_depth` (default 1): a subagent at the limit cannot call `task`.
`general` has `task` denied outright; `explore` cannot run bash or edit.

Subagent transcripts never distill memory or learn skills; usage rolls up to
the parent session. A foreground call returns the child's final text;
cancellation propagates from the parent.

## Plan and research

`plan`/`plan-quick` are the planning agents described in
[Plan mode](./plan-mode.md). `explore` and `general` are the subagents the
model reaches for through `task`; you can also pin them as the session's
agent, but their permission sets make them read-only or research-only.
