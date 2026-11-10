# Plan mode

Two read-only primary agents draft plans instead of making changes:

| Agent | Purpose | Model tier |
|---|---|---|
| `plan` | Deep plan | Strongest (router `Planning`, quality floor 0.90) |
| `plan-quick` | Quick plan | Cheaper (router `PlanningQuick`, floor 0.70) |

## Entering plan mode

- `freedas --agent plan` or `freedas run --agent plan "..."` starts the plan agent.
- `/deep-plan <task>` runs `plan` for one prompt, then restores the previous agent. Alias: `/plan-deep`.
- `/quick-plan <task>` runs `plan-quick` for one prompt. Alias: `/plan-quick`.
- `Tab` or `/agents` switches agents inside the TUI.

With no argument, the plan commands reuse the last prompt.

## What plan agents can do

The permission set is read-only, appended after config rules so the last match
wins:

```json
{
  "edit": { "*": "deny" },
  "bash": { "rm *": "deny", "git push *": "deny", "*": "ask" },
  "read": { "*": "allow" },
  "webfetch": { "*": "allow" },
  "websearch": { "*": "allow" }
}
```

The agent explores the codebase and writes the plan to the transcript. Plan
artifacts may be written under `~/.local/share/freedas/plans/`. Project files
cannot be edited; destructive shell commands are denied; other shell commands
ask by default.

## Using the plan

Switch to `build` (`/agents` or `Tab`) and the plan stays in the transcript as
context, so the build agent can follow it. `/deep-plan` and `/quick-plan`
restore the previous agent automatically when the single prompt finishes.

Headless:

```bash
freedas run --agent plan "design the rate limiter" --auto
```
