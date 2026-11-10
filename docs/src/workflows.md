# Common workflows

Real tasks Freedas handles. Each starts with a plain-language prompt.

## Ship a feature

```
Add pagination to the audit log endpoint. Use the existing cursor pattern, add tests, and update the API docs.
```

After the edits, the standards gate runs your project's format/lint/test
commands once the edit batch ends. A failure comes back to the agent as a
synthetic user message until the checks pass or `standards.max_attempts` runs
out. See [Configuration](./configuration.md).

## Fix a bug

```
Builds fail on Node 22 with a module resolution error. Find the cause, fix it, and run the suite.
```

## Add tests to code that has none

```
Add tests for src/pricing.ts. Cover the discount tiers, the rounding rule, and the empty cart.
```

## Review a diff

```
/review
```

With an argument, `/review <sha>` reviews a commit, `/review <branch>` a
branch, and `/review <number>` a pull request (through `gh` or the GitHub
API). `/standards-review` returns a delete list for over-engineering;
`/ui-review` reports UI and UX findings. See [Slash commands](./slash-commands.md).

## Refactor without changing behavior

```
Split the billing module into invoice, refund, and webhook files. Do not change public behavior. Keep the tests passing.
```

## Upgrade a dependency

```
Upgrade the Postgres client to the next major version. Read the migration guide and fix the call sites.
```

## Write release notes

```
Write release notes for everything since v1.8.0. Group by feature, fix, and breaking change.
```

## Onboard into an unfamiliar codebase

```
Give me a tour of this codebase. What does it do, where does the work happen, and what should I read first?
```

The router classifies this as an Explore step and picks the cheapest capable
model. See [Model router](./router.md).

## Plan before building

```
/deep-plan add OAuth login with refresh tokens
```

`/deep-plan` runs the read-only `plan` agent on the strongest tier;
`/quick-plan` runs `plan-quick` on a cheaper tier. Switch back to `build` to
implement. See [Plan mode](./plan-mode.md).

## Run two agents in parallel

```bash
freedas --worktree billing-fix
freedas --worktree search-filter
```

Each session gets its own worktree under `~/.local/share/freedas/worktrees/`
with a `freedas/<name>` branch, so they never share the index. See
[Worktrees](./worktrees.md).

## Automate in CI

```bash
freedas run "review this branch for security issues" --format json
```

The JSONL stream ends with a `result` event carrying `completed` and `blocked`.
Exit code 0 is success, 3 means a blocked permission stopped the task. See
[Headless runs](./headless.md).

## Let another agent delegate to Freedas

When Claude Code or Codex runs Freedas, install the rule set from
`freedas rules` so the calling agent does not pin models. See
[Using Freedas from another harness](./another-harness.md).
