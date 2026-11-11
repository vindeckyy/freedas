# FAQ

## Does Freedas send my code anywhere?

Only inside the prompt sent to the model you selected, or to a
gateway/control plane you pointed it at. Sessions, memory, snapshots, and
usage are local SQLite and files. There is no telemetry.

## Which model does it use?

`freedas/auto` by default: the router classifies each step (Edit, Debug,
Planning, …) and picks the cheapest catalog model that clears the quality
floor. Pin one with `-m provider/model`, `--variant`, or config `model`.
`freedas router explain --last` shows the last decision.

## Where are my files?

`freedas debug paths`: config `~/.config/freedas/`, data
`~/.local/share/freedas/` (sessions DB, credentials, snapshots, plans),
state `~/.local/state/freedas/` (logs, relay socket), cache
`~/.cache/freedas/`. `FREEDAS_HOME` and the per-dir `FREEDAS_*` variables
relocate them.

## Can I run it without a TTY?

Yes: `freedas run "task"` (optionally `--format json`). Asks auto-reject by
default; use `--auto` to approve non-denied actions. See
[Headless runs](./headless.md).

## How do I stop a run?

Ctrl+C once aborts the current model stream and kills the tool process
group; a second press exits. In the web UI there is a stop button; over the
API `POST /session/{id}/abort`; over the dashboard `POST
/sessions/:id/abort` on the relay.

## Does it work offline?

The fake provider (`FREEDAS_TEST_PROVIDER=fake`) drives the loop without
network; real providers obviously need their API. The OS sandbox blocks tool
network access by default regardless.

## What is the difference between `--auto`, `--manual`, `bypass`, `auto`, `ask`?

`bypass`/`auto`/`ask` are `permission_mode` values (config default `auto`);
`--auto`/`--manual` are per-run CLI overrides. Details in
[Permissions](./permissions.md).

## How do custom agents, skills, and commands differ?

- Agent: a named prompt + permission + model bundle (`build`, `plan`, custom `.md`).
- Skill: a discoverable workflow the model loads on demand.
- Command: a slash command backed by a Markdown file with optional `agent`/`model`/`subtask`.

See [Agents](./agents.md), [Skills](./skills.md), [Commands](./commands.md).

## Can I import my Claude Code / Cursor setup?

Yes: `freedas sync` merges `CLAUDE.md`, `.cursor/rules`, `AGENTS.md`,
copilot/windsurf/cline instruction files into `AGENTS.md` marked sections and
copies `.claude/skills`/`.agents/skills` into `.freedas/skills/`. See
[Import and sync](./import-sync.md).

## How do pull request reviews and sandboxes bill?

Both go through your workspace wallet on the control plane: reviews as model
usage, sandboxes as compute seconds plus model usage. Details in
[Reviews](./reviews.md) and [Cloud sandboxes](./sandboxes.md).

## Does Freedas train or learn?

No model weights change. Two local mechanisms exist: router learning blends
per-class success rates into model choice (`router.learn`), and the skill
learner writes auto-generated skills from successful sessions
(`~/.config/freedas/skills/auto-*/SKILL.md`). Both are local.

## What platforms are supported?

macOS and Linux (glibc). Windows runs inside WSL; native Windows has no OS
sandbox and is not a release target. The install script puts the binary in
`~/.freedas/bin/`.

## How do I upgrade or remove it?

`freedas upgrade` replaces the binary after SHA-256 verification and keeps
`freedas.previous`. `freedas uninstall` removes the binary and data after
confirmation (`--keep-config`, `--keep-data`, `--yes`).

## Is there a hosted version?

Everything is self-hosted: `freedas-control`, `freedas-gateway`,
`freedas-review`, `freedas-relay-server`, `freedas-sandbox-runner`. There is
no managed service; run them yourself behind your own Postgres and GitHub
App.
