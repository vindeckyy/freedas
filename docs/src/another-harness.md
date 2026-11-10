# Using Freedas from another harness

When Claude Code, Codex, or another agent runs Freedas headlessly, add a rule
set so Freedas picks the model for each task on its own.

`freedas rules` prints the same text below. Copy it into the calling agent's
instruction file (AGENTS.md, CLAUDE.md, or equivalent).

## Freedas run rules

This section applies only to an agent that runs the `freedas` CLI, and only when
the person asks it to use Freedas. If you are Freedas, ignore this section.

Freedas picks the model for each task on its own. Do not choose for it. Your own
model or vendor is not a reason to prefer a model.

- Run the task with `freedas run "<task>"`. Do not do the task yourself instead.
- Do not pass `--model`, `-m`, or `--variant` unless the person asks for that
  model or variant in that request. If they do, use it for that run only. A
  continued session keeps a pinned model, so start a new session after.
- Do not add or change `model` or `small_model` in a Freedas config file, or
  `model` in an agent or command frontmatter, unless the person asks for that
  change.
- If a Freedas config already pins a model, leave it and tell the person.
- Do not choose a model from `freedas models`.
- Use `--agent plan` or `--agent plan-quick` when the task is planning. Do not
  pick an agent because of its model.
- If a run fails, retry it or narrow the task. Do not add a model flag.

## Why one rule set

Naming a model is a deliberate choice for one run, so the rule set lets the
calling agent pass it only when the person asked. Planning tasks go to
`--agent plan` or `--agent plan-quick`; the build agent picks its own tier.

## Related

- [Headless runs](./headless.md) - the JSONL events a script reads.
- [Configuration](./configuration.md) - where `model` and `small_model` live.
