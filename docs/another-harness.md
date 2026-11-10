# Using Freedas from another harness

Copy the block below into the calling agent's instruction file so it delegates
work to Freedas instead of doing it itself and does not pin models Freedas
should choose. Claude Code uses `.claude/rules/freedas.md`; Codex uses
`AGENTS.md` or `~/.codex/AGENTS.md`; other agents use their instruction file.

`freedas rules` prints the same block to stdout.

```
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
```
