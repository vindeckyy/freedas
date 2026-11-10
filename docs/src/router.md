# Model router

When `model` is `freedas/auto` (the default) and no model is pinned, the
router picks the model at every model call. `freedas/auto-cheap` is the small
model used for titles and summaries.

## Task classification

Each step is classified deterministically, in order:

1. `agent == "plan"` → `Planning`; `agent == "plan-quick"` → `PlanningQuick`
2. `review_mode` → `Review`
3. First turn with `tour|explain|what does|where is|walk me through` in the prompt → `Explore`
4. `failures_so_far > 0` and the last error mentions a test/build/error → `Debug`
5. Prompt contains `refactor|rename|split|move|extract|inline` → `Refactor`
6. Prompt contains `add tests|write tests|cover|test for` → `TestWrite`
7. Prompt contains `upgrade|bump|migrate|migration guide` → `Upgrade`
8. Prompt contains `release notes|changelog|document|docs` → `Docs`
9. `files_touched > 3 || prompt.len() > 500 || tool_calls_so_far > 8` → `Feature`
10. Otherwise → `Edit`

A difficulty score adds log-scaled input size, tool-call count, failure
count, multi-file and ambiguity bonuses, and a per-class weight.

## Selection

For every model in the catalog, the router requires tool support and a
context window ≥ estimated input + 2000 tokens, and excludes the `free` tier
(pin-only). It filters candidates below the class quality floor (Planning
0.90, PlanningQuick 0.70, Debug/Refactor/Feature 0.80, Review/Upgrade 0.78,
TestWrite/Edit 0.72, Docs/Explore 0.65), relaxing the floor by 0.05 until a
candidate exists.

Estimated cost is `input/1e6 * cost_in + min(max_output, class_budget)/1e6 *
cost_out + (1 - effective_quality) * 0.02`, where `effective_quality` blends
the catalog prior with learned outcomes when `router.learn` is on. The
lowest-cost candidate wins; ties break on higher quality. With `router.learn`
on, a seeded 10% exploration pick takes the second-best candidate so the
prior keeps updating; the seed is `(session hint, step)` so a replayed run
repeats the choice.

A pinned model (`--model`, config `model`, agent/command frontmatter)
short-circuits all of this and records `mode: "pinned"`. When the workspace
balance is known, candidates above the remaining budget are filtered; if
nothing fits, the run fails with `BudgetExceeded` (exit 4).

## Escalation

Consecutive failures raise the floor by 0.05 per failure, capped by
`router.max_escalations` (default 2). A standards-gate failure counts as a
failed outcome for learning.

## Recording

The router's choice is written into assistant message metadata:

```json
{
  "router": {
    "mode": "auto",
    "task_class": "Debug",
    "score": 47.2,
    "tier": "frontier",
    "reason": "class=Debug floor=0.80 eff_q=0.84 escalations=1",
    "escalations": 1,
    "estimated_cost_usd": 0.031,
    "effective_quality": 0.84
  }
}
```

`freedas stats --models` groups usage by the recorded model, keeping
`freedas/auto` as its own row.

## Diagnostics

```bash
freedas router explain --last   # last decision inputs and choice
freedas router stats            # per-class attempts, successes, cost
```

## Config

```jsonc
{
  "router": {
    "mode": "auto",
    "quality_floor": 0.80,
    "max_escalations": 2,
    "learn": true
  }
}
```

`router.learn = false` freezes decisions to static priors and disables the
exploration pick.
