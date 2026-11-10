# Stats

`freedas stats` reports local token and cost usage from the SQLite `usage`
table. No `--json` flag exists; the output is tab-separated for scripts.

```bash
freedas stats
freedas stats --days 7
freedas stats --models
freedas stats --tools
freedas stats --project /path/to/repo
```

- Default output: `provider<TAB>model<TAB>in=<n><TAB>out=<n><TAB>cost=$x.xxxx` per (provider, model) row.
- `--models` is the same grouping with 6-decimal cost; `freedas/auto` keeps its own row because that is what the router records.
- `--tools` lists tool calls and cumulative duration.
- `--project` filters to one project (path or relative name); omitted aggregates every project.

Every model call records provider, model, input/output/cache token counts,
computed cost, and a `kind` (`primary`, `compaction`, `title`, `memory`,
`review`). If a provider does not report usage, token counts are estimated.

See [Model router](./router.md) for how the recorded model is chosen and
[CLI reference](./cli.md) for the flag list.
