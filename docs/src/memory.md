# Memory

Freedas stores local memory in the SQLite database and recalls relevant
records into each turn. Nothing leaves the machine except what the selected
model already sees in the prompt.

## Kinds

- `fact` - stable truths about the user or project.
- `preference` - how work should be done.
- `decision` - why something is the way it is.
- `lesson` - what to do differently next time.

Scope is `project` (stored with the project id) or `user` (global).

## Recall

Before each turn, when `memory.enabled` is on:

- `memory.profile` injects a compact profile of the top 20 stored
  facts/preferences.
- An FTS5 query built from the prompt returns up to `memory.recall.limit`
  (default 8) relevant records, injected as a `Memory:` block.

Embeddings are not wired to a provider yet, so recall is BM25 plus the stored
fields.

## Writes

- Explicit prompts: "remember", "from now on", "always", "never", "prefer" at
  12+ characters store a `preference` record.
- Lessons: a completed run whose final text mentions a resolved error stores a
  `lesson` record (first matching line, capped at 400 chars, secrets redacted).
- Session distillation runs only when `memory.distill.enabled` is on, the run
  completed, and the session is not a subagent; at most 20 records per
  session, exact-duplicate text skipped.

## Import

`freedas sync --memory <file|->` parses an exported memory file. `##` headings
map sections to kinds (`instructions`, `preferences` → preference;
`identity`, `career`, `projects` → fact; `decisions` → decision; `lessons` →
lesson; anything else → fact). Lines like `[2026-01-31] - text` drop the date;
plain lines and `- ` bullets become records in the current section. Records
land in user scope with confidence 0.7.

## Manage

```bash
freedas memory list            # up to 50 records in the current project
freedas memory list --global   # all scopes
freedas memory show <id>       # one record with scope/kind/confidence
freedas memory forget <id>     # project records only; --global for user scope
freedas memory export          # write all records to stdout
```

Commands are scoped to the current project by default — `forget` refuses to
delete another project's records without `--global` — and `list`/`show`
output passes through the redactor. Deleting a record leaves a tombstone so
it is not re-distilled, re-imported, or re-added by the agent's `memory`
tool.

## Config

```jsonc
{
  "memory": {
    "enabled": true,            // recall + writes
    "profile": true,            // standing profile block
    "recall": { "limit": 8 },
    "distill": { "enabled": true }
  }
}
```

Secrets, tokens, and full file contents are never intended as memory; records
go through the redactor before storing.
