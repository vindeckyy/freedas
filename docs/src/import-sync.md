# Import and sync

`freedas sync` imports the instruction and skill files you already have for
other agents, without touching anything outside the managed markers.

## Sources

| Source | Target | Kind |
|---|---|---|
| `CLAUDE.md` | `AGENTS.md` | merge |
| `GEMINI.md` | `AGENTS.md` | merge |
| `.cursorrules` | `AGENTS.md` | merge |
| `.cursor/rules/**/*.mdc` | `AGENTS.md` | merge, one section per file |
| `.windsurfrules` | `AGENTS.md` | merge |
| `.clinerules` | `AGENTS.md` | merge |
| `.github/copilot-instructions.md` | `AGENTS.md` | merge |
| `.claude/skills/**/SKILL.md` | `.freedas/skills/<name>/` | copy directory |
| `.agents/skills/**/SKILL.md` | `.freedas/skills/<name>/` | copy directory |

Detection is rooted at the project directory; `--dir <path>` scans a
different root. A skill's `name` frontmatter wins over its directory name.

## Preview and apply

```bash
freedas sync            # plan
freedas sync --json     # plan as JSON
freedas sync apply      # write
```

The plan prints one line per source: `CLAUDE.md -> AGENTS.md (merge)`,
`.claude/skills/release -> .freedas/skills/release (copydir)`.

## Markers and merge

Instruction files merge into `AGENTS.md` between per-source markers:

```markdown
<!-- freedas:sync:begin source="CLAUDE.md" -->
...imported content...
<!-- freedas:sync:end source="CLAUDE.md" -->
```

A re-run replaces the section in place; a new source appends a new section;
text outside the markers is never touched. If the markers are malformed
(missing end, stray end before begin, duplicates), `apply` refuses to write
instead of truncating the file.

## Conflicts and state

Skill directories copy wholesale. When the target exists and differs, the old
copy moves to `<target>.bak` before replacing, so local edits are never
silently lost.

`.freedas/sync.json` records `{source, target, hash, importedAt}` for each
applied entry; a source whose hash is unchanged is skipped, so a second
`apply` is a no-op.

## Memory import

`freedas sync --memory <file|->` imports a memory export (see
[Memory](./memory.md)).

## First-run offer

After the first session in a workspace that has import sources, the TUI shows
a one-time dialog offering to import; pressing Enter applies, Esc cancels.
`/sync` (alias `/adopt`) shows the same dialog on demand.
