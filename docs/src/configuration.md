# Configuration

Freedas reads JSONC config files (comments and trailing commas allowed) from
several layers and merges them. `freedas debug paths` shows every path in
use.

## Precedence

Lowest to highest:

1. Built-in defaults.
2. System config: `/etc/freedas/freedas.json`, then `.jsonc`.
3. Global config: `~/.config/freedas/freedas.json`, then `.jsonc`.
4. Cached organization settings (`<cache>/org-settings.json`, written by `freedas workspace list|use` and `/org`).
5. Project config: `freedas.json`, then `freedas.jsonc`, then the `.freedas/` versions — in the project directory only. `FREEDAS_CONFIG_ANCESTORS=1` additionally walks every ancestor directory to `/` (farthest first, same order); it stays opt-in because a writable parent directory could otherwise plant config.
6. Environment overrides.
7. CLI flags.

`FREEDAS_DISABLE_PROJECT_CONFIG=1` skips step 5. `FREEDAS_CONFIG`
replaces steps 2-5 with one file. In an untrusted project layer,
`trust_project_code` (always), `server`, `sandbox`, `standards`,
`permission_mode: bypass`, and `{env:}`/`{file:}` under sensitive keys are
ignored until `trust_project_code` is set in a global layer.

Merge rules: objects deep-merge; arrays (such as `instructions`, `skills`,
`plugin`) concatenate; scalars replace; `permission` rules append so the last
match wins.

## Substitution

String values support two substitutions after parsing:

- `{env:VAR}` - replaced by the environment variable; a missing variable is a config error (`missing environment variable VAR`).
- `{file:path}` - reads a UTF-8 file relative to the config file's directory, trimmed. Absolute paths, `..`, and escapes outside the config directory are rejected; the file is capped at 1 MiB.

## Keys

Every top-level key, with its type and default:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `$schema` | string | none | Schema URL; ignored |
| `model` | string | `freedas/auto` | `freedas/auto`, `freedas/auto-cheap`, or `provider/model` |
| `small_model` | string | `freedas/auto-cheap` | Model for titles, compaction, distillation |
| `variant` | string | none | Reasoning variant |
| `permission_mode` | `bypass\|auto\|ask` | `auto` | How asks resolve (see [Permissions](./permissions.md)) |
| `default_agent` | string | `build` | Initial primary agent |
| `subagent_depth` | number | `1` | `task` nesting limit |
| `disabled_providers` | array | `[]` | Providers hidden from the catalog and router |
| `instructions` | array | `[]` | Extra instruction files, globs, or URLs |
| `skills` | array | `[]` | Extra skill directories |
| `permission` | object | built-in rules | `{"rules": [...]}` or per-tool shape `{ "edit": "allow", "bash": { "git push": "ask" } }`; effects `allow`/`ask`/`deny` |
| `memory.enabled` | bool | `true` | Recall + writes |
| `memory.profile` | bool | `true` | Standing profile block |
| `memory.recall.limit` | number | `8` | Max recalled records per turn |
| `memory.distill.enabled` | bool | `true` | Distill records at session end |
| `router.mode` | `auto\|static\|off` | `auto` | `static` routes without learned priors; `off` bypasses the router |
| `router.quality_floor` | number | `0.80` | Base quality floor |
| `router.max_escalations` | number | `2` | Floor raises on consecutive failures |
| `router.learn` | bool | `true` | Blend learned outcomes, allow exploration |
| `standards.enabled` | bool | `true` | Run the gate after edit batches |
| `standards.commands` | array | detected | Gate commands; read only from system/global config so a repo cannot inject them |
| `standards.max_attempts` | number | `3` | Gate retry cap |
| `standards.block_on_failure` | bool | `true` | Feed failures back to the agent |
| `standards.review` | bool | `false` | Reserved |
| `sandbox.mode` | `auto\|on\|off` | `auto` | `auto` sandboxes headless runs only |
| `sandbox.network` | `deny\|allow` | `deny` | Only exactly `allow` opens the network; anything else errors |
| `snapshots` | bool | `true` | Shadow-git snapshots for undo/redo |
| `mcp` | object | `{}` | MCP server map (see [MCP](./mcp.md)) |
| `plugin` | array | `[]` | Plugin specs (see [Plugins](./plugins.md)) |
| `server.hostname` | string | `127.0.0.1` | `serve` bind address |
| `server.port` | number | `4096` | `serve`/`web` port |
| `websearch.provider` | string | `duckduckgo` | Web search backend |
| `telemetry` | bool | `false` | Unused placeholder; there is no telemetry |
| `workspace` | string | none | Billing workspace slug |
| `theme` | string | none | UI theme |
| `max_steps` | number | `50` | Model steps per turn |
| other keys | any | - | Unknown keys are preserved and ignored |

`model`/`small_model` validation accepts `freedas/auto`, `freedas/auto-cheap`,
or a string with exactly one `/`. Anything else fails config load with
`invalid model ...: expected provider/model or freedas/auto`.

## Instructions

Order (all concatenated with `## <source>` headers):

1. Project `AGENTS.md` (or the nearest fallback: `CLAUDE.md`, then `CONTEXT.md`).
2. Global `~/.config/freedas/AGENTS.md` (fallback `~/.claude/CLAUDE.md`).
3. `instructions` entries: files and globs relative to the project root, or `http(s)` URLs fetched through the `webfetch` tool's SSRF guard and size cap.

Missing files are skipped silently.

## Environment overrides

`FREEDAS_MODEL` sets `model` for one run. `FREEDAS_DISABLE_PROJECT_CONFIG=1`
skips the project layer. Path variables relocate directories; see
[CLI reference](./cli.md#environment-variables).

## Example

```jsonc
{
  // Router picks the model per step; pin a cheap model for titles.
  "model": "freedas/auto",
  "small_model": "freedas/auto-cheap",
  "default_agent": "build",
  "permission_mode": "auto",
  "disabled_providers": ["openrouter"],
  "instructions": ["docs/conventions.md", ".cursor/rules/**/*.mdc"],
  "skills": ["./team-skills"],
  "permission": {
    "edit": "allow",
    "bash": { "git push *": "ask", "*": "allow" },
    "read": { "*.env": "ask", "*": "allow" }
  },
  "memory": { "recall": { "limit": 8 } },
  "router": { "learn": true, "max_escalations": 2 },
  "standards": {
    "commands": ["cargo fmt --check", "cargo clippy --workspace --all-targets -- -D warnings", "cargo test --workspace"],
    "max_attempts": 3
  },
  "sandbox": { "mode": "auto", "network": "deny" },
  "mcp": {
    "linear": { "type": "remote", "url": "https://mcp.linear.app/mcp", "oauth": true }
  },
  "plugin": ["./plugins/company-auth.wasm"],
  "server": { "hostname": "127.0.0.1", "port": 4096 },
  "telemetry": false
}
```

## Editing config safely

The `/config` TUI panel edits values inline and writes back to the loaded
file. `freedas workspace use <slug>` writes `workspace` to the global config.
Answering "allow always" on a permission ask appends a rule. A broken JSONC
file fails `run`/TUI with `config: <error>`; diagnostic commands still run so
you can inspect the file.
