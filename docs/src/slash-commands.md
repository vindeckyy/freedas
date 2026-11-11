# Slash commands

Every `/command` available inside a Freedas session. Custom commands, skills,
and MCP prompts register in the same namespace after these; a name that
collides with a built-in never registers. Commands defined under the project
root (`.freedas/commands/`) load only when the project layer is trusted — the
same `trust_project_code` gate as project agents — and `agent`/`model`
frontmatter fields in a project command are validated, not blindly honored.

## Session

- `/new` - Start a new session. Alias: `/clear`.
- `/sessions` - Switch, fork, rename, or delete a session. Aliases: `/resume`, `/continue`.
- `/rename` - Rename the current session.
- `/fork` - Fork the current session.
- `/compact` - Compact the conversation. Alias: `/summarize`.
- `/undo` / `/redo` - Revert the last message and its file edits, or reapply them.
- `/editor` - Compose the next message in `$VISUAL`/`$EDITOR`.
- `/move` - Move the session to another project directory.
- `/export` - Export the transcript as Markdown.
- `/copy` - Copy the transcript to the clipboard.
- `/timestamps` - Toggle message timestamps.
- `/thinking` - Collapse or expand reasoning parts.
- `/status` - Session id, project, agent, model, token and cost totals.
- `/debug` - Paths, providers, MCP, LSP, and the last error.
- `/changelog` - Read the changelog.
- `/help` - Commands, keybindings, version, paths.
- `/config` - Open the settings browser (grouped config rows, search, inline edit).
- `/exit` - Exit Freedas. Aliases: `/quit`, `/q`.

## Model and permissions

- `/model` - Open the model picker (`Tab`/`Shift+Tab` cycles reasoning variants).
- `/variants` - Switch the model variant.
- `/permissions` - Choose how tool permissions ask: `bypass`, `auto`, or `ask`; the choice is saved to the global config.

## Setup and account

- `/init` - Create or update `AGENTS.md` for this project.
- `/sync` - Import instruction and skill files from other agents. Alias: `/adopt`.
- `/agents` - Switch the active agent.
- `/mcps` - Toggle MCP servers for this session.
- `/login` - Sign in to a provider.
- `/credits` - Show the workspace credit balance.
- `/usage` - Tokens and cost by model.
- `/workspace` - Choose which workspace new requests bill. Alias: `/billing`.
- `/org` - Switch organization. Aliases: `/orgs`, `/switch-org`.
- `/remote` - Share this session for remote control. Alias: `/rc`.
- `/update` - Check for and install an update.

## Review and planning

- `/review` - Review uncommitted changes, a commit, a branch, or a pull request.
- `/standards-review` - Review the current changes for over-engineering; return a delete list.
- `/standards-audit` - Audit the whole repository for over-engineering.
- `/ui-review` - Review the current changes for UI and UX issues.
- `/ui-audit` - Audit the whole repository for UI and UX issues.
- `/code-standards` - Review the current changes against the code standards.
- `/ui-standards` - Review the current changes against the UI standards.
- `/quick-plan` - Draft a plan with `plan-quick` on the cheap tier. Alias: `/plan-quick`.
- `/deep-plan` - Draft a plan with `plan` on the strong tier. Alias: `/plan-deep`.

## Notes

- `/editor` opens `$VISUAL`/`$EDITOR`; an empty buffer aborts.
- `/sessions`, `/agents`, `/model`, `/mcps` accept an argument or open a picker.
- `/credits`, `/usage`, `/org`, `/workspace`, and `/remote` use the control plane and relay when reachable; without them they print the stored state or an error.
- `/mcps <name>` toggles one server without editing config.
- `/sync` lists the detected sources and applies them on Enter; the first session in a workspace offers the import once.

Built-in commands reserve these names, so custom definitions with the same
name are ignored: `new`, `clear`, `sessions`, `resume`, `continue`, `rename`,
`fork`, `compact`, `summarize`, `undo`, `redo`, `editor`, `move`, `export`,
`copy`, `timestamps`, `thinking`, `status`, `debug`, `changelog`, `help`,
`exit`, `quit`, `q`, `init`, `sync`, `adopt`, `agents`, `variants`, `mcps`,
`login`, `credits`, `usage`, `workspace`, `billing`, `org`, `orgs`,
`switch-org`, `remote`, `rc`, `update`, `code-standards`, `ui-standards`,
`review`, `standards-review`, `standards-audit`, `ui-review`, `ui-audit`,
`quick-plan`, `plan-quick`, `deep-plan`, `plan-deep`.

Note that `config`, `model`, and `permissions` are TUI commands but not in the
reserved list; a custom file named `config.md` can register, though the
built-in handler still wins in the TUI.
