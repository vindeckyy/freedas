# Interactive mode

Run `freedas` in a project directory to start the terminal UI. An optional
argument chooses the project (`freedas path/to/project`); `fd` does the same
when the installer added the shell function.

## Layout

- **Header**: project, branch, agent, model, tokens, cost.
- **Transcript**: streamed assistant text, reasoning, tool cards, and diffs.
- **Composer**: a multiline input at the bottom.
- **Status bar**: session id, status, key hints.

## Composer

| Key | Action |
|---|---|
| `Enter` | Submit the prompt |
| `Shift+Enter`, `Ctrl+J` | Newline |
| `Up` / `Down` | Prompt history |
| `Ctrl+W` | Delete word |
| `Ctrl+U` | Clear line |
| `Ctrl+K` | Kill to end (opens the session picker when the composer is empty) |
| `Ctrl+E` | Open `$EDITOR`/`$VISUAL` |
| `Ctrl+Y` | Copy the transcript to the clipboard |
| `Home` / `End` | Line start/end; `Ctrl+Home`/`Ctrl+End` scroll to top/bottom |

Type `/` for command completion and `@` for project-file completion;
`Up`/`Down` moves, `Tab`/`Enter` completes, `Esc` dismisses.

## Run control

- `Esc` interrupts a running turn; with no run it clears the composer; pressed twice it recalls the last submitted prompt.
- `Tab` while a run is active queues the typed prompt for after the run.
- `Ctrl+C` cancels the run (also rejects a pending permission ask). With an empty composer it arms quit: press again within a second to exit.
- `Ctrl+D` exits immediately.

## Scrolling and overlays

- `PgUp`/`PgDn` and the mouse wheel scroll the transcript.
- `Ctrl+T` opens the transcript view; `Ctrl+R` opens transcript search.
- `?` or `F1` opens the shortcuts list; `Ctrl+P` or `Ctrl+H` opens help.

## Pickers

- `Ctrl+K` sessions: resume, fork, rename, delete.
- `Ctrl+L` models: pick a model; `Tab`/`Shift+Tab` inside the picker cycles reasoning variants.
- `Ctrl+O` agents: switch the primary agent.
- `Alt+M` MCP servers: toggle each server for the session.
- `/config` opens the settings browser: grouped effective-config rows, search with `/`, inline editing with `Enter`.

## Permission dialog

An `ask` opens a modal over the transcript. `a`/`1` allows once, `A`/`2`
allows always (the rule is written into the global config), `d`/`3` or `Esc`
denies. `Ctrl+C` cancels the whole run and fails the ask.

## Permission modes

The TUI starts in the mode from `permission_mode` in config (default
`auto`). `/permissions` opens a picker with three modes and saves the choice
to the global config:

- `bypass` - never ask; explicit deny rules still block.
- `auto` - ask only for risky actions.
- `ask` - prompt before every action.

`--auto` forces bypass for the session; `--manual` forces ask. See
[Permissions](./permissions.md).

## Sessions

- `/new` starts a session; `/sessions` or `Ctrl+K` switches, forks, renames, deletes, or exports.
- `freedas --continue` resumes the most recent session; `freedas --session <id>` resumes a specific one; `--fork` with either creates a forked copy first.
- `/undo` and `/redo` restore files from shadow-git snapshots. The snapshot
  is taken just before the first file-mutating tool call of a message, so
  read-only messages create none. If the project root contains the Freedas
  data directory (for example launching in your home directory) or exceeds
  the size caps, the snapshot is skipped and `/undo` is unavailable for
  that message — the run itself still proceeds.

## Non-interactive terminals

With no TTY, `freedas` prints
`Interactive UI requires a TTY. Use freedas run "task" for headless runs.` and
exits. See [Headless runs](./headless.md).
