# Worktrees

`--worktree` runs the session inside a git worktree instead of your working
directory, so concurrent sessions never share the index and an experiment
never touches your checkout.

## Creating

```bash
freedas --worktree                  # name is generated (s01...)
freedas --worktree billing-fix
freedas run --worktree "add caching" --auto
```

Requirements: the project must be inside a git repository.

What happens:

1. A worktree is created at `~/.local/share/freedas/worktrees/<project-id>/<name>` on branch `freedas/<name>` from `HEAD`.
2. The session runs with that directory as its cwd; the worktree path is stored in session metadata.
3. On exit the worktree stays in place; its path and branch are printed.

`git worktree remove <path>` cleans up later.

## Parallel sessions

Two sessions on the same repository work without index contention:

```bash
freedas --worktree fix-a &
freedas --worktree fix-b &
```

## Pull request checkout

`freedas pr <number>` checks out a PR and starts the TUI in it:

- `gh pr checkout <number>` when `gh` is installed and authenticated;
- otherwise `git fetch origin pull/<n>/head:pr-<n>` plus `git checkout pr-<n>`.

In a non-TTY shell it checks out and exits without starting the UI.

## Limits

`--worktree` cannot be combined with `--attach` on `freedas run`: a worktree
is a local checkout, and the remote server owns its own cwd. Non-git
directories fail with a clear error.
