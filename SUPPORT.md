# Support

## Where to look first

- [`docs/src/quickstart.md`](docs/src/quickstart.md): install and first run.
- [`docs/src/cli.md`](docs/src/cli.md): every command and flag.
- [`docs/src/slash-commands.md`](docs/src/slash-commands.md): every `/command`.
- [`docs/src/configuration.md`](docs/src/configuration.md): config schema,
  precedence, and `{env:}`/`{file:}` substitution.
- [`docs/src/another-harness.md`](docs/src/another-harness.md): using Freedas
  from Claude Code, Codex, and other agents.
- `freedas debug paths`: prints every data, config, state, and log path.

## Bugs

Open a GitHub issue. Include:

- `freedas --version` output.
- OS and arch (for example `macOS arm64`, `Ubuntu x86_64`, `WSL`).
- The exact command you ran and the config that applied
  (`freedas debug paths` shows which files were loaded).
- Expected versus actual behavior.
- Sanitized output: `freedas export --sanitize` for session data, or
  `FREEDAS_LOG=debug` logs with secrets removed.

## Questions and feature requests

- GitHub Discussions for questions, usage help, and design discussion.
- GitHub Issues for bugs and tracked feature requests.
- SECURITY.md for vulnerabilities; do not post those publicly.

## Common issues

- **No providers authenticated**: run `freedas providers login <provider>`
  or export the matching `*_API_KEY` variable.
- **Permission blocked in headless run**: expected; use `--auto` to approve
  asks, or loosen the rule in `freedas.jsonc`.
- **Sandbox unavailable on Linux**: `bwrap` is missing; install it, or set
  `FREEDAS_EXPERIMENTAL_SANDBOX=false` to fall back to permission prompts.
- **`freedas upgrade` reports no release**: the release page is not
  populated yet; install from source or with `cargo install`.
