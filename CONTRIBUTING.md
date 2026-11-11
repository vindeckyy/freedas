# Contributing

Freedas is a Rust workspace. This file covers setup, the gates a change has
to pass, and the conventions used by the code that is already here.

## Setup

- Rust 1.99.1 (pinned by `rust-toolchain.toml`; `rustup` installs it for
  you), edition 2024.
- No Node.js, Python, or Go is required to build or run.
- `just` is optional; every recipe maps to a plain `cargo` command.

```sh
rustup show                    # installs 1.99.1 + rustfmt + clippy
cargo build                    # or: just build
./target/debug/freedas --help
```

## Gates

Run these before opening a PR; `just check` runs the first three:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
FREEDAS_BIN=$PWD/target/debug/freedas bash scripts/e2e.sh
```

`e2e.sh` needs a built binary and `FREEDAS_TEST_PROVIDER=fake`; it exercises
the real CLI against a fake provider in temp directories and does not touch
your config or database.

The web UI is a single HTML file, so nothing else in the build parses its
inline JavaScript. `scripts/check-spa.sh` parses it with `node --check`; it
skips when node is not installed, and CI runs it on every push.

The control-plane tests need a real PostgreSQL and are skipped without one:

```sh
FREEDAS_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
DATABASE_URL=$FREEDAS_PG_URL \
  cargo test -p freedas-control -- --include-ignored --test-threads=1
cargo test -p freedas-gateway
cargo test -p freedas-sandbox-runner
```

They share one database and one of them drops the auth tables, so they run
one at a time. CI runs them against a `postgres:17-alpine` service.

## Conventions

- **Edition 2024, `thiserror` errors.** Library crates return typed errors;
  binaries may use `anyhow` for top-level context.
- **Behavior tests, not wiring tests.** Test that a rule matches, a scan
  blocks, an export round-trips; do not test that a `Vec` pushes.
- **No new dependencies without discussion.** Open an issue first. The
  workspace dep list in `Cargo.toml` is deliberately short.
- **Reuse the existing pattern.** Read the caller before you add a second
  way to do the same thing. If a helper exists in `freedas-core` or
  `freedas-db`, use it.
- **No telemetry, no hidden network calls.** A change that phones home gets
  rejected.
- **`shortcut:` comments name the limit.** If a deliberate simplification
  would break under a known condition, mark it with
  `shortcut: <the limit>, <when to upgrade>`.

## Commits and PRs

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
  `chore:`). One line, imperative, no scope padding.
- Keep the diff focused: one change per PR, no drive-by reformatting.
- Update `CHANGELOG.md` for user-visible changes.
- Checklist before pushing: `cargo fmt`, `cargo clippy`, `cargo test`, and
  `scripts/e2e.sh` all pass; new flags/commands are documented in
  `docs/src/cli.md` or `docs/src/slash-commands.md`; no secrets in the diff.

## Questions

- Bugs and feature requests: open a GitHub issue (see `SUPPORT.md` for what
  to include).
- Design questions: open a discussion.
- Security: use the private channel in `SECURITY.md`; do not file a public
  issue.
