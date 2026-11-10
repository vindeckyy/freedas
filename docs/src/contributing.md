# Contributing

The full guide is [CONTRIBUTING.md](https://github.com/freedas/freedas/blob/main/CONTRIBUTING.md)
at the repository root. Summary:

## Setup

- Rust pinned by `rust-toolchain.toml` (edition 2024); `rustup` installs it.
- No Node.js, Python, or Go needed to build or run.
- `just` is optional; every recipe maps to a `cargo` command.

```sh
rustup show
cargo build
./target/debug/freedas --help
```

## Gates

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
FREEDAS_BIN=$PWD/target/debug/freedas bash scripts/e2e.sh
```

`e2e.sh` exercises the real CLI against a fake provider in temp directories;
it does not touch your config or database.

## Conventions

- Typed errors in libraries (`thiserror`); `anyhow` only at the binary top.
- Behavior tests over wiring tests.
- No new dependencies without discussion.
- Reuse the existing pattern before adding a second way.
- No telemetry, no hidden network calls.
- `shortcut:` comments name deliberate limits.

## Docs

New flags and commands belong in
[CLI reference](./cli.md) or [Slash commands](./slash-commands.md); a
user-visible change belongs in the changelog.

## Contact

Bugs and features: GitHub issues (see `SUPPORT.md`). Design: discussions.
Security: the private channel in `SECURITY.md`, never a public issue.
