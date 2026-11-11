# Installation

Freedas ships as one `freedas` binary. macOS and Linux (glibc) are supported;
Windows users run inside WSL, which uses the Linux artifacts.

## Install script

```bash
curl -fsSL https://raw.githubusercontent.com/vindeckyy/freedas/main/install.sh | bash
```

The script:

1. Detects your OS and architecture (`darwin`/`linux`, `arm64`/`x86_64`); anything else fails with `unsupported OS` or `unsupported architecture`. Only glibc Linux assets ship — musl hosts (Alpine) get a clear error telling you to build from source.
2. Downloads `freedas-<os>-<arch>.tar.gz` from the release page at `https://github.com/vindeckyy/freedas/releases` (override with `FREEDAS_RELEASE_BASE`, which must be `https://` or `file://`; curl is pinned to those protocols and `https`-only redirects).
3. Refuses to install without a published checksum: the asset's `.sha256` or `SHA256SUMS` must exist and match. When `cosign` is installed and the release ships a `.sig`, the signature is verified too (warns otherwise; `FREEDAS_INSTALL_SKIP_SIG=1` silences the check entirely).
4. Extracts with `--no-absolute-filenames` and requires exactly one `freedas` binary, then installs to `~/.freedas/bin/freedas` (override with `PREFIX` as the first argument — restricted to safe path characters since it is written into your shell rc file; `FREEDAS_VERSION` picks a release tag, default `latest`).
5. Adds `~/.freedas/bin` to your shell profile (`.zshrc`, `.bash_profile`, `.bashrc`, or fish `config.fish`) if it is not already there.
6. Adds an `fd` shell function to the same profile so `fd` opens the TUI even when fd-find is on `PATH`. Use `command fd` for fd-find.

No sudo. Open a new terminal afterward, or `source` your profile.

## From source

```bash
git clone https://github.com/vindeckyy/freedas.git
cd freedas
cargo build --locked --release
cp target/release/freedas ~/.freedas/bin/freedas
```

Rust 1.99.1 (pinned by `rust-toolchain.toml`), edition 2024. `cargo fmt --all --check`, `cargo clippy
--workspace --all-targets -- -D warnings`, and `cargo test --workspace` are the
local gates.

## Verify

```bash
freedas --version
freedas debug paths
```

`debug paths` prints where Freedas keeps config, data, state, cache, the
database, snapshots, worktrees, and plans.

## Upgrade

```bash
freedas upgrade            # latest release
freedas upgrade v0.4.0     # a specific tag
```

The upgrade downloads `latest.json` for the release, verifies the published
SHA-256 before touching the binary, replaces `freedas` atomically, and keeps
the previous binary as `freedas.previous` next to it. `FREEDAS_RELEASE_BASE`
points at a mirror.

## Uninstall

```bash
freedas uninstall
```

It lists the paths it will remove (data, state, cache, config, the installed
binary, the PATH line in your shell profile, the relay daemon) and asks for
confirmation. Flags:

- `--keep-data` - keep the session database, credentials, snapshots, plans, and logs under `~/.local/share/freedas/` and `~/.local/state/freedas/`.
- `--keep-config` - keep `~/.config/freedas/`.
- `--yes` - skip the interactive confirmation (required without a TTY).

The last message names the binary path if it lives outside `~/.freedas/bin` so
you can remove it by hand.

## Where things live

| Thing | Default path |
|---|---|
| Binary | `~/.freedas/bin/freedas` |
| Global config | `~/.config/freedas/freedas.json(c)` |
| Data (DB, credentials, snapshots, worktrees, plans) | `~/.local/share/freedas/` |
| State (logs, relay state, machine id) | `~/.local/state/freedas/` |
| Cache | `~/.cache/freedas/` |
| Project data | `.freedas/` in the project |

`FREEDAS_CONFIG_DIR`, `FREEDAS_DATA`, `FREEDAS_STATE`, `FREEDAS_CACHE`, and
`FREEDAS_DB` relocate each directory; `FREEDAS_HOME` relocates the home
reference itself.
