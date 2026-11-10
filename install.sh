#!/usr/bin/env bash
# Freedas installer: downloads the latest release to ~/.freedas/bin (no sudo).
set -euo pipefail

PREFIX="$HOME/.freedas/bin"
VERSION="${FREEDAS_VERSION:-latest}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
    --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
    --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    -h|--help) echo "usage: install.sh [--prefix DIR] [--version TAG]"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) PREFIX="$1"; shift ;;
  esac
done

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64|x64|amd64) arch="x86_64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

case "$os" in
  darwin) os="darwin" ;;
  linux) os="linux" ;;
  *) echo "unsupported OS: $os (Windows users: run inside WSL)" >&2; exit 1 ;;
esac

# Asset names follow the cargo-dist triples in Cargo.toml
# ([workspace.metadata.dist] targets), not the uname spellings.
if [ "$os" = "darwin" ]; then
  triple="${arch}-apple-darwin"
else
  # glibc and musl need different binaries; Alpine (or any musl host) takes
  # the musl asset.
  if [ -f /etc/alpine-release ] || { command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; }; then
    libc="musl"
  else
    libc="gnu"
  fi
  triple="${arch}-unknown-linux-${libc}"
fi
Asset="freedas-${triple}.tar.gz"
# `FREEDAS_RELEASE_BASE` points the installer at a mirror (or a local
# `file://` directory in tests); the default is the GitHub release page.
BASE="${FREEDAS_RELEASE_BASE:-https://github.com/freedas/freedas/releases}"
# GitHub serves a pinned tag at .../releases/download/<tag>/<asset> and the
# rolling tag at .../releases/latest/download/<asset>.
if [ "$VERSION" = "latest" ]; then
  tag_url="${BASE%/}/latest/download"
else
  tag_url="${BASE%/}/download/${VERSION}"
fi
url="${tag_url}/${Asset}"

echo "Freedas $VERSION for $triple"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$Asset" "$url"
# `freedas upgrade` refuses installs without a published sha256; the script
# holds the same line and verifies the checksum before extracting.
if curl -fsSL -o "$tmp/$Asset.sha256" "$url.sha256" 2>/dev/null; then
  expected="$(awk '{print $1}' "$tmp/$Asset.sha256")"
elif curl -fsSL -o "$tmp/SHA256SUMS" "$tag_url/SHA256SUMS" 2>/dev/null; then
  expected="$(awk -v a="$Asset" '$2 == a {print $1}' "$tmp/SHA256SUMS")"
else
  expected=""
fi
if [ -z "${expected:-}" ]; then
  echo "no checksum published for $Asset; refusing to install" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$Asset" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$Asset" | awk '{print $1}')"
else
  echo "need sha256sum or shasum to verify the download" >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "checksum mismatch for $Asset" >&2
  exit 1
fi
tar -xzf "$tmp/$Asset" -C "$tmp"
# Archives may nest the binary; locate it instead of assuming the root.
bin="$(find "$tmp" -name freedas -type f -print | head -n 1)"
if [ -z "$bin" ]; then
  echo "release archive does not contain a freedas binary" >&2
  exit 1
fi
mkdir -p "$PREFIX"
install -m 0755 "$bin" "$PREFIX/freedas"
echo "Installed to $PREFIX/freedas"

case "${SHELL:-}" in
  */zsh) profile="$HOME/.zshrc" ;;
  */fish) profile="$HOME/.config/fish/config.fish" ;;
  *) profile="$HOME/.bash_profile"; [ -f "$HOME/.bashrc" ] && [ ! -f "$profile" ] && profile="$HOME/.bashrc" ;;
esac

# A fresh HOME may have no shell rc file yet; create the parent so the PATH
# and `fd` lines below are not silently skipped.
mkdir -p "$(dirname "$profile")" 2>/dev/null || true

if ! grep -qFs "$PREFIX" "$profile" 2>/dev/null; then
  if [ -w "$(dirname "$profile")" ]; then
    printf '\nexport PATH="%s:$PATH"\n' "$PREFIX" >> "$profile"
    echo "Added $PREFIX to $profile"
  else
    echo "Add this to $profile: export PATH=\"$PREFIX:\$PATH\"" >&2
  fi
fi

# `fd` opens the terminal UI; it is a shell function so it also works when
# another `fd` (fd-find) exists on PATH, and so arguments pass through.
if ! grep -qFs "freedas: fd keyword" "$profile" 2>/dev/null; then
  if [ -w "$(dirname "$profile")" ]; then
    case "$profile" in
      *fish*)
        printf '\n# freedas: fd keyword\nfunction fd; command freedas $argv; end\n# END freedas: fd keyword\n' >> "$profile"
        ;;
      *)
        cat >> "$profile" <<'EOF'

# freedas: fd keyword
fd() { command freedas "$@"; }
# END freedas: fd keyword
EOF
        ;;
    esac
    echo "Added the \`fd\` keyword to $profile (reopen the terminal to use it)"
  fi
fi

"$PREFIX/freedas" --version
echo "Run: freedas   (or just: fd)"
