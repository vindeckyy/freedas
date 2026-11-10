# Freedas build/test/docs recipes. Every recipe maps to a plain cargo command
# from CONTRIBUTING.md; `just` is optional.

build:
    cargo build

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo deny check
    cargo audit
    cargo test --workspace

test:
    cargo test --workspace

e2e:
    cargo build
    FREEDAS_BIN=$PWD/target/debug/freedas bash scripts/e2e.sh

fmt:
    cargo fmt --all

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

docs:
    mdbook serve docs

release:
    cargo dist build
