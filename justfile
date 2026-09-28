# By default just list all available commands
[private]
default:
    @just -l

# Lints the code
lint: clippy fmt-check doc-check

# Formats the code with nightly cargo
fmt:
    cargo +nightly fmt

# Checks that the code is formatted
fmt-check:
    cargo +nightly fmt -- --check

# Checks that docs emit no warnings
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --document-private-items --no-deps

# Checks clippy lints
clippy:
    cargo clippy --no-deps -- -D warnings

# Checks compilation
check:
    cargo check

alias b := build

# Builds in release mode
build:
    cargo build --release

alias t := test

# Runs the tests (root workspace = `clearing`)
test *FLAGS:
    cargo test {{FLAGS}}

# Circuits workspace (own toolchain / arkworks)
test-circuits *FLAGS:
    cargo test --manifest-path circuits/Cargo.toml --release {{FLAGS}}

# Solana program tests (needs cargo-build-sbf)
test-solana *FLAGS:
    cargo test --manifest-path solana/Cargo.toml {{FLAGS}}

# Reports test coverage for the root workspace (`clearing`) and writes badges/coverage.svg.
coverage *FLAGS:
    cargo llvm-cov {{FLAGS}}
    cargo llvm-cov report --json --summary-only --output-path target/coverage-summary.json
    python3 scripts/coverage_badge.py target/coverage-summary.json badges/coverage.svg

# Line coverage for every workspace. Writes per-crate summaries and a combined badge.
coverage-all:
    cargo llvm-cov --json --summary-only --output-path target/coverage-clearing.json
    cargo llvm-cov --manifest-path circuits/Cargo.toml --release --json --summary-only --output-path target/coverage-circuits.json
    # Host llvm-cov cannot instrument SBF processors or Token-2022 CPI (they run in the .so).
    cargo llvm-cov --manifest-path solana/Cargo.toml --workspace --json --summary-only \
        --ignore-filename-regex 'processor/|program/src/token.rs' \
        --output-path target/coverage-solana.json
    CLEARING_TREE_DEPTH=8 cargo llvm-cov --manifest-path zkvm/script/Cargo.toml --bin clearing-host --json --summary-only --output-path target/coverage-zkvm.json
    python3 scripts/coverage_badge.py --combine \
        clearing:target/coverage-clearing.json \
        circuits:target/coverage-circuits.json \
        solana:target/coverage-solana.json \
        zkvm:target/coverage-zkvm.json \
        badges/coverage.svg
