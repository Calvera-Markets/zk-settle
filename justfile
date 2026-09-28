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
    cargo test --manifest-path clearing-circuits/Cargo.toml --release {{FLAGS}}

# Solana program tests (needs cargo-build-sbf)
test-solana *FLAGS:
    cargo test --manifest-path clearing-solana/Cargo.toml {{FLAGS}}

# Reports test coverage and writes badges/coverage.svg. Requires cargo-llvm-cov.
coverage *FLAGS:
    cargo llvm-cov {{FLAGS}}
    cargo llvm-cov report --json --summary-only --output-path target/coverage-summary.json
    python3 scripts/coverage_badge.py target/coverage-summary.json badges/coverage.svg
