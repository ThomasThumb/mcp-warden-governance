# Developer entry points. Install just: https://github.com/casey/just
# `just ci` mirrors exactly what .github/workflows/security.yml enforces.

# List available recipes
default:
    @just --list

# Everything CI runs, in one shot
ci: fmt-check clippy test check-postgres audit deny

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy -p warden-cp --no-default-features --features postgres --all-targets --locked -- -D warnings

test:
    cargo test --workspace --locked

# The production backend must at least compile and pass tests on every change
check-postgres:
    cargo check -p warden-cp --no-default-features --features postgres --locked
    cargo test -p warden-cp --no-default-features --features postgres --locked

audit:
    cargo audit

deny:
    cargo deny check

# Build the release container the same way the release workflow does
docker-build:
    docker build -f warden-cp/Dockerfile -t warden-cp:dev .
