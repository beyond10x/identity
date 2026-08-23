#!/usr/bin/env bash
# The repository gate: locked workspace tests in both feature postures, clippy,
# formatting, and the component's own checks. Green here is the bar for main.
# Mirrors what the monorepo gate ran for this component before extraction.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
printf 'gate: cargo test --workspace --locked\n'
cargo test --workspace --locked
printf 'gate: cargo test --workspace --locked --features local-login\n'
cargo test --workspace --locked --features local-login
printf 'gate: cargo clippy --workspace --all-targets --locked -- -D warnings\n'
cargo clippy --workspace --all-targets --locked -- -D warnings
printf 'gate: cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings\n'
cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings
printf 'gate: cargo fmt --all --check\n'
cargo fmt --all --check
printf 'gate: bash scripts/check-local-login-refused.sh\n'
bash scripts/check-local-login-refused.sh
printf 'gate: bash scripts/check-audit.sh\n'
bash scripts/check-audit.sh
printf 'gate: bash scripts/check-secrets.sh\n'
bash scripts/check-secrets.sh
printf 'gate: green\n'
