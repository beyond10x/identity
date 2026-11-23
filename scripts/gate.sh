#!/usr/bin/env bash
# The repository gate: locked workspace tests in both feature postures, clippy,
# formatting, and the component's own checks. Green here is the bar for main.
# .github/workflows/test.yml runs the same steps on every pull request and main push.
#
# Test budget (~/beyond10x/AGENTS.md § Tests stay fast): cargo-nextest kills a test over 60 s
# and counts it failed (.config/nextest.toml); each test step fails when it runs over 120 s of
# wall time. The test binaries are built in a step of their own first, so the budget measures
# the tests, not the compile. Debug info is off in test builds (.cargo/config.toml).
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

# `--forge` runs the steps .github/workflows/test.yml runs: every step but the two supply-chain
# checks, which need cargo-audit and a download of gitleaks.
forge=false
if [ "${1:-}" = "--forge" ]; then
  forge=true
elif [ "$#" -ne 0 ]; then
  printf 'usage: bash scripts/gate.sh [--forge]\n' >&2
  exit 2
fi

test_budget=120
# nextest writes its JUnit report under its store directory, which .config/nextest.toml pins to
# target/nextest of the workspace root. CARGO_TARGET_DIR does not move it (measured with
# cargo-nextest 0.9.143: the build went to the set directory, the report stayed here).
junit=$root/target/nextest/default/junit.xml

# Run one test step under the wall-time budget, print its ten slowest tests (also when it failed
# or ran over), then end the gate with the step's status when that is not 0.
test_step() {
  printf 'gate: timeout %s %s\n' "$test_budget" "$*"
  local started status=0
  rm -f -- "$junit"
  started=$(date +%s)
  timeout "$test_budget" "$@" || status=$?
  printf 'gate: test step took %ss (budget %ss)\n' "$(($(date +%s) - started))" "$test_budget"
  if [ -f "$junit" ]; then
    printf 'gate: slowest tests\n'
    sh scripts/slowest-tests.sh "$junit" 10
  else
    printf 'gate: no JUnit report at %s\n' "$junit"
  fi
  if [ "$status" -eq 124 ]; then
    printf 'gate: test step ran over %ss: %s\n' "$test_budget" "$*" >&2
    exit 1
  fi
  if [ "$status" -ne 0 ]; then
    exit "$status"
  fi
}

printf 'gate: cargo nextest run --workspace --locked --no-run\n'
cargo nextest run --workspace --locked --no-run
test_step cargo nextest run --workspace --locked
printf 'gate: cargo nextest run --workspace --locked --features local-login --no-run\n'
cargo nextest run --workspace --locked --features local-login --no-run
test_step cargo nextest run --workspace --locked --features local-login
printf 'gate: cargo clippy --workspace --all-targets --locked -- -D warnings\n'
cargo clippy --workspace --all-targets --locked -- -D warnings
printf 'gate: cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings\n'
cargo clippy --workspace --all-targets --locked --features local-login -- -D warnings
printf 'gate: cargo fmt --all --check\n'
cargo fmt --all --check
printf 'gate: sh scripts/planning-only-test.sh\n'
sh scripts/planning-only-test.sh
printf 'gate: bash scripts/check-local-login-refused.sh\n'
bash scripts/check-local-login-refused.sh
if [ "$forge" = true ]; then
  printf 'gate: green (--forge: check-audit and check-secrets not run)\n'
  exit 0
fi
printf 'gate: bash scripts/check-audit.sh\n'
bash scripts/check-audit.sh
printf 'gate: bash scripts/check-secrets.sh\n'
bash scripts/check-secrets.sh
printf 'gate: green\n'
