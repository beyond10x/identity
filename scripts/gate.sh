#!/usr/bin/env bash
# The repository gate: locked workspace tests in both feature postures, clippy,
# formatting, and the component's own checks. Green here is the bar for main.
# .github/workflows/test.yml runs the same steps on every pull request and main push.
#
# Test budget (~/beyond10x/AGENTS.md § Tests stay fast): cargo-nextest kills a test over 60 s
# and counts it failed (.config/nextest.toml); each test step fails when its test run took over
# 120 s, read from nextest's JUnit report, so neither the compile (built in a step of its own
# first) nor a wait for a build slot counts. Debug info is off in test builds (.cargo/config.toml).
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

# The budget of one test run, in seconds, read from the run's own elapsed time in the JUnit
# report: a wait for a slot of the shared build pool before the run starts does not count.
test_budget=120
# A guard against a hung step only; the pool's 10-minute kill, nextest's 60 s per-test kill and
# test_budget are the limits.
hang_guard=600
# nextest writes its JUnit report under its store directory, which .config/nextest.toml pins to
# target/nextest of the workspace root. CARGO_TARGET_DIR does not move it (measured with
# cargo-nextest 0.9.143: the build went to the set directory, the report stayed here).
junit=$root/target/nextest/default/junit.xml

# Run one test step, print its ten slowest tests (also when it failed), then end the gate with
# the step's status when that is not 0, or with 1 when the run took longer than test_budget or
# left no report to read its time from.
test_step() {
  printf 'gate: timeout %s %s\n' "$hang_guard" "$*"
  local started status=0 run_time
  rm -f -- "$junit"
  started=$(date +%s)
  timeout "$hang_guard" "$@" || status=$?
  printf 'gate: test step took %ss of wall time, slot queue included\n' "$(($(date +%s) - started))"
  if [ ! -f "$junit" ]; then
    printf 'gate: no JUnit report at %s\n' "$junit" >&2
    if [ "$status" -eq 0 ]; then
      printf 'gate: the test run time cannot be read; the step fails\n' >&2
      exit 1
    fi
  else
    printf 'gate: slowest tests\n'
    sh scripts/slowest-tests.sh "$junit" 10
    run_time=$(sed -n 's/.*<testsuites [^>]*time="\([0-9.]*\)".*/\1/p' "$junit")
    if [ -z "$run_time" ]; then
      printf 'gate: %s names no run time; the step fails\n' "$junit" >&2
      exit 1
    fi
    printf 'gate: test run took %ss (budget %ss)\n' "$run_time" "$test_budget"
    if awk -v t="$run_time" -v b="$test_budget" 'BEGIN { exit !(t > b) }'; then
      printf 'gate: test run took %ss, over the %ss budget: %s\n' "$run_time" "$test_budget" "$*" >&2
      exit 1
    fi
  fi
  if [ "$status" -eq 124 ]; then
    printf 'gate: test step hung past the %ss guard: %s\n' "$hang_guard" "$*" >&2
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
