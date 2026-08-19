#!/usr/bin/env bash
# Prove that the deployed posture cannot carry the local development login.
#
# `--features local-login` adds a route that mints an Identity session for whatever mailbox the
# caller types, with no upstream identity provider. In a hosted Identity that is a complete
# authentication bypass for the whole product, so the feature must not merely be off by default:
# a deployment build has to refuse to compile with it.
#
# Facts asserted here, none of which any environment variable or configuration file can change:
#
#   1. `cargo check --release --features local-login` fails. A release profile clears
#      `debug_assertions`, and `src/lib.rs` raises `compile_error!` in exactly that combination.
#   2. `RUSTFLAGS='-C debug-assertions=yes' cargo check --release --features local-login` fails
#      too. Forcing `debug_assertions` back on defeats rule 1's predicate, so `build.rs` derives a
#      second predicate — `optimized_build` from the profile's `OPT_LEVEL`, which `RUSTFLAGS`
#      cannot reach — and `src/lib.rs` raises a second `compile_error!` on it. Without this the
#      route compiled into an optimized 16 MB artifact.
#   3. The image build passes no `--features` at all, so the released binary is built from the
#      default feature set even before rules 1 and 2 apply.
#   4. In the one profile that admits the feature — an unoptimized development build — the
#      feature-gated runtime tests compile and pass, including the loopback-admission test that
#      proves a deployed configuration is refused at run time as well as at compile time.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

refuse() {
  printf 'local-login guard failed: %s\n' "$*" >&2
  exit 1
}

output=$(mktemp "${TMPDIR:-/tmp}/daemonloom-local-login-guard.XXXXXXXX")
trap 'rm -f -- "$output"' EXIT

# A release build with the feature must fail, and fail *because of* the local-login refusal rather
# than for some unrelated reason. $1 is a human label; the remaining arguments run the build.
must_refuse_local_login() {
  local label=$1
  shift
  if "$@" >"$output" 2>&1; then
    refuse "$label succeeded; the release build must refuse local-login"
  fi
  if ! grep -q 'local-login' "$output"; then
    printf '%s\n' "$(cat "$output")" >&2
    refuse "$label failed for some reason other than the local-login refusal"
  fi
}

# 1. The deployment profile refuses to compile the feature.
must_refuse_local_login \
  'cargo check --release --features local-login' \
  cargo check --locked --release --features local-login

# 2. Forcing debug_assertions back on in a release build is refused too. This is the bypass the
#    profile-independent `optimized_build` predicate exists to close.
must_refuse_local_login \
  "RUSTFLAGS='-C debug-assertions=yes' cargo check --release --features local-login" \
  env RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --release --features local-login

# 3. The image build never selects a feature, so the shipped binary cannot contain the path.
if grep -n -- '--features' Dockerfile; then
  refuse 'Dockerfile selects a Cargo feature; the released image must build the default set'
fi
if ! grep -q 'cargo build --locked --release' Dockerfile; then
  refuse 'Dockerfile no longer builds with --release; rules 1 and 2 no longer cover the image'
fi

# 4. The development profile that does admit the feature still compiles and passes its runtime
#    guards, so the refusal is enforced without leaving the feature itself unexercised.
test_output=$(mktemp "${TMPDIR:-/tmp}/daemonloom-local-login-test.XXXXXXXX")
trap 'rm -f -- "$output" "$test_output"' EXIT
if ! cargo test --locked --features local-login local_login >"$test_output" 2>&1; then
  printf '%s\n' "$(cat "$test_output")" >&2
  refuse 'the feature-gated local-login tests did not pass in a development build'
fi
if ! grep -Eq 'local_login_is_admitted_only_by_a_loopback_listener_and_origin \.\.\. ok' "$test_output"; then
  printf '%s\n' "$(cat "$test_output")" >&2
  refuse 'the loopback-admission test did not run in the development feature build'
fi

printf 'local-login: refused by every shipping profile (including forced debug-assertions), absent from the image build, and admitted only by an exercised loopback development build\n'
