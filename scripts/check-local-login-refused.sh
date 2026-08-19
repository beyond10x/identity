#!/usr/bin/env bash
# Prove that the deployed posture cannot carry the local development login.
#
# `--features local-login` adds a route that mints an Identity session for whatever mailbox the
# caller types, with no upstream identity provider. In a hosted Identity that is a complete
# authentication bypass for the whole product, so the feature must not merely be off by default:
# a deployment build has to refuse to compile with it.
#
# Two facts are asserted here, neither of which any environment variable or configuration file can
# change:
#
#   1. `cargo check --release --features local-login` fails. A release profile clears
#      `debug_assertions`, and `src/lib.rs` raises `compile_error!` in exactly that combination.
#   2. The image build passes no `--features` at all, so the released binary is built from the
#      default feature set even before rule 1 applies.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

refuse() {
  printf 'local-login guard failed: %s\n' "$*" >&2
  exit 1
}

# 1. The deployment profile refuses to compile the feature.
output=$(mktemp "${TMPDIR:-/tmp}/daemonloom-local-login-guard.XXXXXXXX")
trap 'rm -f -- "$output"' EXIT
if cargo check --locked --release --features local-login >"$output" 2>&1; then
  refuse 'cargo check --release --features local-login succeeded; the release build must refuse it'
fi
if ! grep -q 'local-login' "$output"; then
  printf '%s\n' "$(cat "$output")" >&2
  refuse 'the release build failed for some reason other than the local-login refusal'
fi

# 2. The image build never selects a feature, so the shipped binary cannot contain the path.
if grep -n -- '--features' Dockerfile; then
  refuse 'Dockerfile selects a Cargo feature; the released image must build the default set'
fi
if ! grep -q 'cargo build --locked --release' Dockerfile; then
  refuse 'Dockerfile no longer builds with --release; rule 1 no longer covers the image'
fi

printf 'local-login is refused by the release profile and absent from the image build\n'
