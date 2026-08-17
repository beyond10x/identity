#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

actual=$(cargo tree --locked --prefix none --format '{p}' -i rsa@0.9.10)
expected=$(printf '%s\n' \
  'rsa v0.9.10' \
  'openidconnect v4.0.1' \
  'daemonloom-identity v0.1.0')

# The final package path is machine-local, so compare its stable name/version separately.
actual=$(printf '%s\n' "$actual" | sed 's#daemonloom-identity v0.1.0 (.*)#daemonloom-identity v0.1.0#')
if [ "$actual" != "$expected" ]; then
  printf 'RUSTSEC-2023-0071 dependency path changed; re-review the exception:\n%s\n' "$actual" >&2
  exit 1
fi

# openidconnect carries rsa unconditionally. Identity uses only public-JWK signature verification
# and never loads an RSA private key, so the advisory's private-key recovery path is unreachable.
cargo audit --ignore RUSTSEC-2023-0071 "$@"
