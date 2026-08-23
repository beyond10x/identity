#!/usr/bin/env bash
# The daemonloom string is banned at the surface of this repository. Allowed:
# pinned provenance URLs, the "the daemonloom monorepo" extraction-provenance
# phrase, the urn:daemonloom:* audience vocabulary and its x-daemonloom-audience
# header (the deployment-owned wire surface that M2's audience registry moves
# into configuration), the daemonloom-bot GitHub App machinery (scripts/as-bot.sh,
# bot-token.sh, check-bot-files.py — the App's name and its DAEMONLOOM_BOT_* env
# vars are functional identifiers that rename only together with the App itself),
# and this check.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
hits=$(git grep -in 'daemonloom' -- \
  ':!scripts/check-brand.sh' \
  ':!scripts/as-bot.sh' ':!scripts/bot-token.sh' ':!scripts/check-bot-files.py' \
  | grep -viE 'github\.com/daemonloom|the daemonloom monorepo|urn:daemonloom:|x-daemonloom-audience' || true)
if test -n "$hits"; then
  printf 'brand check: daemonloom at the surface:\n%s\n' "$hits" >&2
  exit 1
fi
printf 'brand check: clean\n'
