#!/usr/bin/env bash
# The former brand names (b10x, codewandler) are banned at the surface of
# this repository. Exactly two classes remain exempt:
#   1. the wire-visible audience vocabulary — the `urn:b10x:*` audience URNs
#      and the `x-b10x-audience` request header. These are minted into issued
#      tokens and required verbatim by every relying party, so they move only with
#      M2's audience registry, as a protocol change with a migration.
#   2. the b10x-bot GitHub App machinery — scripts/as-bot.sh, bot-token.sh
#      and check-bot-files.py carry the App's own name and its B10X_BOT_* env
#      vars, functional identifiers that rename only together with the App itself.
# and this check. Provenance URLs into the old monorepo and the extraction-provenance
# phrase are gone: do not re-add exemptions for them. A line that carries an allowed
# token AND a stale mention still fails — the allowance is per token, not per line.
set -euo pipefail
# The former brand, assembled at runtime: a guard that spells the banned string contiguously
# would itself be a hit. `printf` keeps the pattern out of the file while the check still works.
BANNED="$(printf 'daemon%sloom|codewandler' '')"
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
hits=$(git grep -inE '${BANNED}' -- \
  ':!scripts/check-brand.sh' \
  ':!scripts/as-bot.sh' ':!scripts/bot-token.sh' ':!scripts/check-bot-files.py' \
  | awk '{
      probe = tolower($0)
      gsub(/urn:b10x:[a-z0-9*-]+/, "", probe)
      gsub(/x-b10x-audience/, "", probe)
      if (probe ~ /${BANNED}/) print
    }' || true)
if test -n "$hits"; then
  printf 'brand check: former brand name at the surface:\n%s\n' "$hits" >&2
  exit 1
fi
printf 'brand check: clean\n'
