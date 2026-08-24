#!/usr/bin/env bash
# The former brand name (and `codewandler`) are banned at the surface of this
# repository. The only remaining exemption is the b10x-bot GitHub App machinery:
# scripts/as-bot.sh, scripts/bot-token.sh and scripts/check-bot-files.py carry the
# App's own name and its B10X_BOT_* env vars, functional identifiers that can only
# be renamed together with the GitHub App itself.
# The wire-visible audience vocabulary is no longer exempt: the audience URNs and
# the audience request header moved to `urn:b10x:*` and `x-b10x-audience`, which
# invalidated every session minted under the old names. That was deliberate, so
# there is nothing left here to exempt -- do not re-add an allowance for them.
# Provenance URLs into the old monorepo and the extraction-provenance phrase are
# gone too: do not re-add exemptions for those either.
set -euo pipefail
# The former brand, assembled at runtime: a guard that spells the banned string
# contiguously would itself be a hit. `printf` keeps the pattern out of the file
# while the check still works.
BANNED="$(printf 'daemon%sloom|codewandler' '')"
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
# `git grep` exits 1 for "no matches" and greater than 1 for a real failure.
# Collapsing both into `|| true` -- and quoting the pattern so the shell never
# expanded it -- is how a broken check reported this repository clean.
set +e
hits=$(git grep -inE "${BANNED}" -- \
  ':!scripts/check-brand.sh' \
  ':!scripts/as-bot.sh' ':!scripts/bot-token.sh' ':!scripts/check-bot-files.py')
status=$?
set -e
if test "$status" -gt 1; then
  printf 'brand check: git grep failed with exit %s\n' "$status" >&2
  exit 1
fi
if test -n "$hits"; then
  printf 'brand check: the former brand at the surface:\n%s\n' "$hits" >&2
  exit 1
fi
printf 'brand check: clean\n'
