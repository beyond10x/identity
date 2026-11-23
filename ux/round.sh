#!/bin/sh
# One measured round against a rendered page: three Playwright runs (each under the 120 s step budget), then the round report.
# Usage (from ux/): slot sh round.sh <R-nn> <source commit> [base url]
set -eu
round=$1
commit=$2
base=${3:-https://beyond10x.github.io}
cd "$(dirname "$0")"
rm -rf "rounds/$round/raw" "rounds/$round/round.json" "rounds/$round/report.md"
rm -f "rounds/$round"/shots/sheet-*.png
mkdir -p ../target/ux
readme=../target/ux/README-$commit.md
git show "$commit:README.md" > "$readme"
status=0
for group in '1280x800|390x844' '1440x900|1024x768' '768x1024'; do
  UX_OUT="rounds/$round" UX_BASE_URL="$base" npx playwright test --workers=2 \
    $(printf '%s\n' "$group" | tr '|' '\n' | sed 's/.*/--project=&-light --project=&-dark/') || status=1
done
node round.ts "rounds/$round" --source-commit "$commit" --url "$base/docs/identity/" --readme "$readme" || status=1
exit $status
