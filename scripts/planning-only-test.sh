#!/bin/sh
# Give scripts/planning-only.sh both sides: lists of planning and prose files only (exit 0) and
# lists that need the tests (exit 1). scripts/gate.sh runs it.
#
#   sh scripts/planning-only-test.sh [script]
#
# The optional argument names the script under test (default scripts/planning-only.sh), so that a
# planted defect can be run in a copy. It prints one line per case decided otherwise and exits 1,
# or one line with the count.

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
script=${1:-$root/scripts/planning-only.sh}
test -f "$script" || { echo "planning-only-test: $script: missing"; exit 1; }

planning='.engineering/planning/story/audience-registry.md
.engineering/planning/journal.jsonl
.engineering/project.yaml
docs/decisions/0004-agnostic-relying-party-registration.md
README.md
AGENTS.md'

cases=0
wrong=0
check() {
  expected=$1
  name=$2
  list=$3
  cases=$((cases + 1))
  status=0
  if [ -n "$list" ]; then
    printf '%s\n' "$list" | sh "$script" > /dev/null 2>&1 || status=$?
  else
    sh "$script" < /dev/null > /dev/null 2>&1 || status=$?
  fi
  if [ "$status" -ne "$expected" ]; then
    echo "planning-only-test: $name: exit $status, expected $expected"
    wrong=$((wrong + 1))
  fi
}

check 0 "planning and prose files only" "$planning"
check 0 "one README.md alone" "README.md"
check 1 "with one file of src/" "$planning
src/lib.rs"
check 1 "with one file of crates/" "$planning
crates/identity-client/src/lib.rs"
check 1 "with one *.md under src/" "$planning
src/notes.md"
check 1 "with Cargo.lock" "$planning
Cargo.lock"
check 1 "with the workflow test itself" "$planning
.github/workflows/test.yml"
check 1 "with the script that decides" "$planning
scripts/planning-only.sh"
check 1 "with a change record of changes/" "$planning
changes/0.5.8.yaml"
check 1 "an empty list" ""

if [ "$wrong" -ne 0 ]; then
  echo "planning-only-test: $wrong of $cases case(s) decided otherwise by $script"
  exit 1
fi
echo "planning-only-test: $cases case(s), each decided as expected by $script"
