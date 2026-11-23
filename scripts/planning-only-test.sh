#!/bin/sh
# Give scripts/planning-only.sh both sides: lists of planning and prose files only (exit 0) and
# lists that need the tests (exit 1), as path lists and as commits of a scratch repository that
# the script diffs itself. scripts/gate.sh runs it.
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
script=$(cd -- "$(dirname -- "$script")" && pwd)/$(basename -- "$script")

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

# The two-commit form, which the workflow runs: the real `git diff` over commits of a scratch
# repository under target/. A rename of a code file to a *.md must list the old path too.
mkdir -p "$root/target"
repo=$(mktemp -d "$root/target/planning-only-test.XXXXXXXX")
trap 'rm -rf -- "$repo"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
g() {
  git -C "$repo" -c user.name=planning-only-test -c user.email=planning-only-test@invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@" > /dev/null
}
g init -q -b main
mkdir -p "$repo/src" "$repo/docs"
printf 'pub fn a() {}\npub fn b() {}\npub fn c() {}\n' > "$repo/src/lib.rs"
printf '# Notes\n\nOne.\nTwo.\nThree.\n' > "$repo/docs/notes.md"
printf '# Readme\n' > "$repo/README.md"
g add -A
g commit -q -m base
base=$(git -C "$repo" rev-parse HEAD)

check_diff() {
  expected=$1
  name=$2
  cases=$((cases + 1))
  head=$(git -C "$repo" rev-parse HEAD)
  status=0
  (cd "$repo" && sh "$script" "$base" "$head") > /dev/null 2>&1 || status=$?
  if [ "$status" -ne "$expected" ]; then
    echo "planning-only-test: $name: exit $status, expected $expected"
    wrong=$((wrong + 1))
  fi
  g reset -q --hard "$base"
}

printf 'More.\n' >> "$repo/README.md"
g commit -q -am readme
check_diff 0 "git diff: README.md changed"
g mv docs/notes.md docs/renamed.md
g commit -q -m prose-rename
check_diff 0 "git diff: a *.md renamed to a *.md"
printf 'pub fn d() {}\n' >> "$repo/src/lib.rs"
g commit -q -am code
check_diff 1 "git diff: src/lib.rs changed"
g mv src/lib.rs docs/lib.md
g commit -q -m code-to-prose
check_diff 1 "git diff: src/lib.rs renamed to docs/lib.md"

if [ "$wrong" -ne 0 ]; then
  echo "planning-only-test: $wrong of $cases case(s) decided otherwise by $script"
  exit 1
fi
echo "planning-only-test: $cases case(s), each decided as expected by $script"
