#!/bin/sh
# Decide whether a change is planning or prose only, so that the workflow `test` may skip
# building and testing it (.github/workflows/test.yml).
#
#   sh scripts/planning-only.sh <base> <head>     the files of `git diff <base>...<head>`
#   <one path per line> | sh scripts/planning-only.sh
#
# With two commits it lists the changed files itself, with rename detection off: a rename lists
# both its old and its new path, so moving `src/lib.rs` to `docs/lib.md` is not prose only.
# Without arguments it reads one path per line, relative to the repository root, from standard
# input. It exits 0 when every path is a planning or prose file, and 1 when one is not or when
# there is none; it prints each path that is not, and one line with the decision.
#
# The one list of planning and prose paths:
# - `.engineering/**`: the planning store;
# - `*.md` anywhere else (`README.md`, `AGENTS.md`, `docs/decisions/*.md`), except under `src/`
#   and `crates/`, where the code may read it.
# The documentation check (`b10x-docs-check.yml`) is a separate workflow and is not skipped.
# POSIX sh: the runner's sh is dash.

set -eu

decide() {
  total=0
  other=0
  while IFS= read -r path || [ -n "$path" ]; do
    [ -n "$path" ] || continue
    total=$((total + 1))
    case $path in
      .engineering/*) continue ;;
      src/* | crates/*) ;;
      *.md) continue ;;
    esac
    other=$((other + 1))
    echo "planning-only: $path: not a planning or prose file"
  done

  if [ "$total" -eq 0 ]; then
    echo "planning-only: no changed file; the tests run"
    return 1
  fi
  if [ "$other" -ne 0 ]; then
    echo "planning-only: $other of $total changed file(s) not planning or prose; the tests run"
    return 1
  fi
  echo "planning-only: $total changed file(s), all planning or prose; the build and the tests are skipped"
}

case $# in
  0) decide ;;
  2)
    changed=$(git diff --no-renames --name-only "$1...$2")
    printf '%s\n' "$changed" | sed 's/^/  /'
    printf '%s\n' "$changed" | decide
    ;;
  *)
    echo "usage: sh scripts/planning-only.sh [<base> <head>]" >&2
    exit 2
    ;;
esac
