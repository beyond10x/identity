#!/bin/sh
# Both sides of scripts/check-docs-source.sh: a passing document, and one failing document per rule
# that must fail with that rule's message. POSIX sh; no network; fixtures under target/.

set -eu
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/target"
dir=$(mktemp -d "$root/target/check-docs-source-test.XXXXXX")
trap 'rm -rf "$dir"' EXIT INT TERM

printf 'repository:\n  displayName: Demo\n  id: demo\n' > "$dir/b10x.docs.yaml"
export CHECK_DOCS_MANIFEST="$dir/b10x.docs.yaml"
fence='```'
long=$(printf '%081d' 0)
cell=$(printf 'x%.0s' $(seq 1 151))
ok_cell=$(printf 'é%.0s' $(seq 1 150))

good() {
  printf '# Demo\n\n## Invariants\n\n%sbash\necho ok\n%s\n\n| a | b |\n|---|---|\n| [x](%s) | %s |\n' \
    "$fence" "$fence" "$long" "$ok_cell"
}

failures=0
expect() {
  name=$1 want=$2 file=$3
  if out=$(sh "$root/scripts/check-docs-source.sh" "$file" 2>&1); then
    if [ "$want" = pass ]; then
      echo "check-docs-source-test: $name: pass as expected"
    else
      echo "check-docs-source-test: $name: passed, expected \"$want\"" >&2
      failures=$((failures + 1))
    fi
  elif [ "$want" != pass ] && printf '%s\n' "$out" | grep -q -- "$want"; then
    echo "check-docs-source-test: $name: refused as expected"
  else
    echo "check-docs-source-test: $name: expected \"$want\", got: $out" >&2
    failures=$((failures + 1))
  fi
}

good > "$dir/good.md"
expect good pass "$dir/good.md"

good | sed 's/^echo ok$/'"$long"'/' > "$dir/code-line.md"
expect code-line 'code line is 81 characters' "$dir/code-line.md"

good | sed 's/^```bash$/```/' > "$dir/fence.md"
expect fence 'code fence without a language' "$dir/fence.md"

good | sed 's/^| \[x\].*/| a | '"$cell"' |/' > "$dir/cell.md"
expect cell 'table cell 2 is 151 characters' "$dir/cell.md"

good | sed 's/^# Demo$/# demo/' > "$dir/h1.md"
expect h1 'H1 is "demo"' "$dir/h1.md"

good | sed 's/^## Invariants$/## Rules/' > "$dir/invariants.md"
expect invariants 'no heading names the invariants' "$dir/invariants.md"

if [ "$failures" -ne 0 ]; then
  echo "check-docs-source-test: $failures case(s) failed" >&2
  exit 1
fi
echo "check-docs-source-test: 6 cases pass"
