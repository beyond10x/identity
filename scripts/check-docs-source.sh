#!/bin/sh
# Check the published documentation source for the rules UX round R-01 measured on the docs page
# (ux/rounds/R-01, findings UXF-001, 002, 007, 008, 009). No network, no build; well under 1 s.
#
#   sh scripts/check-docs-source.sh [file ...]     default: README.md
#
# Rules, each printed with file and line when broken:
# - a code line is at most 80 characters (UXF-001: wider lines scroll sideways on the page);
# - every opening code fence names a language;
# - a table cell is at most 150 characters, link targets not counted (UXF-008, UXF-007);
# - the H1 equals `repository.displayName` of b10x.docs.yaml (UXF-009);
# - one heading names the invariants (UXF-002).
# Characters are counted, not bytes. Exit 0 when every file passes, 1 otherwise. POSIX sh: the
# runner's sh is dash, its awk may be mawk.

set -eu
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
manifest=${CHECK_DOCS_MANIFEST:-$root/b10x.docs.yaml}

display=$(sed -n 's/^  displayName: *//p' "$manifest" | head -n 1)
if [ -z "$display" ]; then
  echo "check-docs-source: no repository.displayName in $manifest" >&2
  exit 1
fi

cd "$root"
[ "$#" -gt 0 ] || set -- README.md

status=0
for file in "$@"; do
  LC_ALL=C awk -v file="$file" -v display="$display" '
    function chars(s) { gsub(/[\200-\277]/, "", s); return length(s) }
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function bad(msg) { printf "check-docs-source: %s:%d: %s\n", file, NR, msg; fails++ }
    /^[ \t]*(```|~~~)/ {
      if (!fence) {
        info = $0; sub(/^[ \t]*(```+|~~~+)/, "", info)
        if (trim(info) == "") bad("code fence without a language")
      }
      fence = !fence
      next
    }
    fence {
      if (chars($0) > 80) bad("code line is " chars($0) " characters (at most 80)")
      next
    }
    /^# / && !h1 {
      h1 = 1
      title = trim(substr($0, 3))
      if (title != display) bad("H1 is \"" title "\", b10x.docs.yaml displayName is \"" display "\"")
    }
    /^#+ / { if (tolower($0) ~ /invariant/) invariants = 1 }
    /^\|/ {
      if ($0 ~ /^\|[-:| ]+\|[ \t]*$/) next
      row = $0; gsub(/\\\|/, "\001", row)
      n = split(row, cell, "|")
      for (i = 2; i < n; i++) {
        c = trim(cell[i]); gsub(/\]\([^)]*\)/, "]", c)
        if (chars(c) > 150) bad("table cell " (i - 1) " is " chars(c) " characters (at most 150): " substr(c, 1, 40) "...")
      }
    }
    END {
      if (!h1) { NR = 0; bad("no H1") }
      if (!invariants) { NR = 0; bad("no heading names the invariants") }
      exit fails > 0
    }
  ' "$file" || status=1
done

if [ "$status" -eq 0 ]; then
  echo "check-docs-source: $* pass"
fi
exit "$status"
