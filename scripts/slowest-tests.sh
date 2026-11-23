#!/bin/sh
# The slowest tests of a cargo-nextest JUnit report, as scripts/gate.sh prints them.
#
# usage: slowest-tests.sh <junit file> [count]
#
# Prints one line per test, the slowest first, at most count of them (default 10):
# "  <seconds>s <classname> <name>", the seconds with three decimals in eight columns. It exits
# 1 with one line on standard error when the file is missing or count is not a number.
#
# No command of the pipeline ends before its input ends: under pipefail a reader that stops
# early (head) ends the writer before it on SIGPIPE once the list is larger than the pipe's
# buffer, and the pipeline fails with 141 although every test passed (2026-11-22, 892 tests,
# a list of 70,331 bytes). awk reads every line and prints the first count. The script sets
# pipefail itself where the shell has it, so a test of the script sees what the task sees.
# POSIX sh: the forge's sh is dash.

set -u
if (set -o pipefail) 2> /dev/null; then
  set -o pipefail
fi

junit=${1:-}
count=${2:-10}
if [ -z "$junit" ] || [ ! -f "$junit" ]; then
  echo "slowest-tests: ${junit:-<junit file>}: no such file" >&2
  exit 1
fi
case $count in
  '' | *[!0-9]*)
    echo "slowest-tests: count $count is not a number" >&2
    exit 1
    ;;
esac

tr '\n' ' ' < "$junit" |
  sed 's/<testcase /\
<testcase /g' |
  sed -n 's/^<testcase name="\([^"]*\)" classname="\([^"]*\)"[^>]*time="\([0-9.]*\)".*/\3 \2 \1/p' |
  sort -rn |
  awk -v count="$count" 'NR <= count { printf "  %8.3fs %s %s\n", $1, $2, $3 }'
