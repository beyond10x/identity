#!/usr/bin/env bash
# Scan the complete repository history with one checksum-pinned Gitleaks release.
set -euo pipefail

gitleaks_version="8.30.1"
gitleaks_archive="gitleaks_${gitleaks_version}_linux_x64.tar.gz"
gitleaks_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scan_tool_directory="$(mktemp -d "${TMPDIR:-/tmp}/daemonloom-gitleaks.XXXXXXXX")"

cleanup() {
  case "$scan_tool_directory" in
    */daemonloom-gitleaks.*) rm -rf -- "$scan_tool_directory" ;;
    *) echo "refusing to clean an unexpected Gitleaks tool directory" >&2 ;;
  esac
}
trap cleanup EXIT

curl -fsSL   "https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/${gitleaks_archive}"   -o "${scan_tool_directory}/${gitleaks_archive}"
printf '%s  %s\n' "$gitleaks_sha256" "${scan_tool_directory}/${gitleaks_archive}"   | sha256sum --check --status
tar -xzf "${scan_tool_directory}/${gitleaks_archive}" -C "$scan_tool_directory" gitleaks

cd "$repository_root"
"${scan_tool_directory}/gitleaks" git --redact=100 --no-banner
