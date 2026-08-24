#!/usr/bin/env bash
# Run one git command with b10x-bot authorship and push authentication.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
bot_token="$(${repo_root}/scripts/bot-token.sh)"
export B10X_BOT_TOKEN="$bot_token"

bot_id="$(
  curl -fsS \
    -H "Authorization: Bearer ${bot_token}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    'https://api.github.com/users/b10x-bot%5Bbot%5D' \
    | jq -er '.id'
)"

exec git \
  -c user.name='b10x-bot[bot]' \
  -c user.email="${bot_id}+b10x-bot[bot]@users.noreply.github.com" \
  -c 'url.https://github.com/.pushInsteadOf=git@github.com:' \
  -c 'credential.https://github.com.helper=' \
  -c 'credential.https://github.com.helper=!f() { echo username=x-access-token; echo "password=${B10X_BOT_TOKEN}"; }; f' \
  "$@"
