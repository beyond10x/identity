#!/usr/bin/env bash
# Mint one short-lived GitHub App installation token for b10x-bot.
set -euo pipefail

config_root="${XDG_CONFIG_HOME:-${HOME}/.config}/b10x"
config="${B10X_BOT_CONFIG:-${config_root}/b10x-bot.json}"
key="${B10X_BOT_KEY:-${config_root}/b10x-bot.private-key.pem}"
org="${B10X_BOT_ORG:-beyond10x}"

script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 "${script_root}/check-bot-files.py" "$config" "$key"

app_id="${B10X_BOT_APP_ID:-$(jq -er '.app_id' "$config")}"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now="$(date +%s)"
header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
payload="$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' "$((now - 60))" "$((now + 540))" "$app_id" | b64url)"
signature="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$key" -binary | b64url)"
jwt="${header}.${payload}.${signature}"

api() {
  curl -fsS \
    -H "Authorization: Bearer ${jwt}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@"
}

installation_id="$(
  api https://api.github.com/app/installations \
    | jq -er --arg org "$org" '.[] | select(.account.login == $org) | .id' \
    | head -1
)"

api -X POST "https://api.github.com/app/installations/${installation_id}/access_tokens" \
  | jq -er '.token'
