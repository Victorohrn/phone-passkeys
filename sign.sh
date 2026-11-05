#!/usr/bin/env bash
# Signs the extension through addons.mozilla.org (AMO).
#
#   ./sign.sh unlisted   # self-distributed: you get a signed .xpi, nothing is published (default)
#   ./sign.sh listed     # submit to the public AMO listing (full human review, takes days)
#
# Credentials come from https://addons.mozilla.org/developers/addon/api/key/ and are read
# from WEB_EXT_API_KEY / WEB_EXT_API_SECRET, or from ~/.config/phone-passkeys/amo.env:
#   WEB_EXT_API_KEY=user:12345:678
#   WEB_EXT_API_SECRET=...
# Keep that file chmod 600 and never commit it. Either value may also be a 1Password
# secret reference, resolved at run time with the 1Password CLI so nothing secret is
# stored on disk:
#   WEB_EXT_API_KEY="op://Private/Mozilla Dev API/username"
#   WEB_EXT_API_SECRET="op://Private/Mozilla Dev API/credential"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANNEL="${1:-unlisted}"
case "$CHANNEL" in
  listed|unlisted) ;;
  *) echo "usage: $0 [unlisted|listed]" >&2; exit 2 ;;
esac

ENV_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/phone-passkeys/amo.env"
if [ -f "$ENV_FILE" ]; then
  set -a; . "$ENV_FILE"; set +a
fi
resolve_secret() {
  case "$1" in
    op://*)
      command -v op >/dev/null 2>&1 || { echo "1Password CLI (op) is needed to resolve $1" >&2; exit 1; }
      op read --no-newline "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}
WEB_EXT_API_KEY="$(resolve_secret "${WEB_EXT_API_KEY:-}")"
WEB_EXT_API_SECRET="$(resolve_secret "${WEB_EXT_API_SECRET:-}")"
export WEB_EXT_API_KEY WEB_EXT_API_SECRET
: "${WEB_EXT_API_KEY:?set WEB_EXT_API_KEY (JWT issuer from the AMO API keys page)}"
: "${WEB_EXT_API_SECRET:?set WEB_EXT_API_SECRET (JWT secret from the AMO API keys page)}"

if command -v web-ext >/dev/null 2>&1; then
  WEB_EXT=(web-ext)
elif command -v pnpm >/dev/null 2>&1; then
  WEB_EXT=(pnpm dlx web-ext@10)
else
  WEB_EXT=(npx --yes web-ext@10)
fi

VERSION="$(python3 -c 'import json;print(json.load(open("'"$ROOT"'/extension/manifest.json"))["version"])')"
echo "==> Linting extension $VERSION"
"${WEB_EXT[@]}" lint --source-dir "$ROOT/extension" --no-input

ARGS=(--source-dir "$ROOT/extension" --channel "$CHANNEL" --artifacts-dir "$ROOT/dist" --no-input)
if [ "$CHANNEL" = listed ]; then
  # Listing metadata (name, summary, description, category, licence, reviewer notes).
  ARGS+=(--amo-metadata "$ROOT/amo-metadata.json" --approval-timeout 0)
fi

echo "==> Signing ($CHANNEL) through addons.mozilla.org"
"${WEB_EXT[@]}" sign "${ARGS[@]}"

cat <<MSG

Done. Remember that AMO rejects re-uploads of the same version number:
bump "version" in extension/manifest.json before signing the next build.
MSG
