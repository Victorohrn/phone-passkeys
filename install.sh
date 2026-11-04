#!/usr/bin/env bash
# Builds the native host, registers it with Zen/Firefox, and packages the extension.
# Usage: ./install.sh            build host, register it, package the extension
#        ./install.sh --host-only build and register the host only (when the
#                                 extension comes from addons.mozilla.org)
set -euo pipefail

HOST_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --host-only) HOST_ONLY=1 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_NAME="phone_passkeys_host"
EXT_ID="phone-passkeys@zen-extensions.local"
BIN="$ROOT/host/target/release/phone-passkeys-host"
XPI="$ROOT/dist/phone-passkeys.xpi"

echo "==> Building the native host (release)"
cargo build --release --manifest-path "$ROOT/host/Cargo.toml"

echo "==> Registering the native messaging host"
# Zen (like Firefox) reads user-level native messaging manifests from ~/.mozilla.
for dir in "$HOME/.mozilla/native-messaging-hosts"; do
  mkdir -p "$dir"
  cat > "$dir/$HOST_NAME.json" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Phone Passkeys: WebAuthn hybrid (phone QR) ceremonies for the browser extension",
  "path": "$BIN",
  "type": "stdio",
  "allowed_extensions": ["$EXT_ID"]
}
JSON
  echo "    wrote $dir/$HOST_NAME.json"
done

if [ "$HOST_ONLY" = 1 ]; then
  cat <<MSG

Done. The native host is registered. Open the extension's setup page (toolbar icon ->
Setup instructions, or the add-on's Preferences) and click "Check again".
MSG
  exit 0
fi

echo "==> Packaging the extension"
python3 "$ROOT/tools/build-xpi.py" "$ROOT/extension" "$XPI"

cat <<MSG

Done.

Next steps in Zen:
  1. Open about:config and set  xpinstall.signatures.required  to  false
     (Zen is built without the signing requirement, so this pref is honoured).
  2. Open  file://$XPI  (or drag the file onto the browser) and confirm the install.
     For development you can instead use about:debugging > This Zen > Load Temporary Add-on
     and pick  $ROOT/extension/manifest.json
  3. Click the toolbar icon: it should report that the native host is installed and Bluetooth is available.
  4. Try it: https://webauthn.io  -> Register / Authenticate.

Browser-free check of the host (shows the QR code in the terminal):
  $ROOT/tools/host-smoke-test.py --wait 120
MSG
