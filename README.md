# Phone Passkeys for Zen / Firefox on Linux

Sign in with the passkeys on your phone or tablet by scanning a QR code, the way
Chrome's "Use your phone or tablet" option works. Firefox (and therefore Zen)
on Linux does not implement the WebAuthn *hybrid* transport (caBLE), so sites
that only offer phone passkeys cannot be used without switching browsers. This
project fills that gap with a browser extension plus a small native helper.

```
page (navigator.credentials.get/create)
  │  page.js replaces the WebAuthn entry points (page world)
  ▼
bridge.js (extension world) ──runtime port──▶ background.js
                                                 │  opens the QR dialog window
                                                 │  native messaging (stdio JSON)
                                                 ▼
                                   phone-passkeys-host (Rust, libwebauthn)
                                     1. generates the FIDO:/ QR code
                                     2. listens for the phone's BLE advertisement (proximity)
                                     3. opens the WebSocket tunnel (Google / Apple relay)
                                     4. Noise handshake + CTAP2 over the tunnel
                                     5. returns a standard WebAuthn JSON credential
```

The ceremony itself (QR encoding, BLE scan, tunnel, Noise, CTAP2) is done by
[libwebauthn](https://github.com/linux-credentials/libwebauthn), the library
behind the Credentials-for-Linux project. This repo only adds the browser glue
and a dialog. Nothing is installed system-wide: no daemon, no portal patches.

## Requirements

- Zen, or Firefox 140 or newer (needed for the `world: "MAIN"` content script and the data-collection manifest key; Zen 1.23 is on Firefox 158).
- Linux with BlueZ running and a Bluetooth adapter (`bluetoothctl show` must say `Powered: yes`).
  Bluetooth is only used to receive the phone's advertisement, which proves it is nearby.
- Rust toolchain (`cargo`), `pkg-config`, OpenSSL and D-Bus headers, Python 3 (packaging and tests).
- A phone with passkeys: Android (Google Password Manager) or iPhone/iPad (iCloud Keychain).
  Both use their vendor's tunnel server; the host knows both.
- Optional: `publicsuffix-list` package. Without it the host uses an embedded copy of the list.

## Install

Two ways, depending on where the extension comes from.

**From addons.mozilla.org (once published).** Install the extension from the
store; a setup tab opens. Then install only the native host:

```sh
git clone https://github.com/Victorohrn/phone-passkeys.git
cd phone-passkeys
./install.sh --host-only
```

Click *Check again* on the setup page (also reachable from the toolbar popup or
the add-on's Preferences). Until the host is installed, passkey requests are
handed back to Firefox unchanged, so nothing breaks.

**From this repository (unsigned build).**

```sh
./install.sh
```

This builds `host/` in release mode, writes the native messaging manifest to
`~/.mozilla/native-messaging-hosts/phone_passkeys_host.json` (Zen reads the same
location as Firefox), and packages the extension to `dist/phone-passkeys.xpi`.

Then in Zen:

1. `about:config` → set `xpinstall.signatures.required` to `false`. Zen is built
   without the add-on signing requirement, so the pref is honoured (stock Firefox
   release ignores it; there you need Developer Edition/Nightly or a signed build).
2. Open `dist/phone-passkeys.xpi` (File → Open, or drag it onto a tab) and confirm.
   For development, `about:debugging` → *This Zen* → *Load Temporary Add-on* →
   `extension/manifest.json` works without the pref.
3. Click the toolbar icon. It pings the native host and reports whether Bluetooth is available.
4. Try <https://webauthn.io>: *Register* or *Authenticate* should open the QR dialog.

## How a request flows

1. A site calls `navigator.credentials.get({ publicKey })` (or `create`).
2. `page.js` serialises the options to WebAuthn JSON and hands them to the
   background script. Requests with `mediation: "conditional"` (autofill) and
   non-WebAuthn credentials go to Firefox untouched.
3. The background script derives the origin from the frame that asked (never
   from page data), starts the host, and opens the dialog window.
4. The host validates `rp.id` against the origin (Public Suffix List plus
   Related Origin Requests), shows a QR code, and waits for the phone.
5. The dialog shows progress: *waiting* → *connecting* → *connected* (confirm on
   the phone). Transport failures re-issue a fresh code up to five times.
6. The credential comes back as WebAuthn JSON and is rebuilt into an object with
   the `PublicKeyCredential` / `AuthenticatorAssertionResponse` prototypes, so
   `instanceof`, `getClientExtensionResults()`, `toJSON()`, `getTransports()`,
   `getPublicKey()`, etc. behave as libraries expect.

The dialog also offers **Use security key**, which hands the original request
back to Firefox's own WebAuthn implementation (USB security keys keep working).

## Testing without a browser

```sh
tools/host-smoke-test.py --wait 120        # sign-in flow for https://webauthn.io
tools/host-smoke-test.py --cmd create      # registration flow
```

The script speaks the native messaging protocol to the host, prints the QR
code in the terminal (install `qrencode` for a scannable image), and either
waits for your phone or cancels after `--wait` seconds. It exits non-zero if
the host misbehaves (no QR, no clean cancel, no clean exit).

Unit tests for the host: `cargo test --manifest-path host/Cargo.toml`.

## Troubleshooting

- **Toolbar popup says the host is not reachable.** Run `./install.sh` again and
  restart Zen; check that `~/.mozilla/native-messaging-hosts/phone_passkeys_host.json`
  points at an existing binary.
- **"No Bluetooth adapter is available".** `systemctl status bluetooth`,
  `bluetoothctl power on`. BlueZ is accessed over D-Bus; no root needed.
- **Logs.** The host logs to stderr, which Zen shows in the Browser Console
  (Ctrl+Shift+J). Set `PHONE_PASSKEYS_LOG=debug` when running the smoke test.
- **A site does not detect passkey support.** `page.js` reports a platform
  authenticator as available (`CLAIM_PLATFORM_AUTHENTICATOR`) so that sites
  offer passkey sign-in; flip the constant if a site misbehaves.
- **Phone shows an error after scanning.** The host always closes the tunnel
  cleanly on cancel; if it happens on a successful sign-in, capture the debug
  log and the phone model.

## Limitations

- One request at a time; a second concurrent request is rejected.
- No "remember this phone" (state-assisted) flow yet: every sign-in scans a QR
  code. libwebauthn supports it, so it is a natural next step.
- No conditional UI (passkey autofill), which would need browser integration.
- Only `https://` origins and `http://localhost`.
- Unsigned extension: Zen needs `xpinstall.signatures.required=false`, or sign it
  yourself through addons.mozilla.org (unlisted).

## Publishing to addons.mozilla.org

Everything an AMO submission needs is in the repo:

- `amo-metadata.json`: listing name, summary, description, category
  (`privacy-security`), licence (`MPL-2.0`), release notes and reviewer notes.
- `REVIEWER_NOTES.md`: what reviewers are told (also embedded in the metadata).
- `assets/listing-icon-128.png` / `-64.png`: listing icons, uploaded in the
  Developer Hub.
- `sign.sh`: wraps `web-ext sign`. Credentials come from the AMO API keys page
  and are read from `WEB_EXT_API_KEY` / `WEB_EXT_API_SECRET` or
  `~/.config/phone-passkeys/amo.env`.

```sh
./sign.sh unlisted   # self-distributed: signed .xpi in dist/, nothing published
./sign.sh listed     # public listing: submits for human review
```

Before the first upload, settle the two things that cannot change afterwards:
the add-on ID (`browser_specific_settings.gecko.id` in `extension/manifest.json`)
and the name. Also replace the placeholder `homepage_url` / repository links with
the real repository. Every later submission needs a higher `version`.

Listed add-ons get a full human review. Reviewers can read the host source in
`host/` and follow `REVIEWER_NOTES.md`; the extension contains no minified or
generated code, so no separate source upload is needed.

`.github/workflows/ci.yml` builds and tests both parts on every push and, on a
`v*` tag, attaches a prebuilt host tarball and an unsigned .xpi to a GitHub
release. That gives store users a download instead of a Rust build.

## Layout

```
extension/          WebExtension (manifest v2, Firefox/Zen)
host/               Rust native messaging host (libwebauthn)
tools/              packaging script, host smoke test, page.js unit test
install.sh          build + register (+ package)
sign.sh             sign / submit through addons.mozilla.org
amo-metadata.json   store listing metadata
REVIEWER_NOTES.md   notes for AMO reviewers
```

## Licence

The extension is released under the Mozilla Public License 2.0 (`LICENSE`).
The native host in `host/` is released under the GNU LGPL 2.1 or later
(`host/LICENSE`) because it statically links libwebauthn (LGPL-2.1-or-later).
The extension's structure is informed by the credentialsd helper add-on but
written independently.
