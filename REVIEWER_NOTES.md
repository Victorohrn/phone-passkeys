# Notes for AMO reviewers

Phone Passkeys adds the WebAuthn *hybrid* transport ("use your phone or tablet",
QR code + Bluetooth proximity + vendor tunnel) to Firefox-based browsers on
Linux, where Firefox does not implement it. It is the same user flow Chrome
offers natively.

## Architecture

- `page.js` (content script, `world: "MAIN"`): replaces
  `navigator.credentials.get()` / `create()` for WebAuthn (`publicKey`)
  requests. Requests with `mediation: "conditional"` and non-WebAuthn
  credentials are passed to the browser's own implementation untouched.
- `bridge.js` (isolated world): relays the request to the background script.
- `background.js`: takes the origin from the port sender (the browser's own
  view of the frame, never page data), opens a dialog window with the QR code,
  and talks to a native messaging host.
- `host/` (Rust, same repository, LGPL-2.1): performs the ceremony with the
  open-source `libwebauthn` crate from the Credentials-for-Linux project.

## Why these permissions

- `nativeMessaging`: browser extensions cannot listen for Bluetooth
  advertisements or run the CTAP protocol; the native host does that.
- `<all_urls>` content scripts: any site may use WebAuthn, so the override must
  be present everywhere, exactly like password-manager extensions that provide
  passkeys. The content script only acts when a page calls the WebAuthn API.
- `world: "MAIN"` is required to replace a page-visible API.

## Data and network

- The extension collects nothing (`data_collection_permissions: none`) and
  makes no network requests itself.
- The native host connects to the phone vendor's caBLE tunnel server
  (`cable.ua5v.com` for Google, `cable.auth.com` for Apple) during a sign-in,
  as every hybrid-transport client does. Traffic inside the tunnel is
  end-to-end encrypted between the computer and the phone (Noise protocol).
  The host may also fetch `https://<rp-id>/.well-known/webauthn` to honour
  WebAuthn Related Origin Requests.
- No remote code is loaded. All JavaScript is unminified and in the package.

## Behaviour without the native host

If the host is not installed, the first intercepted request is handed back to
the browser's own WebAuthn implementation (`useNative`) and a setup tab opens
once. Built-in authenticators and security keys therefore keep working after
installing the extension alone.

## How to test

1. Linux machine with a Bluetooth adapter; Android phone (Google Password
   Manager) or iPhone (iCloud Keychain).
2. Build and register the host: `./install.sh --host-only` (needs Rust).
3. Open https://webauthn.io → Register. The QR dialog opens; scan it with the
   phone and approve. Then Authenticate with the same passkey.
4. The toolbar popup and the setup page (add-on preferences) report whether
   the host is installed and Bluetooth is available.
