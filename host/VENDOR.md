# Vendored libwebauthn

`vendor/libwebauthn/` is a copy of the `libwebauthn` crate from
<https://github.com/linux-credentials/libwebauthn> at the commit recorded in
`vendor/libwebauthn/UPSTREAM_COMMIT` (v0.11.0), wired in through
`[patch.crates-io]` in `Cargo.toml`. The `pxp` dependency is taken from
crates.io (same version) instead of the upstream workspace path, and the
examples were dropped.

## Local changes

**Native `largeBlob` extension (phones over hybrid, platform authenticators).**
Upstream only implements the security-key flavour of WebAuthn `largeBlob`:
getInfo option `largeBlobs` + `largeBlobKey` + the `authenticatorLargeBlobs`
command, and silently drops the extension otherwise. Phones (iCloud Keychain,
Google Password Manager) instead advertise a `largeBlob` *extension* in getInfo
and handle storage themselves, the same way they do for `prf`. Chromium calls
this `LargeBlobSupportType::kExtension`. Without it, Apple's sign-in fails
("Your browser needs to be updated to support signing in with a passkey"),
because icloud.com reads device-trust keys out of the passkey's large blob.

- `proto/ctap2/model/get_assertion.rs`: `Ctap2LargeBlobExtensionInput`,
  `Ctap2GetAssertionRequestExtensions::large_blob` (serialised as
  `largeBlob: {read: true}` or `{write: <DEFLATE>, originalSize: n}`),
  `convert_large_blob_to_native`, and the getInfo check in
  `from_webauthn_request`.
- `proto/ctap2/model/make_credential.rs`: `largeBlob: {support: …}` request
  member and `{supported: bool}` output.
- `webauthn.rs`: `native_large_blob_output` reads
  `unsignedExtensionOutputs["largeBlob"]` (`{blob, originalSize}` /
  `{written}`), inflating the DEFLATE payload with a size cap.
- `ops/webauthn/large_blob.rs`: `deflate_large_blob`, `inflate_large_blob`.

The change is meant to go upstream; once it lands and a release includes it,
delete `vendor/` and the `[patch.crates-io]` entry.

## Updating

```sh
git clone https://github.com/linux-credentials/libwebauthn /tmp/libwebauthn
cp -r /tmp/libwebauthn/libwebauthn vendor/libwebauthn   # then re-apply the changes above
git -C /tmp/libwebauthn rev-parse HEAD > vendor/libwebauthn/UPSTREAM_COMMIT
```
