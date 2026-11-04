#!/usr/bin/env node
// Unit test for extension/page.js: runs it against stubbed WebAuthn globals and
// checks option serialisation, credential reconstruction and the pass-through,
// abort and error paths. Usage: node tools/page-js-test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(here, '..', 'extension', 'page.js'), 'utf8');

// ---- stub browser globals --------------------------------------------------
const listeners = [];
globalThis.window = globalThis;
globalThis.isSecureContext = true;
globalThis.addEventListener = (type, fn) => { if (type === 'message') listeners.push(fn); };
const posted = [];
globalThis.postMessage = (data) => {
  posted.push(data);
  queueMicrotask(() => { for (const fn of [...listeners]) fn({ source: globalThis, data }); });
};
class CredentialsContainer {
  get(options) { return Promise.resolve({ native: 'get', options }); }
  create(options) { return Promise.resolve({ native: 'create', options }); }
}
class PublicKeyCredential {
  static isUserVerifyingPlatformAuthenticatorAvailable() { return Promise.resolve(false); }
  static getClientCapabilities() { return Promise.resolve({ conditionalGet: true, hybridTransport: false }); }
}
class AuthenticatorAttestationResponse {}
class AuthenticatorAssertionResponse {}
Object.assign(globalThis, { CredentialsContainer, PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse });
Object.defineProperty(globalThis, 'navigator', { value: { credentials: Object.create(CredentialsContainer.prototype) }, configurable: true });

// Load page.js as a classic script.
new Function(source)();

const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const bytesOf = (buf) => Array.from(new Uint8Array(buf));
const nextRequest = () => posted.filter((m) => m.type === 'phone-passkeys:request').at(-1);
const reply = (requestId, payload) => globalThis.postMessage({ type: 'phone-passkeys:response', requestId, ...payload });
const tick = () => new Promise((r) => setTimeout(r, 0));

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`ok   ${name}`); }
  catch (e) { console.log(`FAIL ${name}\n     ${e.stack}`); process.exitCode = 1; }
}

await test('conditional mediation and non-WebAuthn requests pass through', async () => {
  const r1 = await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(1) }, mediation: 'conditional' });
  assert.equal(r1.native, 'get');
  const r2 = await navigator.credentials.create({ password: {} });
  assert.equal(r2.native, 'create');
  assert.equal(nextRequest(), undefined);
});

await test('get(): options are serialised to WebAuthn JSON and the assertion is rebuilt', async () => {
  const challenge = new Uint8Array([1, 2, 3, 250, 251, 252]).buffer;
  const credId = new Uint8Array([9, 8, 7]);
  const p = navigator.credentials.get({
    publicKey: {
      challenge, rpId: 'webauthn.io', timeout: 60000, userVerification: 'preferred',
      allowCredentials: [{ type: 'public-key', id: credId, transports: ['hybrid'] }],
      extensions: { prf: { eval: { first: new Uint8Array([4, 4]) } } },
    },
  });
  await tick();
  const req = nextRequest();
  assert.equal(req.cmd, 'get');
  assert.equal(req.publicKey.challenge, b64u([1, 2, 3, 250, 251, 252]));
  assert.equal(req.publicKey.allowCredentials[0].id, b64u([9, 8, 7]));
  assert.equal(req.publicKey.extensions.prf.eval.first, b64u([4, 4]));
  assert.equal(req.publicKey.timeout, 60000);

  const credential = {
    id: b64u([9, 8, 7]), rawId: b64u([9, 8, 7]), type: 'public-key', authenticatorAttachment: 'cross-platform',
    response: { clientDataJSON: b64u(Buffer.from('{"type":"webauthn.get"}')), authenticatorData: b64u([1, 1]), signature: b64u([2, 2]), userHandle: b64u([3, 3]) },
    clientExtensionResults: { prf: { results: { first: b64u([5, 5]) } } },
  };
  reply(req.requestId, { credential });
  const cred = await p;
  assert.ok(cred instanceof PublicKeyCredential);
  assert.ok(cred.response instanceof AuthenticatorAssertionResponse);
  assert.equal(cred.id, credential.id);
  assert.equal(cred.type, 'public-key');
  assert.deepEqual(bytesOf(cred.rawId), [9, 8, 7]);
  assert.ok(cred.rawId instanceof ArrayBuffer);
  assert.deepEqual(bytesOf(cred.response.signature), [2, 2]);
  assert.deepEqual(bytesOf(cred.response.userHandle), [3, 3]);
  assert.equal(Buffer.from(cred.response.clientDataJSON).toString(), '{"type":"webauthn.get"}');
  assert.deepEqual(bytesOf(cred.getClientExtensionResults().prf.results.first), [5, 5]);
  assert.deepEqual(cred.toJSON(), credential);
  assert.equal(cred.authenticatorAttachment, 'cross-platform');
});

await test('create(): attestation response exposes the WebAuthn L3 accessors', async () => {
  const p = navigator.credentials.create({ publicKey: { challenge: new Uint8Array([7]), rp: { id: 'webauthn.io', name: 'x' }, user: { id: new Uint8Array([1]), name: 'u', displayName: 'U' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } });
  await tick();
  const req = nextRequest();
  assert.equal(req.cmd, 'create');
  assert.equal(req.publicKey.user.id, b64u([1]));
  const credential = {
    id: b64u([1, 2]), rawId: b64u([1, 2]), type: 'public-key',
    response: { clientDataJSON: b64u([1]), authenticatorData: b64u([2]), attestationObject: b64u([3]), transports: ['hybrid', 'internal'], publicKey: b64u([4]), publicKeyAlgorithm: -7 },
    clientExtensionResults: {},
  };
  reply(req.requestId, { credential });
  const cred = await p;
  assert.ok(cred.response instanceof AuthenticatorAttestationResponse);
  assert.deepEqual(cred.response.getTransports(), ['hybrid', 'internal']);
  assert.deepEqual(bytesOf(cred.response.getAuthenticatorData()), [2]);
  assert.deepEqual(bytesOf(cred.response.getPublicKey()), [4]);
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual(bytesOf(cred.response.attestationObject), [3]);
  assert.equal(cred.toJSON().authenticatorAttachment, 'cross-platform');
});

await test('"use security key" falls back to the native implementation with the original options', async () => {
  const options = { publicKey: { challenge: new Uint8Array([1]), rpId: 'webauthn.io' } };
  const p = navigator.credentials.get(options);
  await tick();
  reply(nextRequest().requestId, { useNative: true });
  const r = await p;
  assert.equal(r.native, 'get');
  assert.equal(r.options, options);
});

await test('errors become DOMExceptions with the reported name', async () => {
  const p = navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) } });
  await tick();
  reply(nextRequest().requestId, { error: { name: 'InvalidStateError', message: 'already registered' } });
  await assert.rejects(p, (e) => e instanceof DOMException && e.name === 'InvalidStateError' && e.message === 'already registered');
});

await test('AbortSignal rejects with AbortError and sends a cancel', async () => {
  const ac = new AbortController();
  const p = navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) }, signal: ac.signal });
  await tick();
  const req = nextRequest();
  ac.abort();
  await assert.rejects(p, (e) => e.name === 'AbortError');
  await tick();
  assert.ok(posted.some((m) => m.type === 'phone-passkeys:cancel' && m.requestId === req.requestId));
});

await test('capability probes advertise hybrid transport', async () => {
  assert.equal(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), true);
  const caps = await PublicKeyCredential.getClientCapabilities();
  assert.equal(caps.hybridTransport, true);
  assert.equal(caps.conditionalGet, true);
});

console.log(`\n${passed} test(s) passed${process.exitCode ? ', some FAILED' : ''}`);
