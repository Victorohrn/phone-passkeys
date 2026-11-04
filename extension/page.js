// Phone Passkeys - page-world script.
//
// Runs inside the web page's own JavaScript world (manifest `world: "MAIN"`)
// so it can replace navigator.credentials.get() / create() for WebAuthn
// requests. Intercepted requests are forwarded (via window.postMessage) to
// bridge.js, which lives in the extension's isolated world and relays them to
// the background script. The background script performs the ceremony with a
// phone over the hybrid transport (QR code + BLE proximity + tunnel) through a
// native messaging host, and the resulting credential comes back the same way.
//
// Anything we do not handle (conditional/autofill mediation, non-WebAuthn
// credentials) is passed straight through to the browser's own implementation.
(() => {
  'use strict';

  if (!window.isSecureContext) return;
  if (typeof CredentialsContainer === 'undefined' || typeof PublicKeyCredential === 'undefined') return;

  const MARK = '__phonePasskeysInstalled';
  if (Object.prototype.hasOwnProperty.call(window, MARK)) return;
  Object.defineProperty(window, MARK, { value: true });

  // When true, PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  // resolves true so that sites offer passkey sign-in / passkey creation even
  // though Linux has no built-in platform authenticator. The phone fills that role.
  const CLAIM_PLATFORM_AUTHENTICATOR = true;

  const REQ = 'phone-passkeys:request';
  const RES = 'phone-passkeys:response';
  const CANCEL = 'phone-passkeys:cancel';

  const proto = CredentialsContainer.prototype;
  const nativeGet = proto.get;
  const nativeCreate = proto.create;
  const nativeGetClientCapabilities = PublicKeyCredential.getClientCapabilities;

  // ---------------------------------------------------------------- helpers

  function bytesToBase64Url(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToBuffer(str) {
    if (typeof str !== 'string') return null;
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function isBufferSource(v) {
    return v instanceof ArrayBuffer || ArrayBuffer.isView(v);
  }

  function bufferSourceToBytes(v) {
    if (v instanceof ArrayBuffer) return new Uint8Array(v);
    return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  }

  // Converts a PublicKeyCredential{Creation,Request}Options dictionary into the
  // WebAuthn JSON form (every BufferSource becomes a base64url string).
  function toJsonOptions(value) {
    if (value === null || value === undefined) return value;
    if (isBufferSource(value)) return bytesToBase64Url(bufferSourceToBytes(value));
    if (Array.isArray(value)) return value.map(toJsonOptions);
    const t = typeof value;
    if (t === 'function' || t === 'symbol') return undefined;
    if (t === 'object') {
      const out = {};
      for (const key of Object.keys(value)) {
        const v = toJsonOptions(value[key]);
        if (v !== undefined) out[key] = v;
      }
      return out;
    }
    return value;
  }

  function domException(message, name) {
    return new DOMException(message, name);
  }

  function defineAttributes(obj, attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      Object.defineProperty(obj, k, { value: v, enumerable: true, configurable: true, writable: false });
    }
  }

  function defineMethods(obj, methods) {
    for (const [k, v] of Object.entries(methods)) {
      Object.defineProperty(obj, k, { value: v, enumerable: false, configurable: true, writable: true });
    }
  }

  // Client extension outputs arrive as WebAuthn JSON; turn the binary members
  // back into ArrayBuffers the way getClientExtensionResults() returns them.
  function decodeExtensionOutputs(json) {
    const out = {};
    if (!json || typeof json !== 'object') return out;
    for (const [k, v] of Object.entries(json)) out[k] = v;
    if (json.prf && typeof json.prf === 'object') {
      out.prf = {};
      if (json.prf.enabled !== undefined) out.prf.enabled = json.prf.enabled;
      if (json.prf.results) {
        out.prf.results = { first: base64UrlToBuffer(json.prf.results.first) };
        if (json.prf.results.second !== undefined) {
          out.prf.results.second = base64UrlToBuffer(json.prf.results.second);
        }
      }
    }
    if (json.hmacGetSecret && typeof json.hmacGetSecret === 'object') {
      out.hmacGetSecret = { output1: base64UrlToBuffer(json.hmacGetSecret.output1) };
      if (json.hmacGetSecret.output2 !== undefined) {
        out.hmacGetSecret.output2 = base64UrlToBuffer(json.hmacGetSecret.output2);
      }
    }
    if (json.largeBlob && typeof json.largeBlob === 'object') {
      out.largeBlob = Object.assign({}, json.largeBlob);
      if (typeof json.largeBlob.blob === 'string') {
        out.largeBlob.blob = base64UrlToBuffer(json.largeBlob.blob);
      }
    }
    return out;
  }

  // Builds an object that walks and talks like a PublicKeyCredential from the
  // WebAuthn JSON (RegistrationResponseJSON / AuthenticationResponseJSON)
  // produced by the native host. Pages cannot construct real
  // PublicKeyCredential instances, so we create objects with the right
  // prototypes and own properties; instanceof checks and every accessor used by
  // common libraries (SimpleWebAuthn, webauthn-json, ...) work on them.
  function buildCredential(cmd, c) {
    if (!c || typeof c !== 'object' || !c.response) throw new Error('empty credential');
    const r = c.response;
    const clientDataJSON = base64UrlToBuffer(r.clientDataJSON);
    const authenticatorData = base64UrlToBuffer(r.authenticatorData);
    let response;
    if (cmd === 'create') {
      const transports = Array.isArray(r.transports) ? r.transports.slice() : ['hybrid'];
      const publicKey = r.publicKey ? base64UrlToBuffer(r.publicKey) : null;
      const alg = typeof r.publicKeyAlgorithm === 'number' ? r.publicKeyAlgorithm : -7;
      response = Object.create(AuthenticatorAttestationResponse.prototype);
      defineAttributes(response, {
        clientDataJSON,
        attestationObject: base64UrlToBuffer(r.attestationObject),
      });
      defineMethods(response, {
        getTransports() { return transports.slice(); },
        getAuthenticatorData() { return authenticatorData; },
        getPublicKey() { return publicKey; },
        getPublicKeyAlgorithm() { return alg; },
      });
    } else {
      response = Object.create(AuthenticatorAssertionResponse.prototype);
      defineAttributes(response, {
        clientDataJSON,
        authenticatorData,
        signature: base64UrlToBuffer(r.signature),
        userHandle: r.userHandle ? base64UrlToBuffer(r.userHandle) : null,
      });
    }

    const extensionResults = decodeExtensionOutputs(c.clientExtensionResults);
    const json = JSON.parse(JSON.stringify(c));
    if (!json.clientExtensionResults) json.clientExtensionResults = {};
    if (!json.authenticatorAttachment) json.authenticatorAttachment = 'cross-platform';

    const cred = Object.create(PublicKeyCredential.prototype);
    defineAttributes(cred, {
      id: c.id,
      rawId: base64UrlToBuffer(c.rawId),
      type: 'public-key',
      response,
      authenticatorAttachment: c.authenticatorAttachment || 'cross-platform',
    });
    defineMethods(cred, {
      getClientExtensionResults() { return extensionResults; },
      toJSON() { return JSON.parse(JSON.stringify(json)); },
    });
    return cred;
  }

  // ------------------------------------------------------------ messaging

  const pending = new Map();
  let counter = 0;

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.type !== RES) return;
    const settle = pending.get(data.requestId);
    if (!settle) return;
    pending.delete(data.requestId);
    settle(data);
  });

  function requestViaPhone(cmd, options, thisArg) {
    const publicKey = toJsonOptions(options.publicKey);
    const signal = options.signal;
    const requestId = `${Date.now().toString(36)}-${(++counter).toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

    return new Promise((resolve, reject) => {
      if (signal && signal.aborted) {
        reject(signal.reason || domException('The operation was aborted.', 'AbortError'));
        return;
      }
      const onAbort = () => {
        if (!pending.has(requestId)) return;
        pending.delete(requestId);
        window.postMessage({ type: CANCEL, requestId }, '*');
        reject(signal.reason || domException('The operation was aborted.', 'AbortError'));
      };
      if (signal) signal.addEventListener('abort', onAbort, { once: true });

      pending.set(requestId, (msg) => {
        if (signal) signal.removeEventListener('abort', onAbort);
        if (msg.useNative) {
          // The user picked the browser's built-in flow (e.g. a USB security key).
          try {
            resolve((cmd === 'get' ? nativeGet : nativeCreate).call(thisArg, options));
          } catch (e) {
            reject(e);
          }
          return;
        }
        if (msg.error) {
          reject(domException(
            msg.error.message || 'The operation either timed out or was not allowed.',
            msg.error.name || 'NotAllowedError'
          ));
          return;
        }
        try {
          resolve(buildCredential(cmd, msg.credential));
        } catch (e) {
          reject(domException(`Phone Passkeys could not build the credential: ${e && e.message}`, 'UnknownError'));
        }
      });

      window.postMessage({ type: REQ, requestId, cmd, publicKey }, '*');
    });
  }

  // -------------------------------------------------------------- overrides

  function shouldIntercept(options) {
    return !!(options && typeof options === 'object' && options.publicKey && options.mediation !== 'conditional');
  }

  Object.defineProperty(proto, 'get', {
    configurable: true, enumerable: true, writable: true,
    value: function get(options) {
      if (!shouldIntercept(options)) return nativeGet.apply(this, arguments);
      return requestViaPhone('get', options, this);
    },
  });

  Object.defineProperty(proto, 'create', {
    configurable: true, enumerable: true, writable: true,
    value: function create(options) {
      if (!shouldIntercept(options)) return nativeCreate.apply(this, arguments);
      return requestViaPhone('create', options, this);
    },
  });

  if (CLAIM_PLATFORM_AUTHENTICATOR) {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function () {
      return Promise.resolve(true);
    };
  }

  PublicKeyCredential.getClientCapabilities = async function () {
    let caps = {};
    try {
      if (typeof nativeGetClientCapabilities === 'function') {
        caps = await nativeGetClientCapabilities.call(PublicKeyCredential);
      }
    } catch (e) { /* ignore */ }
    const extra = { hybridTransport: true, relatedOrigins: true };
    if (CLAIM_PLATFORM_AUTHENTICATOR) {
      extra.passkeyPlatformAuthenticator = true;
      extra.userVerifyingPlatformAuthenticator = true;
    }
    return Object.assign({}, caps, extra);
  };
})();
