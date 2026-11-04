// Phone Passkeys - isolated-world bridge.
//
// Relays WebAuthn requests posted by page.js (page world) to the background
// script over a runtime port, and relays the outcome back to the page.
(() => {
  'use strict';

  const REQ = 'phone-passkeys:request';
  const RES = 'phone-passkeys:response';
  const CANCEL = 'phone-passkeys:cancel';
  const PORT_NAME = 'phone-passkeys-request';

  const ports = new Map();

  function respond(requestId, payload) {
    window.postMessage(Object.assign({ type: RES, requestId }, payload), '*');
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || typeof data !== 'object') return;

    if (data.type === REQ) {
      const requestId = String(data.requestId);
      let port;
      try {
        port = browser.runtime.connect({ name: PORT_NAME });
      } catch (e) {
        respond(requestId, { error: { name: 'NotAllowedError', message: `Phone Passkeys is unavailable: ${e && e.message}` } });
        return;
      }
      ports.set(requestId, port);
      port.onMessage.addListener((msg) => {
        if (!ports.has(requestId)) return;
        ports.delete(requestId);
        respond(requestId, msg);
        try { port.disconnect(); } catch (e) { /* ignore */ }
      });
      port.onDisconnect.addListener(() => {
        if (!ports.has(requestId)) return;
        ports.delete(requestId);
        respond(requestId, { error: { name: 'NotAllowedError', message: 'Phone Passkeys: the extension disconnected before the request finished.' } });
      });
      port.postMessage({ type: 'start', requestId, cmd: data.cmd === 'create' ? 'create' : 'get', publicKey: data.publicKey });
    } else if (data.type === CANCEL) {
      const port = ports.get(String(data.requestId));
      if (port) {
        try { port.postMessage({ type: 'cancel' }); } catch (e) { /* ignore */ }
      }
    }
  });
})();
