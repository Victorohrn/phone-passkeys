// Phone Passkeys - background script.
//
// Owns the lifecycle of one WebAuthn request at a time:
//   content bridge  --(runtime port)-->  background  --(native messaging)-->  host
//                                           |
//                                           +--(runtime port)--> dialog window (QR code UI)
//
// The origin used for the ceremony is taken from the port sender (the browser's
// own view of the frame), never from page-supplied data, so a page can only
// obtain credentials for its own origin.
'use strict';

const HOST_NAME = 'phone_passkeys_host';
const REQUEST_PORT = 'phone-passkeys-request';
const DIALOG_PORT = 'phone-passkeys-dialog';
const DIALOG_WIDTH = 460;
const DIALOG_HEIGHT = 720;
const ERROR_LINGER_MS = 7000;
const NATIVE_DISCONNECT_GRACE_MS = 1500;
const SETUP_URL = browser.runtime.getURL('setup.html');
const SETUP_THROTTLE_MS = 60 * 1000;

let active = null;   // request currently being served
let current = null;  // most recent request (kept so the dialog can show a final error)
let setupShownAt = 0;

function log(...args) {
  console.log('[phone-passkeys]', ...args);
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch (e) {
    return null;
  }
}

function errorReply(name, message) {
  return { error: { name, message } };
}

browser.runtime.onConnect.addListener((port) => {
  if (port.name === REQUEST_PORT) onRequestPort(port);
  else if (port.name === DIALOG_PORT) onDialogPort(port);
});

// --------------------------------------------------------- setup & status

browser.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') openSetup(true);
});

// Spawns the host once to see whether it is installed and Bluetooth works.
async function pingHost() {
  try {
    const reply = await browser.runtime.sendNativeMessage(HOST_NAME, { type: 'ping' });
    return {
      installed: true,
      version: reply && reply.version ? String(reply.version) : null,
      bluetooth: !!(reply && reply.bluetooth),
    };
  } catch (e) {
    return { installed: false, error: e && e.message ? e.message : String(e) };
  }
}

async function openSetup(force) {
  const now = Date.now();
  if (!force && now - setupShownAt < SETUP_THROTTLE_MS) return;
  setupShownAt = now;
  try {
    await browser.tabs.create({ url: SETUP_URL });
  } catch (e) {
    log('could not open the setup page', e);
  }
}

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || typeof msg !== 'object') return undefined;
  if (msg.type === 'hostStatus') return pingHost();
  if (msg.type === 'openSetup') return openSetup(true).then(() => true);
  return undefined;
});

// ------------------------------------------------------------ page requests

function onRequestPort(port) {
  port.onMessage.addListener((msg) => {
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'start') {
      startRequest(port, msg);
    } else if (msg.type === 'cancel' && active && active.requestPort === port) {
      finish(active, errorReply('AbortError', 'The operation was aborted.'));
    }
  });
  port.onDisconnect.addListener(() => {
    if (active && active.requestPort === port) finish(active, null);
  });
}

async function startRequest(port, msg) {
  const sender = port.sender || {};
  const origin = originOf(sender.url);
  if (!origin || !(origin.startsWith('https://') || /^http:\/\/localhost(:\d+)?$/.test(origin))) {
    port.postMessage(errorReply('SecurityError', 'Phone Passkeys only works on https pages (or http://localhost).'));
    return;
  }
  const topOrigin = sender.tab && sender.tab.url ? originOf(sender.tab.url) : origin;
  const crossOrigin = (sender.frameId || 0) > 0 && !!topOrigin && topOrigin !== origin;

  if (active) {
    port.postMessage(errorReply('NotAllowedError', 'Another passkey request is already in progress.'));
    return;
  }

  const publicKey = msg.publicKey && typeof msg.publicKey === 'object' ? msg.publicKey : {};
  const rpId = publicKey.rpId || (publicKey.rp && publicKey.rp.id) || new URL(origin).hostname;

  const req = {
    id: String(msg.requestId),
    cmd: msg.cmd === 'create' ? 'create' : 'get',
    origin,
    topOrigin: crossOrigin ? topOrigin : null,
    rpId,
    requestPort: port,
    tabWindowId: sender.tab ? sender.tab.windowId : null,
    nativePort: null,
    dialogWindowId: null,
    dialogPort: null,
    state: 'starting',
    detail: null,
    qrSvg: null,
    done: false,
    lingering: false,
    hostResponded: false,
  };
  active = req;
  current = req;
  log(`start ${req.cmd} for ${rpId} (${origin}${crossOrigin ? ' in ' + topOrigin : ''})`);

  let native;
  try {
    native = browser.runtime.connectNative(HOST_NAME);
  } catch (e) {
    finish(req, errorReply('NotAllowedError', `Phone Passkeys native host could not be started: ${e.message}`), {
      linger: true,
      detail: `The native host could not be started (${e.message}). Run install.sh and restart the browser.`,
    });
    return;
  }
  req.nativePort = native;
  native.onMessage.addListener((m) => onNativeMessage(req, m));
  native.onDisconnect.addListener((p) => {
    if (req.done) return;
    const err = p.error || browser.runtime.lastError;
    const message = err && err.message ? err.message : 'the native host exited unexpectedly';
    if (!req.hostResponded) {
      // The host is not installed or cannot start. Hand the request back to the
      // browser so built-in authenticators keep working, and show the setup page.
      log(`native host unavailable (${message}); falling back to the browser`);
      finish(req, { useNative: true });
      openSetup(false);
      return;
    }
    finish(req, errorReply('NotAllowedError', `Phone Passkeys: ${message}`), {
      linger: true,
      detail: `Native host error: ${message}. Run install.sh to (re)install the host, then restart the browser.`,
    });
  });
  native.postMessage({
    type: 'start',
    id: req.id,
    cmd: req.cmd,
    origin,
    topOrigin: req.topOrigin || undefined,
    options: publicKey,
  });

  try {
    const win = await browser.windows.create({
      url: browser.runtime.getURL('dialog.html'),
      type: 'popup',
      width: DIALOG_WIDTH,
      height: DIALOG_HEIGHT,
    });
    req.dialogWindowId = win.id;
    if (req.done && !req.lingering) closeDialog(req);
  } catch (e) {
    log('could not open the dialog window', e);
  }
}

function onNativeMessage(req, m) {
  if (!m || typeof m !== 'object' || req.done) return;
  req.hostResponded = true;
  switch (m.type) {
    case 'qr':
      req.qrSvg = m.svg;
      setDialogState(req, 'waiting', null);
      break;
    case 'state':
      setDialogState(req, m.state, m.detail || null);
      break;
    case 'result':
      finish(req, { credential: m.credential }, { completed: true });
      break;
    case 'error':
      finish(req, errorReply(m.name || 'NotAllowedError', m.message || 'The operation failed.'), {
        linger: m.name !== 'AbortError',
        detail: m.message,
      });
      break;
    case 'log':
      log('host:', m.message);
      break;
    default:
      break;
  }
}

function finish(req, reply, opts = {}) {
  if (req.done) return;
  req.done = true;
  if (active === req) active = null;

  if (reply) {
    try { req.requestPort.postMessage(reply); } catch (e) { /* page went away */ }
  }

  const native = req.nativePort;
  if (native) {
    if (!opts.completed) {
      try { native.postMessage({ type: 'cancel', id: req.id }); } catch (e) { /* already gone */ }
    }
    // Give the host a moment to tell the phone the session ended cleanly.
    setTimeout(() => { try { native.disconnect(); } catch (e) { /* ignore */ } }, NATIVE_DISCONNECT_GRACE_MS);
  }

  if (opts.linger) {
    req.lingering = true;
    setDialogState(req, 'error', opts.detail || (reply && reply.error && reply.error.message) || 'Something went wrong.');
    setTimeout(() => closeDialog(req), ERROR_LINGER_MS);
  } else {
    closeDialog(req);
  }

  if (req.tabWindowId != null) {
    browser.windows.update(req.tabWindowId, { focused: true }).catch(() => {});
  }
}

// ------------------------------------------------------------------ dialog

function snapshot(req) {
  return {
    type: 'update',
    cmd: req.cmd,
    rpId: req.rpId,
    origin: req.origin,
    state: req.state,
    detail: req.detail,
    qrSvg: req.qrSvg,
  };
}

function setDialogState(req, state, detail) {
  req.state = state;
  req.detail = detail;
  if (req.dialogPort) {
    try { req.dialogPort.postMessage(snapshot(req)); } catch (e) { /* dialog closed */ }
  }
}

function closeDialog(req) {
  const id = req.dialogWindowId;
  req.dialogWindowId = null;
  if (id != null) browser.windows.remove(id).catch(() => {});
}

function onDialogPort(port) {
  const req = current;
  if (!req) {
    try { port.postMessage({ type: 'close' }); } catch (e) { /* ignore */ }
    return;
  }
  req.dialogPort = port;
  port.postMessage(snapshot(req));

  port.onMessage.addListener((msg) => {
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'cancel') {
      if (!req.done) finish(req, errorReply('NotAllowedError', 'The operation either timed out or was not allowed.'));
      else closeDialog(req);
    } else if (msg.type === 'useSecurityKey') {
      if (!req.done) finish(req, { useNative: true });
    } else if (msg.type === 'close') {
      closeDialog(req);
    }
  });

  port.onDisconnect.addListener(() => {
    if (req.dialogPort === port) req.dialogPort = null;
    req.dialogWindowId = null;
    if (!req.done) finish(req, errorReply('NotAllowedError', 'The operation either timed out or was not allowed.'));
  });
}
