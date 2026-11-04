// Phone Passkeys - dialog window script. Pure view: the background script owns
// all state and closes this window when the request is over.
'use strict';

const STATUS = {
  starting: 'Preparing a QR code…',
  waiting: 'Waiting for you to scan the code…',
  connecting: 'Phone found. Connecting…',
  connected: 'Connected. Follow the prompts on your phone.',
  restarting: 'The connection failed. Showing a new code…',
  error: 'Something went wrong.',
};

const $ = (id) => document.getElementById(id);
let lastSvg = null;

const port = browser.runtime.connect({ name: 'phone-passkeys-dialog' });
port.onMessage.addListener((msg) => {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'close') { window.close(); return; }
  if (msg.type === 'update') render(msg);
});
port.onDisconnect.addListener(() => window.close());

function render(s) {
  for (const el of document.querySelectorAll('.rp')) el.textContent = s.rpId || '';
  const creating = s.cmd === 'create';
  $('heading').textContent = creating ? 'Create a passkey' : 'Use a passkey';
  document.title = `${creating ? 'Create a passkey' : 'Sign in'} · ${s.rpId || ''}`;

  if (s.qrSvg && s.qrSvg !== lastSvg) {
    lastSvg = s.qrSvg;
    $('qr-img').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s.qrSvg);
    $('qr-img').hidden = false;
    $('qr-badge').hidden = false;
    $('qr-placeholder').hidden = true;
  }

  $('qr').classList.toggle('scanned', s.state === 'connecting' || s.state === 'connected');

  const status = $('status');
  let text = STATUS[s.state] || s.state || '';
  if (s.state === 'error' && s.detail) text = s.detail;
  status.textContent = text;
  status.classList.toggle('error', s.state === 'error');

  if (s.state === 'error') {
    $('cancel').textContent = 'Close';
    $('use-key').disabled = true;
  }
}

$('cancel').addEventListener('click', () => port.postMessage({ type: 'cancel' }));
$('use-key').addEventListener('click', () => port.postMessage({ type: 'useSecurityKey' }));
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') port.postMessage({ type: 'cancel' });
});
