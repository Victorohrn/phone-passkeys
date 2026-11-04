'use strict';
const status = document.getElementById('status');
browser.runtime.sendNativeMessage('phone_passkeys_host', { type: 'ping' }).then((reply) => {
  const bt = reply && reply.bluetooth;
  status.innerHTML = '';
  const line = document.createElement('span');
  line.className = bt ? 'ok' : 'bad';
  line.textContent = `Native host v${reply && reply.version ? reply.version : '?'} is installed. Bluetooth: ${bt ? 'available' : 'not available (needed to confirm the phone is nearby)'}.`;
  status.appendChild(line);
}).catch((err) => {
  status.innerHTML = '';
  const line = document.createElement('span');
  line.className = 'bad';
  line.textContent = `Native host not reachable (${err && err.message}). Run install.sh from the project folder and restart the browser.`;
  status.appendChild(line);
});

document.getElementById('setup').addEventListener('click', (e) => {
  e.preventDefault();
  browser.runtime.sendMessage({ type: 'openSetup' }).finally(() => window.close());
});
