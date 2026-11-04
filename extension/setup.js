'use strict';
const status = document.getElementById('status');

async function check() {
  status.className = '';
  status.textContent = 'Checking…';
  let result;
  try {
    result = await browser.runtime.sendMessage({ type: 'hostStatus' });
  } catch (e) {
    result = { installed: false, error: e && e.message };
  }
  if (result && result.installed) {
    status.className = 'ok';
    status.textContent = result.bluetooth
      ? `Installed (version ${result.version || '?'}) and Bluetooth is available. You are ready to go.`
      : `Installed (version ${result.version || '?'}), but no Bluetooth adapter was found. Turn Bluetooth on and check again.`;
  } else {
    status.className = 'bad';
    status.textContent = `Not found (${result && result.error ? result.error : 'no reply'}). Follow the steps below, then check again.`;
  }
}

document.getElementById('recheck').addEventListener('click', check);
check();
