const { ipcRenderer } = require('electron');
const fs = require('fs');
const path = require('path');
const os = require('os');

function humanSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024; const sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k,i)).toFixed(2)} ${sizes[i]}`;
}

async function prepareRequest(opts, data = null) {
  try {
    const { hostname = 'localhost', port = 5000, path: reqPath = '/', method = 'GET', headers = {} } = opts || {};
    if (!headers['Accept']) headers['Accept'] = 'application/json';
    // Inject Basic Auth from main config (via IPC)
    try {
      const cfg = await ipcRenderer.invoke('get-config');
      const user = (cfg && cfg.username) ? cfg.username : 'admin';
      const pass = (cfg && cfg.password) ? cfg.password : 'gnuDh8VYUYBnHx2Zv3k';
      headers['Authorization'] = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
    } catch (_) {}
    if (data && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const body = data ? JSON.stringify(data) : null;
    const res = await ipcRenderer.invoke('prepare-request', { hostname, port, path: reqPath, method, headers, body });
    if (typeof res === 'string') { try { return JSON.parse(res); } catch { return null; } }
    return res || null;
  } catch (e) {
    console.log(`[history] prepareRequest error: ${e.message}`);
    return null;
  }
}

function setStatus(msg) {
  const el = document.getElementById('status');
  if (el) el.textContent = msg || '';
}

async function loadHosts() {
  setStatus('Loading...');
  const res = await prepareRequest({ path: '/api/client/history/hosts', method: 'GET' });
  const tbody = document.getElementById('hostsTbody');
  const select = document.getElementById('hostSelect');
  const sizeLabel = document.getElementById('sizeLabel');
  tbody.innerHTML = '';
  select.innerHTML = '';
  sizeLabel.textContent = '';
  if (!res || !res.success || !Array.isArray(res.hosts)) { setStatus('Failed to load hosts'); return; }
  res.hosts.sort((a,b)=>a.hostname.localeCompare(b.hostname));
  res.hosts.forEach((h, idx) => {
    // table
    const tr = document.createElement('tr');
    const tdHost = document.createElement('td'); tdHost.textContent = h.hostname; tr.appendChild(tdHost);
    const tdSize = document.createElement('td'); tdSize.textContent = humanSize(h.size || 0); tr.appendChild(tdSize);
    tr.addEventListener('click', ()=> { select.value = h.host_id; sizeLabel.textContent = humanSize(h.size || 0); });
    tbody.appendChild(tr);
    // select
    const opt = document.createElement('option'); opt.value = h.host_id; opt.textContent = h.hostname; select.appendChild(opt);
    if (idx === 0) sizeLabel.textContent = humanSize(h.size || 0);
  });
  setStatus('');
}

async function downloadSelected() {
  const select = document.getElementById('hostSelect');
  const hostId = select.value;
  if (!hostId) { setStatus('Select a host'); return; }
  setStatus('Downloading...');
  const res = await prepareRequest({ path: `/api/client/history/download/${encodeURIComponent(hostId)}`, method: 'GET' });
  if (!res || !res.success || !res.data_b64) { setStatus('Download failed'); return; }
  try {
    const buf = Buffer.from(res.data_b64, 'base64');
    const saveDir = path.join(os.homedir(), 'Venom', 'history');
    if (!fs.existsSync(saveDir)) fs.mkdirSync(saveDir, { recursive: true });
    const filename = `${res.hostname || 'host'}.hist`;
    const filePath = path.join(saveDir, filename);
    fs.writeFileSync(filePath, buf);
    setStatus(`Saved to ${filePath}`);
  } catch (e) {
    setStatus(`Save failed: ${e.message}`);
  }
}

window.addEventListener('DOMContentLoaded', ()=>{
  document.getElementById('refreshBtn').addEventListener('click', loadHosts);
  document.getElementById('downloadBtn').addEventListener('click', downloadSelected);
  document.getElementById('hostSelect').addEventListener('change', (e)=>{
    const row = [...document.querySelectorAll('#hostsTbody tr')].find(tr=>tr.firstChild && tr.firstChild.textContent===e.target.value);
    if (row) {
      const size = row.children[1].textContent;
      document.getElementById('sizeLabel').textContent = size;
    }
  });
  loadHosts();
});

