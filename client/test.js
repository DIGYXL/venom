const { ipcRenderer } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TEST_DIR = path.join(os.homedir(), 'Venom', 'Test');
const COMMANDS_FILE = path.join(TEST_DIR, 'commands.json');

const DEFAULT_COMMANDS = [
  { cmd: 'sleep 0 0', selected: true },
  { cmd: 'sleep 1 10', selected: true },
  { cmd: 'shell whoami', selected: true },
  { cmd: 'shell hostname', selected: true },
  { cmd: 'cat test.txt', selected: true },
  { cmd: 'write test.txt Hello Venom', selected: true },
  { cmd: 'cat test.txt', selected: true },
  { cmd: 'mkdir test_dir', selected: true },
  { cmd: 'cd test_dir', selected: true },
  { cmd: 'pwd', selected: true },
  { cmd: 'mv ../test.txt test.txt', selected: true },
  { cmd: 'ls', selected: true },
  { cmd: 'cat test.txt', selected: true },
  { cmd: 'mv test.txt ../test2.txt', selected: true },
  { cmd: 'cd ../', selected: true },
  { cmd: 'rmdir test_dir', selected: true },
  { cmd: 'chmod 400 test2.txt', selected: true },
  { cmd: 'ls', selected: true },
  { cmd: 'download test2.txt', selected: true },
  { cmd: 'upload ~/Venom/downloads/test2.txt test3.txt', selected: true },
  { cmd: 'ls', selected: true },
  { cmd: 'cp test3.txt test4.txt', selected: true },
  { cmd: 'ls', selected: true },
  { cmd: 'rm test4.txt', selected: true },
  { cmd: 'rm test3.txt', selected: true },
  { cmd: 'rm test2.txt', selected: true },
  { cmd: 'ls', selected: true }
];

function ensureTestDir() { try { if (!fs.existsSync(TEST_DIR)) fs.mkdirSync(TEST_DIR, { recursive: true }); } catch (_) {} }
function loadCommands() { try { ensureTestDir(); if (fs.existsSync(COMMANDS_FILE)) { const d = JSON.parse(fs.readFileSync(COMMANDS_FILE, 'utf-8')); if (Array.isArray(d)) return d; } } catch (e) {} return DEFAULT_COMMANDS.slice(); }
function saveCommands(list) { try { ensureTestDir(); fs.writeFileSync(COMMANDS_FILE, JSON.stringify(list, null, 2)); } catch (_) {} }

function appendOutput(text) { const box = document.getElementById('outputBox'); box.value += (box.value ? '\n' : '') + text; box.scrollTop = box.scrollHeight; }

function getDownloadsDir(){ const dir = path.join(os.homedir(),'Venom','downloads'); try{ if(!fs.existsSync(dir)) fs.mkdirSync(dir,{recursive:true}); } catch(_){} return dir; }
function expandTilde(p){ if(!p) return p; if(p.startsWith('~/')) return path.join(os.homedir(), p.slice(2)); return p; }

async function populateAgents() {
  try {
    const agents = await ipcRenderer.invoke('list-agents');
    const sel = document.getElementById('agentSelect');
    sel.innerHTML = '';
    if (agents && agents.agents && Array.isArray(agents.agents)) {
      agents.agents.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.agent_id;
        opt.textContent = `${a.agent_id} | ${a.system_info?.username || ''}@${a.system_info?.hostname || ''}`;
        sel.appendChild(opt);
      });
    }
  } catch (e) { appendOutput(`[!] Failed to load agents: ${e.message}`); }
}

function makeRow(idx, item) {
  const tr = document.createElement('tr');
  const tdIndex = document.createElement('td'); tdIndex.textContent = (idx + 1).toString();
  const tdDrag = document.createElement('td'); tdDrag.innerHTML = '<span class="drag">↕</span>';
  const tdCmd = document.createElement('td'); const input = document.createElement('input'); input.className='command'; input.value=item.cmd; input.addEventListener('change',()=>{item.cmd=input.value; persist();}); tdCmd.appendChild(input);
  const tdSel = document.createElement('td'); const cb=document.createElement('input'); cb.type='checkbox'; cb.checked=!!item.selected; cb.addEventListener('change',()=>{item.selected=cb.checked; persist();}); tdSel.appendChild(cb);
  const tdAct = document.createElement('td');
  const runBtn=document.createElement('button'); runBtn.textContent='Run'; runBtn.addEventListener('click',()=>runOne(item.cmd));
  const delBtn=document.createElement('button'); delBtn.textContent='Delete'; delBtn.style.marginLeft='6px'; delBtn.addEventListener('click',()=>removeAt(idx));
  tdAct.appendChild(runBtn); tdAct.appendChild(delBtn);
  tr.appendChild(tdIndex); tr.appendChild(tdDrag); tr.appendChild(tdCmd); tr.appendChild(tdSel); tr.appendChild(tdAct);
  tr.draggable=true;
  tr.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/plain',idx.toString());});
  tr.addEventListener('dragover',e=>e.preventDefault());
  tr.addEventListener('drop',e=>{e.preventDefault(); const from=parseInt(e.dataTransfer.getData('text/plain'),10); const to=idx; reorder(from,to);});
  return tr;
}

let commands = loadCommands();

function render() { const tbody=document.getElementById('cmdTbody'); tbody.innerHTML=''; commands.forEach((it,idx)=>tbody.appendChild(makeRow(idx,it))); }
function persist(){ saveCommands(commands); }
function addRow(){ commands.push({cmd:'',selected:false}); persist(); render(); }
function removeAt(idx){ commands.splice(idx,1); persist(); render(); }
function reorder(from,to){ if(from===to)return; const it=commands.splice(from,1)[0]; commands.splice(to,0,it); persist(); render(); }
function selectAll(){ commands = commands.map(c => ({ ...c, selected: true })); persist(); render(); }
function deselectAll(){ commands = commands.map(c => ({ ...c, selected: false })); persist(); render(); }

async function prepareRequest({ hostname='localhost', port=5000, path='/', method='GET', headers={} }, data=null){
  try{
    const body = data ? JSON.stringify(data) : null;
    if (!headers['Content-Type']) headers['Content-Type']='application/json';
    if (!headers['Accept']) headers['Accept']='application/json';
    const res = await ipcRenderer.invoke('prepare-request', { hostname, port, path, method, headers, body });
    if (res && res.error) throw new Error(res.error);
    if (typeof res === 'string') { try { return JSON.parse(res); } catch { return null; } }
    return res || null;
  } catch(e){ appendOutput(`[!] request error: ${e.message}`); return null; }
}

function splitArgsRespectQuotes(str){
  const out=[]; let cur=''; let inQ=false; let q='';
  for(let i=0;i<str.length;i++){
    const c=str[i];
    if(inQ){ if(c==='\\' && (str[i+1]===q || str[i+1]==='\\')){ cur+=str[i+1]; i++; } else if(c===q){ inQ=false; out.push(cur); cur=''; } else { cur+=c; } }
    else { if(c==='"' || c==="'"){ inQ=true; q=c; } else if(c===' '){ if(cur){ out.push(cur); cur=''; } } else { cur+=c; } }
  }
  if(cur) out.push(cur);
  return out;
}

function buildTaskFromCommand(cmd, agentId){
  const argv = splitArgsRespectQuotes(cmd.trim());
  if (argv.length===0) return null;
  const type = argv[0].toLowerCase();
  const mk = (data)=>({ path:'/api/client/task', method:'POST', data });
  switch(type){
    case 'pwd': return mk({ type:'pwd', agent_id: agentId });
    case 'ls': return mk({ type:'ls', path: argv[1]||'.', agent_id: agentId });
    case 'cd': if(!argv[1]) return null; return mk({ type:'cd', path: argv[1], agent_id: agentId });
    case 'cat': if(!argv[1]) return null; return mk({ type:'cat', path: argv[1], agent_id: agentId });
    case 'mv': if(argv.length<3) return null; return mk({ type:'mv', src: argv[1], dst: argv[2], agent_id: agentId });
    case 'cp': if(argv.length<3) return null; return mk({ type:'cp', src: argv[1], dst: argv[2], agent_id: agentId });
    case 'mkdir': if(!argv[1]) return null; return mk({ type:'mkdir', path: argv[1], agent_id: agentId });
    case 'rmdir': if(!argv[1]) return null; return mk({ type:'rmdir', path: argv[1], agent_id: agentId });
    case 'write': if(!argv[1]) return null; return mk({ type:'write', path: argv[1], content: argv.slice(2).join(' ') || '', agent_id: agentId });
    case 'chmod': if(argv.length<3) return null; return mk({ type:'chmod', mode: argv[1], path: argv[2], agent_id: agentId });
    case 'rm': if(!argv[1]) return null; return mk({ type:'rm', path: argv[1], agent_id: agentId });
    case 'sleep': { const secs=parseInt(argv[1]||'0',10); const jitter=argv[2]?parseInt(argv[2],10):undefined; const data={ type:'sleep', sleep_time: secs, agent_id: agentId }; if(Number.isFinite(jitter)) data.jitter_percent=jitter; return mk(data); }
    case 'sshrev': if(argv.length<5) return null; return mk({ type:'sshrev', key_path: argv[1], port: argv[2], user: argv[3], domain: argv[4], agent_id: agentId });
    case 'kill': return mk({ type:'kill', agent_id: agentId });
    case 'download': if(!argv[1]) return null; return mk({ type:'download', remote_path: argv[1], agent_id: agentId });
    case 'upload': {
      if (argv.length < 3) return null;
      const localPath = expandTilde(argv[1]);
      const remotePath = argv[2];
      if (!fs.existsSync(localPath)) { appendOutput(`[!] Local file not found: ${localPath}`); return null; }
      const stat = fs.statSync(localPath);
      if (!stat.isFile()) { appendOutput(`[!] Not a file: ${localPath}`); return null; }
      const maxSize = 100*1024*1024; if (stat.size > maxSize) { appendOutput(`[!] File too large: ${stat.size}`); return null; }
      const fileBytes = fs.readFileSync(localPath);
      const fileB64 = Buffer.from(fileBytes).toString('base64');
      return mk({ type:'upload', local_path: localPath, remote_path: remotePath, file_data: fileB64, agent_id: agentId });
    }
    case 'shell': default: return mk({ type:'shell', command: argv.slice(type==='shell'?1:0).join(' '), agent_id: agentId });
  }
}

async function monitorTask(taskId){
  return new Promise((resolve)=>{
    const tick = async ()=>{
      const res = await prepareRequest({ path:`/api/client/task/${taskId}`, method:'GET' });
      if(!res || !res.success){ setTimeout(tick, 500); return; }
      const t = res.task || {}; const st = t.status;
      if(st==='completed' || st==='failed') return resolve(res);
      setTimeout(tick, 500);
    };
    tick();
  });
}

async function runOne(cmd){
  try {
    const agentId = document.getElementById('agentSelect').value || '';
    if (!agentId) { appendOutput('[!] Select an agent first'); return; }
    appendOutput(`> ${cmd}`);
    const req = buildTaskFromCommand(cmd, agentId);
    if (!req) { appendOutput('[!] Invalid command'); return; }
    const created = await prepareRequest({ path: req.path, method: req.method }, req.data);
    if (!created || !created.success) { appendOutput('[!] Failed to create task'); return; }
    const taskId = created.task_id;
    const result = await monitorTask(taskId);
    if (!result || !result.success) { appendOutput('[!] Task failed or no result'); return; }
    const t = result.task || {}; const r = (t.result && t.result.result) || {};
    if (t.type === 'download') {
      const downloadsDir = getDownloadsDir();
      if (r.file_data) {
        let filename = r.filename || (r.file_path ? path.basename(r.file_path) : `download_${taskId}`);
        let localPath = path.join(downloadsDir, filename);
        if (fs.existsSync(localPath)) {
          const ts = new Date().toISOString().replace(/[:.]/g,'-');
          const parsed = path.parse(filename);
          filename = `${ts}_${parsed.name}${parsed.ext}`;
          localPath = path.join(downloadsDir, filename);
        }
        fs.writeFileSync(localPath, Buffer.from(r.file_data,'base64'));
        appendOutput(`Downloaded: ${localPath}`);
      } else {
        appendOutput('[!] No file data received');
      }
      return;
    }
    if (r.stdout) appendOutput(r.stdout.trim());
    if (r.stderr) appendOutput(r.stderr.trim());
  } catch (e) { appendOutput(`[!] ${e.message}`); }
}

async function runSelected(){ for(const it of commands){ if(it.selected && it.cmd.trim()) await runOne(it.cmd.trim()); } }
async function runAll(){ for(const it of commands){ if(it.cmd.trim()) await runOne(it.cmd.trim()); } }
function resetDefaults(){ commands=DEFAULT_COMMANDS.slice(); persist(); render(); }

window.addEventListener('DOMContentLoaded',()=>{
  render();
  populateAgents();
  document.getElementById('refreshAgentsBtn').addEventListener('click', populateAgents);
  document.getElementById('addRowBtn').addEventListener('click', addRow);
  document.getElementById('runSelectedBtn').addEventListener('click', runSelected);
  document.getElementById('runAllBtn').addEventListener('click', runAll);
  document.getElementById('resetBtn').addEventListener('click', resetDefaults);
  document.getElementById('selectAllBtn').addEventListener('click', selectAll);
  document.getElementById('deselectAllBtn').addEventListener('click', deselectAll);

  // Draggable divider logic
  const divider = document.getElementById('divider');
  const top = document.getElementById('topPanel');
  const bottom = document.getElementById('bottomPanel');
  const container = document.getElementById('splitContainer');
  let dragging = false; let startY = 0; let startTopHeight = 0; let startBottomHeight = 0;
  const minTop = 160; const minBottom = 140;
  function containerInnerHeight(){
    const rect = container.getBoundingClientRect();
    const styles = getComputedStyle(container);
    const vertPad = parseFloat(styles.paddingTop) + parseFloat(styles.paddingBottom);
    return rect.height - vertPad;
  }
  divider.addEventListener('mousedown', (e)=>{ 
    dragging = true; 
    startY = e.clientY; 
    startTopHeight = top.getBoundingClientRect().height; 
    startBottomHeight = bottom.getBoundingClientRect().height; 
    document.body.style.userSelect='none'; 
  });
  window.addEventListener('mousemove', (e)=>{
    if(!dragging) return;
    const dy = e.clientY - startY;
    let newTop = Math.max(minTop, startTopHeight + dy);
    const total = containerInnerHeight() - divider.getBoundingClientRect().height;
    let newBottom = total - newTop;
    if(newBottom < minBottom){
      newBottom = minBottom;
      newTop = total - newBottom;
    }
    top.style.flex = '0 0 auto';
    bottom.style.flex = '0 0 auto';
    top.style.height = `${newTop}px`;
    bottom.style.height = `${newBottom}px`;
  });
  window.addEventListener('mouseup', ()=>{ dragging=false; document.body.style.userSelect='auto'; });
});