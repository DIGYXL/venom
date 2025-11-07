const { app, BrowserWindow, ipcMain, Menu, clipboard, shell, screen, dialog, MenuItem, nativeTheme } = require('electron');
const fs   = require('fs');  
const path = require('path');
const os = require('os');
const teamserver   = require('./teamserver');
global.agentWindow = [];
global.agentWindowsById = {};
global.appConfig = { server: 'localhost', port: 5000, username: 'admin', password: 'gnuDh8VYUYBnHx2Zv3k' };

function ensureVenomFolders() {
    try {
        const venomDir = path.join(os.homedir(), 'Venom');
        const downloadsDir = path.join(venomDir, 'downloads');
        const testDir = path.join(venomDir, 'Test');
        const historyDir = path.join(venomDir, 'history');
        if (!fs.existsSync(venomDir)) {
            fs.mkdirSync(venomDir, { recursive: true });
        }
        if (!fs.existsSync(downloadsDir)) {
            fs.mkdirSync(downloadsDir, { recursive: true });
        }
        if (!fs.existsSync(testDir)) {
            fs.mkdirSync(testDir, { recursive: true });
        }
        if (!fs.existsSync(historyDir)) {
            fs.mkdirSync(historyDir, { recursive: true });
        }
    } catch (err) {
        console.log(`[!] Failed to ensure Venom folders: ${err.message}`);
    }
}

function getConfigFilePath() {
    return path.join(os.homedir(), 'Venom', 'config.js');
}

function ensureConfigFile() {
    try {
        const cfgPath = getConfigFilePath();
        if (!fs.existsSync(cfgPath)) {
            const defaultCfg = { server: 'localhost', port: 5000, username: 'admin', password: 'gnuDh8VYUYBnHx2Zv3k' };
            fs.writeFileSync(cfgPath, JSON.stringify(defaultCfg, null, 2));
        }
    } catch (err) {
        console.log(`[!] ensureConfigFile error: ${err.message}`);
    }
}

function loadConfig() {
    try {
        ensureConfigFile();
        const raw = fs.readFileSync(getConfigFilePath(), 'utf-8');
        const parsed = JSON.parse(raw);
        const server = (parsed && parsed.server) ? String(parsed.server) : 'localhost';
        const port = (parsed && parsed.port) ? Number(parsed.port) : 5000;
        const username = (parsed && parsed.username) ? String(parsed.username) : 'admin';
        const password = (parsed && parsed.password) ? String(parsed.password) : 'gnuDh8VYUYBnHx2Zv3k';
        global.appConfig = { server, port, username, password };
    } catch (err) {
        console.log(`[!] loadConfig error: ${err.message}`);
        global.appConfig = { server: 'localhost', port: 5000, username: 'admin', password: 'gnuDh8VYUYBnHx2Zv3k' };
    }
}

function saveConfig(nextCfg) {
    try {
        const cfg = {
            server: String((nextCfg && nextCfg.server) || 'localhost'),
            port: Number((nextCfg && nextCfg.port) || 5000),
            username: String((nextCfg && nextCfg.username) || 'admin'),
            password: String((nextCfg && nextCfg.password) || 'gnuDh8VYUYBnHx2Zv3k')
        };
        fs.writeFileSync(getConfigFilePath(), JSON.stringify(cfg, null, 2));
        global.appConfig = cfg;
        if (global.dashboardWindow && !global.dashboardWindow.isDestroyed()) {
            global.dashboardWindow.reload();
        }
        return { success: true };
    } catch (err) {
        return { success: false, error: err.message };
    }
}

function createDashboardWindow() {
    // Force dark theme
    nativeTheme.themeSource = 'dark';
    
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;
    
    global.dashboardWindow = new BrowserWindow({
        width: Math.floor(width * 0.76),
        height: Math.floor(height * 0.8),
        center: true,
        darkTheme: true,
        webPreferences: {
          contextIsolation: false,
          enableRemoteModule: true,
          nodeIntegration: true
        },
    });
    
    // Set dashboard-specific menu when window is focused
    global.dashboardWindow.on('focus', () => {
        setDashboardMenu();
    });
    
    global.dashboardWindow.focus();
    global.dashboardWindow.loadFile('dashboard.html');
    
    // Set dashboard menu immediately
    setDashboardMenu();
    
    console.log('Main window created');
}


async function createAgentWindow(agent, pendingCmd = null) {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;
    const thisAgentWindow = new BrowserWindow({
        width: Math.floor(width * 0.6),
        height: Math.floor(height * 0.7),
        center: true,
        darkTheme: true,
        webPreferences: {
            contextIsolation: false,
            enableRemoteModule: true,
            nodeIntegration: true
        },
    });
    console.log(`Agent object: ${JSON.stringify(agent)}`);
    global.agentWindow.push(thisAgentWindow);
    global.agentWindowsById[agent.agent_id] = thisAgentWindow;
    thisAgentWindow.focus();
    thisAgentWindow.loadFile('agent.html').then(() => {
        console.log(`createAgentWindow: Sending IPC agent-data for agent ${agent.agent_id} to new agent window`);
        thisAgentWindow.webContents.send('agent-data', agent);
        if (pendingCmd) {
            setTimeout(() => {
                try {
                    thisAgentWindow.webContents.send('agent-run-command', { cmd: pendingCmd });
                } catch (e) { console.log(`[createAgentWindow] send run error: ${e.message}`); }
            }, 200);
        }
    });
    thisAgentWindow.on('closed', () => {
        try { delete global.agentWindowsById[agent.agent_id]; } catch (_) {}
    });
}

function createTestWindow() {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;
    const testWindow = new BrowserWindow({
        width: Math.floor(width * 0.55),
        height: Math.floor(height * 0.65),
        center: true,
        darkTheme: true,
        webPreferences: {
            contextIsolation: false,
            enableRemoteModule: true,
            nodeIntegration: true
        },
    });
    testWindow.loadFile('test.html');
    testWindow.on('focus', () => setDashboardMenu());
}

function createHistoryWindow() {
    const primaryDisplay = screen.getPrimaryDisplay();
    const { width, height } = primaryDisplay.workAreaSize;
    const histWindow = new BrowserWindow({
        width: Math.floor(width * 0.5),
        height: Math.floor(height * 0.55),
        center: true,
        darkTheme: true,
        webPreferences: {
            contextIsolation: false,
            enableRemoteModule: true,
            nodeIntegration: true
        },
    });
    histWindow.loadFile('history.html');
    histWindow.on('focus', () => setDashboardMenu());
}

function createConfigWindow() {
    const cfgWindow = new BrowserWindow({
        width: 560,
        height: 420,
        minWidth: 520,
        minHeight: 240,
        center: true,
        darkTheme: true,
        resizable: true,
        useContentSize: true,
        webPreferences: {
            contextIsolation: false,
            enableRemoteModule: true,
            nodeIntegration: true
        },
    });
    cfgWindow.loadFile('config.html');
    cfgWindow.on('focus', () => setDashboardMenu());

    // Context menu (Cut/Copy/Paste/Select All)
    cfgWindow.webContents.on('context-menu', () => {
        const menu = Menu.buildFromTemplate([
            { role: 'cut', label: 'Cut' },
            { role: 'copy', label: 'Copy' },
            { role: 'paste', label: 'Paste' },
            { type: 'separator' },
            { role: 'selectAll', label: 'Select All' }
        ]);
        menu.popup({ window: cfgWindow });
    });

    // Keyboard shortcuts for Cut/Copy/Paste/Select All
    cfgWindow.webContents.on('before-input-event', (event, input) => {
        const isAccel = input.control || input.meta;
        if (!isAccel) return;
        const k = (input.key || '').toLowerCase();
        try {
            if (k === 'c') { cfgWindow.webContents.copy(); event.preventDefault(); }
            else if (k === 'v') { cfgWindow.webContents.paste(); event.preventDefault(); }
            else if (k === 'x') { cfgWindow.webContents.cut(); event.preventDefault(); }
            else if (k === 'a') { cfgWindow.webContents.selectAll(); event.preventDefault(); }
        } catch (_) {}
    });
}

function setDashboardMenu() {
    const dashboardMenu = Menu.buildFromTemplate([
        { label: 'Settings', submenu: [{ label: 'Configuration', click: () => { createConfigWindow(); } }] },
        {
            label: 'Downloads',
            submenu: [
                {
                    label: 'Open Downloads Folder',
                    click: () => {
                        try {
                            const downloadsDir = path.join(os.homedir(), 'Venom', 'downloads');
                            ensureVenomFolders();
                            shell.openPath(downloadsDir);
                        } catch (err) {
                            console.log(`[!] Failed to open downloads folder: ${err.message}`);
                        }
                    }
                },
                {
                    label: 'Agent History',
                    click: () => {
                        ensureVenomFolders();
                        createHistoryWindow();
                    }
                }
            ]
        },
        {
            label: 'Developer',
            submenu: [
                {
                    label: 'Toggle Developer Tools',
                    accelerator: 'CmdOrCtrl+Shift+I',
                    click: () => {
                        const focusedWindow = BrowserWindow.getFocusedWindow();
                        if (focusedWindow) {
                            focusedWindow.webContents.toggleDevTools();
                        }
                    }
                },
                {
                    label: 'Command Test',
                    click: () => {
                        ensureVenomFolders();
                        createTestWindow();
                    }
                }
            ]
        }
    ]);
    Menu.setApplicationMenu(dashboardMenu);
}



ipcMain.on('open-agent-window', async (event, agent) => {
    createAgentWindow(agent); 
});

ipcMain.handle('list-agents', async (event, agentid) => {
  let agents = await teamserver.listAgents(global.appConfig.server, global.appConfig.port);
  return agents;
});

ipcMain.handle('prepare-request', async (event, payload) => {
  try {
    const { path: reqPath = '/', method = 'GET', headers = {}, body = null } = payload || {};
    const hostname = (payload && payload.hostname) ? payload.hostname : global.appConfig.server;
    const port = (payload && payload.port) ? payload.port : global.appConfig.port;
    const options = { hostname, port, path: reqPath, method, headers };
    const res = await teamserver.makeRequest(options, body);
    return res;
  } catch (e) {
    return { error: e.message };
  }
});

app.whenReady().then(() => {
    console.log('App is ready');
    ensureVenomFolders();
    ensureConfigFile();
    loadConfig();
    createDashboardWindow();
    
    // Set initial dashboard menu
    setDashboardMenu();

    // Config IPC
    ipcMain.handle('get-config', () => ({ ...global.appConfig }));
    ipcMain.handle('save-config', (event, cfg) => saveConfig(cfg));

    // Auth test helper for config window
    ipcMain.handle('auth-test', async (event, payload) => {
        try {
            const server = (payload && payload.server) ? String(payload.server) : global.appConfig.server;
            const port = (payload && payload.port) ? Number(payload.port) : global.appConfig.port;
            const username = (payload && payload.username) ? String(payload.username) : global.appConfig.username;
            const password = (payload && payload.password) ? String(payload.password) : global.appConfig.password;

            // Ensure dashboard window is ready
            if (!global.dashboardWindow.webContents.isLoading()) {
            } else {
                await new Promise(resolve => {
                    global.dashboardWindow.webContents.once('did-finish-load', resolve);
                });
            }

            const url = `http://${server}:${port}/api/health`;
            const requestId = Date.now().toString();
            const authHeader = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');

            return await new Promise((resolve) => {
                const responseHandler = (evt, response) => {
                    const status = (response && typeof response.status === 'number') ? response.status : 0;
                    if (!status) { resolve({ success: false, error: 'unreachable' }); return; }
                    if (status === 401) { resolve({ success: false, error: 'auth' }); return; }
                    if (status >= 200 && status < 300) { resolve({ success: true }); return; }
                    resolve({ success: false, error: 'server' });
                };
                ipcMain.once(`web-request-status-response-${requestId}`, responseHandler);
                try {
                    global.dashboardWindow.webContents.send('make-web-request-status', {
                        url,
                        method: 'GET',
                        headers: { 'Accept': 'application/json', 'Authorization': authHeader },
                        requestId
                    });
                } catch (err) {
                    ipcMain.removeListener(`web-request-status-response-${requestId}`, responseHandler);
                    resolve({ success: false, error: 'unreachable' });
                }
                setTimeout(() => {
                    ipcMain.removeListener(`web-request-status-response-${requestId}`, responseHandler);
                    resolve({ success: false, error: 'unreachable' });
                }, 15000);
            });
        } catch (e) {
            return { success: false, error: 'server' };
        }
    });

    ipcMain.on('command-test-run', (event, payload) => {
        try {
            const { agentId, cmd } = payload || {};
            const win = global.agentWindowsById[agentId];
            if (win && !win.isDestroyed()) {
                win.webContents.send('agent-run-command', { cmd });
            } else {
                console.log(`[command-test] No agent window for ${agentId}, creating one...`);
                (async () => {
                    try {
                        const agents = await teamserver.listAgents();
                        if (agents && agents.agents) {
                            const agent = agents.agents.find(a => a.agent_id === agentId);
                            if (agent) {
                                createAgentWindow(agent, cmd);
                            } else {
                                console.log(`[command-test] Agent not found: ${agentId}`);
                            }
                        }
                    } catch (e) { console.log(`[command-test] create window error: ${e.message}`); }
                })();
            }
        } catch (e) {
            console.log(`[command-test] Error: ${e.message}`);
        }
    });

    ipcMain.on('show-agent-right-click-menu', (event, clickedAgentRow) => {
        console.log(`[RIGHT-CLICK] clickedAgentRow : ${JSON.stringify(clickedAgentRow)}`);
        const agentid = clickedAgentRow.agent_id;
        const contextMenu = Menu.buildFromTemplate([
            {
                label: 'Kill',
                click: async () => {
                    try {
                        console.log(`Hit kill for agent ID: ${agentid}`);
                    } catch (error) {
                        console.log(`[KILL][!] Unexpected error in kill operation:\r\n${error}\r\n${error.stack}`);
                    }
                }
            }
        ]);
      contextMenu.popup(BrowserWindow.fromWebContents(event.sender));
    });

    // Fix for macOS Clipboard Shortcuts
    ipcMain.on('copy', async (event) => {
        const focusedWindow = BrowserWindow.getFocusedWindow();
        if (focusedWindow) {
            const selectedText = await focusedWindow.webContents.executeJavaScript('window.getSelection().toString()');
            clipboard.writeText(selectedText);
        }
    });

    ipcMain.on('cut', async (event) => {
        const focusedWindow = BrowserWindow.getFocusedWindow();
        if (focusedWindow) {
            const selectedText = await focusedWindow.webContents.executeJavaScript('window.getSelection().toString()');
            clipboard.writeText(selectedText);
            focusedWindow.webContents.executeJavaScript('document.execCommand("cut")');
        }
    });

    ipcMain.on('paste', (event) => {
        const focusedWindow = BrowserWindow.getFocusedWindow();
        if (focusedWindow) {
            focusedWindow.webContents.paste();
        }
    });

});

app.on('window-all-closed', () => {
    app.quit();
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createDashboardWindow();
    }
});
