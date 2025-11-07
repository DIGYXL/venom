const { ipcRenderer } = require('electron');
const { log } = require('console');

// Agent class definition
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

let tableinit = false;
// Sort state: column one of agentid, hostname, username, pid, ip, os, lastseen; direction 'asc'|'desc'
// direction: 'asc' | 'desc' | null (no sort)
let sortState = { column: null, direction: null };

// Global array to hold all agent objects
let agentsArray = [];

// Helper function to format time difference
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

function getAgeSeconds(lastSeenTimestamp) {
    const now = new Date();
    const lastSeen = new Date(lastSeenTimestamp);
    const diffMs = now - lastSeen;
    return Math.max(0, Math.floor(diffMs / 1000));
}

// Helper function to find or create agent object
function getOrCreateAgent(agentData) {
    const existingAgent = agentsArray.find(agent => agent.agent_id === agentData.agent_id);
    
    if (existingAgent) {
        // Update existing agent with new data
        existingAgent.update(agentData);
        return existingAgent;
    } else {
        // Create new agent object using Agent class
        const newAgent = new Agent(agentData);
        agentsArray.push(newAgent);
        return newAgent;
    }
}

function debug(message) 
{
    const timestamp = new Date().toISOString();
    log(`[${timestamp}] ${message}`);
}

window.addEventListener('DOMContentLoaded', async () => {
    debug('Dashboard loading');
    // Attach sortable header clicks
    const header = document.querySelector('#agentTable thead');
    if (header) {
        header.querySelectorAll('th[data-column]').forEach(th => {
            th.style.userSelect = 'none';
            th.style.cursor = 'pointer';
            // Add resize handle
            const resizer = document.createElement('div');
            resizer.className = 'col-resizer';
            th.appendChild(resizer);
            let startX = 0; let startWidth = 0;
            const onMouseMove = (e) => {
                const dx = e.clientX - startX;
                const newWidth = Math.max(60, startWidth + dx);
                th.style.width = newWidth + 'px';
            };
            const onMouseUp = () => {
                window.removeEventListener('mousemove', onMouseMove);
                window.removeEventListener('mouseup', onMouseUp);
            };
            resizer.addEventListener('mousedown', (e) => {
                e.stopPropagation();
                startX = e.clientX;
                startWidth = th.getBoundingClientRect().width;
                window.addEventListener('mousemove', onMouseMove);
                window.addEventListener('mouseup', onMouseUp);
            });
            th.addEventListener('click', () => {
                const col = th.getAttribute('data-column');
                if (!col) return;
                if (sortState.column === col) {
                    // Toggle asc -> desc -> none
                    if (sortState.direction === 'asc') sortState.direction = 'desc';
                    else if (sortState.direction === 'desc') { sortState.column = null; sortState.direction = null; }
                    else { sortState.direction = 'asc'; }
                } else {
                    sortState.column = col;
                    sortState.direction = 'asc';
                }
                updateSortArrows();
                renderTableSorted();
            });
        });
    }
    async function updateTable() {
        try {
            let agents = await ipcRenderer.invoke('list-agents');
            if (agents && Array.isArray(agents.agents)) {
                agents.agents.forEach(agent => { if (agent) getOrCreateAgent(agent); });
                renderTableSorted();
            }
            tableinit = true;
        } catch (error) {
            debug(`[!] updateTable(): ${error.message} ${error.stack}`);
        }
    }

    function renderTableSorted() {
        try {
            const tbody = document.getElementById('agentTable').getElementsByTagName('tbody')[0];
            tbody.innerHTML = '';
            const sorted = (!sortState.column || !sortState.direction)
                ? [...agentsArray]
                : [...agentsArray].sort((a, b) => compareAgents(a, b));
            sorted.forEach(agentObj => {
                const row = tbody.insertRow();
                for (let i = 0; i < 7; i++) row.insertCell(i);
                row.cells[0].textContent = agentObj.agent_id;
                row.cells[1].textContent = agentObj.hostname;
                row.cells[2].textContent = agentObj.username;
                row.cells[3].textContent = agentObj.pid;
                const ips = Array.isArray(agentObj.ip_addresses) ? agentObj.ip_addresses.join(',') : (agentObj.ip_addresses || '');
                row.cells[4].textContent = ips;
                row.cells[5].textContent = agentObj.os_info;
                if (agentObj.is_new) {
                    row.cells[6].textContent = agentObj.last_seen;
                    agentObj.markAsExisting();
                } else {
                    row.cells[6].textContent = formatTimeDifference(agentObj.last_seen);
                }
                row.addEventListener('click', () => {
                    debug(`Agent ${agentObj.agent_id} row left-clicked!`);
                    const agentPayload = {
                        agent_id: agentObj.agent_id,
                        system_info: {
                            hostname: agentObj.hostname,
                            username: agentObj.username,
                            pid: agentObj.pid,
                            ip_addresses: agentObj.ip_addresses,
                            os_info: agentObj.os_info
                        },
                        last_seen: agentObj.last_seen
                    };
                    ipcRenderer.send('open-agent-window', agentPayload);
                });
            });
        } catch (error) {
            debug(`[!] renderTableSorted(): ${error.message} ${error.stack}`);
        }
    }

    function compareAgents(a, b) {
        if (!sortState.column || !sortState.direction) return 0;
        const dir = sortState.direction === 'asc' ? 1 : -1;
        const col = sortState.column;
        const val = (agent, column) => {
            switch (column) {
                case 'agentid': return String(agent.agent_id || '');
                case 'hostname': return String(agent.hostname || '');
                case 'username': return String(agent.username || '');
                case 'pid': return Number(agent.pid || 0);
                case 'ip': {
                    const ips = Array.isArray(agent.ip_addresses) ? agent.ip_addresses.join(',') : (agent.ip_addresses || '');
                    return String(ips);
                }
                case 'os': return String(agent.os_info || '');
                case 'lastseen': return Number(getAgeSeconds(agent.last_seen));
                default: return '';
            }
        };
        let av = val(a, col);
        let bv = val(b, col);
        if (col === 'pid' || col === 'lastseen') {
            return (av - bv) * dir;
        }
        // string compare
        if (av < bv) return -1 * dir;
        if (av > bv) return 1 * dir;
        return 0;
    }

    function updateSortArrows() {
        const cols = ['agentid','hostname','username','pid','ip','os','lastseen'];
        cols.forEach(c => {
            const arrow = document.getElementById(`${c}Arrow`);
            if (!arrow) return;
            if (!sortState.column || sortState.column !== c || !sortState.direction) {
                arrow.textContent = '';
            } else {
                arrow.textContent = sortState.direction === 'asc' ? '▲' : '▼';
            }
        });
    }
    setInterval(updateTable, 1000);
    const table = document.getElementById('agentTable');
    if (!table) return;
    table.addEventListener('contextmenu', rightClickAgentRow);
});

async function rightClickAgentRow(event) {
    event.preventDefault();
    log("Right-click detected on agent row");
    log(`event : ${JSON.stringify(event)}`);
    if(tableinit === true) {
        let row = event.target.closest("tr");
        log(`row : ${JSON.stringify(row)}`);
        if (!row || row.rowIndex === 0) return;

        // Get the agentid for the clicked row
        let agentid = row.cells[0]?.textContent || '';
        
        // Get data for the clicked agent
        let clickedAgentRow = {
            agent_id:     row.cells[0]?.textContent || '',
            hostname:     row.cells[1]?.textContent || '',
            username:     row.cells[2]?.textContent || '',
            pid:          row.cells[3]?.textContent || '',
            ip_addresses: row.cells[4]?.textContent || '',
            os_info:      row.cells[5]?.textContent || '',
            last_seen:    row.cells[6]?.textContent || ''
        };

        ipcRenderer.send('show-agent-right-click-menu', clickedAgentRow);
    }
}

ipcRenderer.on('make-web-request', async (event, requestOptions) => {
    try {
        const { url, method = 'GET', headers = {}, body, requestId } = requestOptions;
        const defaultHeaders = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        };
        const fetchOptions = {
            method,
            headers: { ...defaultHeaders, ...headers }
        };
        if (body !== undefined) {
            fetchOptions.body = body;
        }
        const response = await fetch(url, fetchOptions);
        let data = "";
        const contentType = response.headers.get('content-type');
        if (contentType && (
            contentType.includes('application/octet-stream') ||
            contentType.includes('application/x-binary') ||
            contentType.includes('application/x-msdownload') ||
            contentType.includes('application/zip') ||
            contentType.includes('application/pdf') ||
            contentType.includes('image/') ||
            contentType.includes('video/') ||
            contentType.includes('audio/')
        )) {
            const arrayBuffer = await response.arrayBuffer();
            data = Buffer.from(arrayBuffer);
        } else {
            data = await response.text();
        }
        ipcRenderer.send(`web-request-response-${requestId}`, data);
    } catch (error) {
        ipcRenderer.send(`web-request-response-${requestId}`, {
            error: error.message
        });
    }
});

// Minimal request that reports HTTP status for auth testing
ipcRenderer.on('make-web-request-status', async (event, requestOptions) => {
    try {
        const { url, method = 'GET', headers = {}, requestId } = requestOptions;
        const defaultHeaders = {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        };
        const fetchOptions = { method, headers: { ...defaultHeaders, ...headers } };
        const response = await fetch(url, fetchOptions);
        ipcRenderer.send(`web-request-status-response-${requestId}`, { status: response.status });
    } catch (error) {
        ipcRenderer.send(`web-request-status-response-${requestId}`, { error: error.message });
    }
});
