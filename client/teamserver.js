const { ipcMain} = require('electron');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs'); 
const fsp = require('fs').promises;
const { log } = require('console');

function decodeBase64(base64) {
  const buffer = Buffer.from(base64, 'base64');
  return buffer.toString('utf-8');
}
function encodeBase64(input) {
  const buffer = Buffer.from(input, 'utf-8');
  return buffer.toString('base64');
}
async function aesEncrypt(data, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = "";
  if (Buffer.isBuffer(data)) {
    encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  }
  else {
    encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
  }
  return encrypted;
}
async function aesDecrypt(encryptedData, key, iv) {
  // const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  // let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  // decrypted += decipher.final('utf8');
  // return decrypted;
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  
  let decrypted = "";
  if ( Buffer.isBuffer( encryptedData ) ) {
    decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }
  else { 
    decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
  }
  return decrypted;
}

function buildAuthHeader() {
  try {
    const cfg = global.appConfig || {};
    const user = cfg.username || 'admin';
    const pass = cfg.password || 'gnuDh8VYUYBnHx2Zv3k';
    return 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');
  } catch (_) { return null; }
}

async function listAgents(host='localhost', port=5000)
{
  try{
    let options = {
      hostname: host,
      port: port,
      path: `/api/client/agents`,
      method: 'GET',
      headers: { 'Authorization': buildAuthHeader() }
    };
    let agents = JSON.parse(await makeRequest(options));
    return agents;
  } catch (error) {
    return 0;
  }
}

async function makeRequest(options, data = null) {
    try{
        // Wait for renderer to be ready
        if (!global.dashboardWindow.webContents.isLoading()) {
        } else {
            await new Promise(resolve => {
                global.dashboardWindow.webContents.once('did-finish-load', resolve);
            });
        }

        return new Promise((resolve, reject) => {
            const url = `http://${options.hostname}:${options.port}${options.path}`;
            const requestId = Date.now().toString();
            // Set up response handler before sending request
            const responseHandler = (event, response) => {
                if (response.error) {
                    log(`[WEB-REQUEST] Error: ${response.error}`);
                    reject(new Error(response.error));
                    return;
                }
                resolve(response);
            };
            // Listen for the response with timeout
            ipcMain.once(`web-request-response-${requestId}`, responseHandler);
            if (data) {
                if (!options.headers) {
                    options.headers = {};
                }
                options.headers['Content-Length'] = Buffer.byteLength(data);
            }
            // Inject Authorization header if not set
            if (!options.headers) options.headers = {};
            if (!options.headers['Authorization']) {
              const auth = buildAuthHeader();
              if (auth) options.headers['Authorization'] = auth;
            }
            // Send request to renderer
            try {
                global.dashboardWindow.webContents.send('make-web-request', {
                    url,
                    method: options.method,
                    headers: options.headers,
                    body: data,
                    requestId
                });
            } catch (err) {
                ipcMain.removeListener(`web-request-response-${requestId}`, responseHandler);
                reject(err);
            }
            let timeout = 300000;
            setTimeout(() => {
                ipcMain.removeListener(`web-request-response-${requestId}`, responseHandler);
                reject(new Error(`Web request timed out after ${timeout}ms`));
            }, timeout);
        });
    } catch (error) {
      console.error(`Error making request: ${error.message} ${error.stack}`);
      return [];
    }
}


module.exports = {
  listAgents,
  makeRequest
};