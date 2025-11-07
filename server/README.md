### Venom Server

Operational guide for running the C2 server and building agents.

### Requirements

- Python 3.x
- Install deps:

```bash
pip3 install -r requirements.txt
```

### Run the server

```bash
python3 server.py --help
```

Common usage:

```bash
python3 server.py            # start (defaults shown in profiles/default.json)
python3 server.py --host 0.0.0.0 --port 5000
python3 server.py --adduser <USERNAME> <PASSWORD>   # create/update admin
```

- On first run, if `config.json` is missing, it is created and the server prints a randomly generated admin username/password. Copy and store these credentials from the console output.
- You can alternatively set your own credentials up front with `--adduser`.

The server logs all routes on startup and then begins listening, e.g.:

```bash
==================================================
Default admin credentials (store securely):
  username: admin
  password: <generated-password>
==================================================
 * Running on http://127.0.0.1:5000
```

Security note (client API): The client communicates to the server under the `/api/` base path. Do not expose `/api/` directly to the internet. Require VPN/private access or restrictive firewall/reverse-proxy rules that allow only trusted clients.

### Agent build workflow

Agents are created and used from this `server/` directory.

1) Create a standalone agent (embeds values from `profiles/default.json` into `../agent/agent.py`). The CLI now requires server host and port; use `-http` to force HTTP (default is HTTPS):

```bash
python3 agent_create.py -H <server_host> -P <server_port> [-http]
```

- Output goes to `agents/agent_YYYYMMDD_HHMMSS.py` by default.
- Use `--profile`, `--template`, and `--output-dir` for overrides.

2) Obfuscate the generated agent:

```bash
python3 agent_obfuscate.py agents/<generated_agent>.py
```

- Output goes to `obfuscate/output/obfuscated_agent_YYYYMMDD_HHMMSS.py`.

### Profiles and configuration

- `profiles/default.json` controls default agent behavior. Important fields under `agent` include:

```json
"server_host": "localhost",
"server_port": 5000,
"server_scheme": "http",
"proxy_host": "127.0.0.1"
```

Set these to match where the server is reachable from agents. If using an outbound proxy, adjust `proxy_host` accordingly. The profile also defines agent API base paths and randomization pools.

Agent API base paths are defined under `agent_api_base_paths` (see lines 97–118 of the default profile). Consider customizing these paths to align with your reverse proxy and routing strategy.

- `config.json` (auto-created) stores server-side admin credentials and runtime configuration.

### Reverse proxy recommendation

Place the server behind a reverse proxy and only expose the specific API paths (printed in the server logs at startup). Terminate TLS at the proxy when possible. Avoid exposing `/api/` publicly; prefer VPN or tightly controlled access.


