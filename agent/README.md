### Venom Agent (Development Template)

`agent.py` in this directory is the development template. You generally do not deploy this file directly. If you want to contribute to the project this is the development agent file that should have the changes made to it.

### How agents are built

From the `server/` directory, run:

```bash
python3 agent_create.py -H <server_host> -P <server_port> [-http]
```

This reads values from `server/profiles/default.json`, embeds them into the template `agent/agent.py`, and writes a standalone agent to `server/agents/`.

To obfuscate the generated agent:

```bash
python3 agent_obfuscate.py agents/<generated_agent>.py
```

The obfuscated agent is written to `server/obfuscate/output/`.

### Configuration source of truth

Edit `server/profiles/default.json` (not `agent/agent.py`) to set:

```json
"server_host": "localhost",
"server_port": 5000,
"server_scheme": "http",
"proxy_host": "127.0.0.1"
```

Adjust these to match how the agent reaches the server. Re-run `agent_create.py` whenever you change profile values.

You can also customize the agent base paths under `agent_api_base_paths` (see lines 97–118 of the default profile) to align with your reverse proxy and routing.


