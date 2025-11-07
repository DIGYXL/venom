### Venom Client (GUI)

Web UI for interacting with the Venom server.

### Requirements

- Node.js (LTS recommended)

### Install and run

```bash
npm install
npm run start
```

This starts the development server for the client UI. Run the client on your workstation, not on the server. The client must be able to reach the server.

### Configure credentials

- After starting the Venom server, copy the admin username/password printed on first run (or set your own with `--adduser`).
- Open the client, go to the Config menu, and enter the server credentials. Save them so the client can authenticate to the server.

Security note: The client uses the server’s `/api/` base path. Do not expose `/api/` to the public internet. Use a VPN/private network or strict firewall/reverse-proxy rules so only trusted clients can access it.

### Connecting agents

- Agents contact the Venom server using the host/port/scheme set in `server/profiles/default.json` on the server side. Ensure those values reflect the publicly reachable address and port if agents are remote.
- Consider running the server behind a reverse proxy and only exposing the server API paths.
  - For agents, you can customize the base paths in `server/profiles/default.json` under `agent_api_base_paths` (see lines 97–118 of the default profile).


