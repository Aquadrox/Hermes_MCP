# Instructions for AI agents (Hermes)

This repository is an MCP server that lets you open short-lived ngrok tunnels for your user,
protected by a TOTP code from their Proton Authenticator app. It also ships an optional NAS
file manager (separate `hermes-nas` service, reachable only through an MFA-gated tunnel) and an
audit log. Read this file before installing
or using it. The user-facing documentation (in French) is in `README.md`.

## Ground rules

- The server runs as a **dedicated systemd service under its own Unix user** (`hermes-ngrok`).
  Never run it under your own user, and never try to read or change `/etc/hermes-ngrok-mcp/` or
  `/var/lib/hermes-ngrok-mcp/`: the isolation is what makes the MFA meaningful.
- Never start `ngrok` yourself and never try to bypass the MFA.
- Never try to reach the NAS directly (`127.0.0.1:8766`, its folder, `/etc/hermes-nas/`,
  `/var/lib/hermes-nas/`): the user reaches it through `nas_open` and their MFA code.
- Never invent, guess, reuse or store an MFA code. Ask the user each time.
- Installing the service needs root **once**. If you do not have passwordless `sudo`, give the
  user the exact command to run over SSH. If you do have it, tell the user that the isolation
  between you and the service is weaker in that setup.

## Installation

The root steps are run by the user over SSH (or by you only if you have passwordless sudo,
in which case tell the user that the isolation is weaker). Root must install from a
**root-owned clone**, never from a directory you can write to: otherwise a compromised agent
could change what root executes. Give the user these commands, replacing `<hermes-user>` by
the Unix user you run as (`whoami`):

1. Root-owned clone and installation:

   ```bash
   sudo git clone https://github.com/Aquadrox/Hermes_MCP.git /usr/local/src/hermes-ngrok-mcp
   sudo /usr/local/src/hermes-ngrok-mcp/deploy/install.sh --hermes-user <hermes-user>
   ```

   The installer creates the service, generates the API token, writes `HERMES_NGROK_MCP_TOKEN`
   into your `~/.hermes/.env` and pre-fills the Telegram settings from it. If `uv` is missing
   for root and the system Python is older than 3.12, it prints the command to install `uv`.

2. ngrok authtoken (the user edits the file, you never see it):

   ```bash
   sudo nano /etc/hermes-ngrok-mcp/hermes-ngrok-mcp.env   # NGROK_AUTHTOKEN=...
   sudo systemctl restart hermes-ngrok-mcp
   sudo hermes-ngrok-admin check
   ```

Then, as yourself:

3. Declare the server in `~/.hermes/config.yaml`. Merge it under the existing `mcp_servers:`
   key if there is one; never create a second `mcp_servers:` key. The port must match
   `HERMES_NGROK_PORT` (default 8765). Reference: `deploy/hermes-config.snippet.yaml`.

   ```yaml
   mcp_servers:
     ngrok:
       url: "http://127.0.0.1:8765/mcp"
       headers:
         Authorization: "Bearer ${HERMES_NGROK_MCP_TOKEN}"
       timeout: 120
       connect_timeout: 30
       sampling:
         enabled: false
   ```

4. Install the skill that explains how to use the tools:

   ```bash
   mkdir -p ~/.hermes/skills/devops
   cp -r /usr/local/src/hermes-ngrok-mcp/skills/ngrok-tunnels ~/.hermes/skills/devops/
   ```

5. Reload with `hermes gateway restart` (needed so that the new `HERMES_NGROK_MCP_TOKEN` from
   `~/.hermes/.env` is loaded), or `/reload-mcp` in a session if the variable was already there.

6. Verify: call `mcp_ngrok_mfa_status`; a fresh install answers `configured: false`. Then offer
   the user to configure MFA (see the skill).

### Optional: NAS file manager

The user (root) installs it once; give them these commands, adapting the folder and its owner
(the owner must be the user's own account, never yours):

```bash
sudo apt install acl
sudo /usr/local/src/hermes-ngrok-mcp/deploy/install.sh --nas-dir /var/MonNAS --nas-owner <owner>
sudo hermes-ngrok-admin nas check
```

The installer creates the `hermes-nas` system user, sets the folder to `<owner>:hermes-nas 2770`
with default ACLs, generates the access key shared with the MCP server and installs the
socket-activated `hermes-nas` units. Then call `mcp_ngrok_nas_status`: it answers
`enabled: true, reachable: true`. Copy the skill again (it documents `nas_open` and `audit_log`).

## Updating

```bash
sudo git -C /usr/local/src/hermes-ngrok-mcp pull
sudo /usr/local/src/hermes-ngrok-mcp/deploy/install.sh --hermes-user <hermes-user>
```

The configuration and the MFA secret are kept. Copy the skill again if it changed.

Updating restarts the service, which closes any open tunnel.

## Troubleshooting

- Tools missing in Hermes: check the YAML indentation, that `HERMES_NGROK_MCP_TOKEN` is in
  `~/.hermes/.env`, then `hermes gateway restart`.
- `401 unauthorized`: the token in `~/.hermes/.env` differs from `HERMES_NGROK_API_TOKEN` in
  the service configuration. Re-run the installer with `--hermes-user`.
- Service problems: ask the user for `sudo journalctl -u hermes-ngrok-mcp -n 50`.
- NAS problems: ask for `systemctl status hermes-nas.socket hermes-nas`,
  `sudo journalctl -u hermes-nas -n 50` and `sudo hermes-ngrok-admin nas check`.
- What happened: `mcp_ngrok_audit_log`, or ask the user for `sudo hermes-ngrok-admin audit --since 24h`.

## Development

`uv sync`, then `make check` (ruff, mypy --strict, pytest). The code is in `src/hermes_ngrok_mcp/`
(the NAS in `src/hermes_ngrok_mcp/nas/`, its UI in `nas/static/`), the tests in `tests/`. Keep
tool descriptions and `skills/ngrok-tunnels/SKILL.md` consistent.
