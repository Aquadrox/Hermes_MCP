---
name: ngrok-tunnels
description: Open, check, extend and close temporary ngrok tunnels that expose a local port of this server, protected by a TOTP code from the user's Proton Authenticator, through the "ngrok" MCP server. Also sets up that MFA. Use when the user asks to open/expose/share a local port or service, needs remote (e.g. SSH) access, asks whether a tunnel is used, wants to extend or close it, or asks to configure MFA for tunnels.
version: 1.0.0
platforms: [linux]
metadata:
  hermes:
    tags: [ngrok, tunnel, remote-access, mfa, totp, security]
    category: devops
---

# ngrok tunnels protected by MFA

The server is not reachable from the Internet. On request, the `ngrok` MCP server opens a
short-lived public tunnel to one local port. Every opening and every extension needs a fresh
6-digit code from the user's **Proton Authenticator** app.

## When to Use

- "Ouvre-moi un tunnel sur le port 8080", "donne-moi accès à Grafana", "expose le port 3000"
- "J'ai besoin d'un accès SSH" → TCP tunnel on port 22
- "Le tunnel est-il utilisé ?", "prolonge le tunnel", "ferme le tunnel"
- "Configure le MFA pour les tunnels", "j'ai changé de téléphone"

## Tools

| Tool | Purpose | MFA code |
|------|---------|----------|
| `mcp_ngrok_mfa_status` | Is MFA configured / locked? | no |
| `mcp_ngrok_mfa_setup_start` | Start enrollment (QR code sent to the user on Telegram) | only to replace an existing authenticator |
| `mcp_ngrok_mfa_setup_confirm` | Finish enrollment with a code from the new authenticator | yes |
| `mcp_ngrok_tunnel_open` | Open, verify end to end and return the URL | yes |
| `mcp_ngrok_tunnel_status` | URL, expiry, idle timer, real usage (connections, bytes); `verify=true` re-tests from the Internet | no |
| `mcp_ngrok_tunnel_extend` | Push back the expiry | yes |
| `mcp_ngrok_tunnel_close` | Close one tunnel, or all of them | no |

## Rules

1. **Always ask the user for the code right before the call** (« Envoie-moi le code à 6 chiffres
   affiché dans Proton Authenticator pour *Hermes ngrok*. »). Never invent, guess, reuse or store
   a code. A code is single-use and changes every 30 seconds.
2. Ask for a code only when the user requested the action themselves. Never ask for one
   "just in case".
3. When `access.password_delivery` is `telegram`, the bot has already sent the URL, username and
   password to the user. Do not ask for the password and do not repeat it.
4. Never bypass this server: do not run `ngrok` yourself, do not read or modify
   `/etc/hermes-ngrok-mcp/` or `/var/lib/hermes-ngrok-mcp/`. The whole point is that exposure
   requires the user's second factor.
5. Offer to close tunnels that are no longer needed.

## Procedure — open a tunnel

1. Work out the local port; ask if it is unclear. Protocol: `http` for websites, web UIs and
   HTTP APIs (gives an `https://` URL); `tcp` for SSH, databases and other TCP services.
2. HTTP tunnels are password-protected by default. Pass `protect=false` only if the user
   explicitly asks for no password.
3. Ask for the MFA code, then call `mcp_ngrok_tunnel_open(port, mfa_code, protocol, label?)`.
4. Reply with the URL (for TCP: host and port, e.g. `ssh -p <port> user@<host>`), the expiry
   time, and the rule: it closes after 10 minutes without use and at the latest after
   20 minutes, unless extended (the server's exact values are in the result).

## Procedure — usage and extension

- "Is it used?" → `mcp_ngrok_tunnel_status`: report `in_use`, `usage.connections_total`,
  `usage.last_activity_at`, `closes_if_idle_in_seconds` and `expires_in_seconds`.
- The user gets a Telegram warning 5 minutes before expiry. To extend: ask for a new code, then
  `mcp_ngrok_tunnel_extend(mfa_code, tunnel_id?)` (`tunnel_id` may be omitted when a single
  tunnel is open). Extending also resets the idle timer.

## Procedure — MFA setup (first time, or new phone)

1. `mcp_ngrok_mfa_status`. If MFA is already configured and the user wants a new device, ask for
   a code from the **current** device and pass it as `current_mfa_code`.
2. `mcp_ngrok_mfa_setup_start`.
   - `delivered_via: telegram`: the bot has sent a QR code and the key to the user. Explain:
     in Proton Authenticator, tap **+**, then scan the QR code, or choose manual entry and
     paste the key (tap the key in Telegram to copy it). Scanning is impossible from the same
     phone, so manual entry is the usual way.
   - `delivered_via: this_result` (Telegram not configured): send the user the QR image
     (`MEDIA:` path) and the key, and advise them to delete these messages afterwards.
3. Ask for the 6-digit code shown by the app, then call `mcp_ngrok_mfa_setup_confirm(mfa_code)`.

## Pitfalls

- *Invalid MFA code*: ask for a new code. Several failures lock MFA (15 min, doubling each
  time) and alert the user on Telegram: do not retry blindly.
- *Code already used*: wait for the next code (30 s).
- *Nothing is listening on 127.0.0.1:PORT*: the service is not running; start it first.
- *ERR_NGROK_8013*: TCP tunnels need a payment method on the ngrok account (free plan included).
- *ERR_NGROK_334* / limit reached: the free plan has a single dev domain, so one HTTP tunnel at a
  time. Close the existing one first.
- On the free plan, browsers first see an ngrok warning page: the user clicks "Visit Site".
- Lost phone: only the administrator can reset MFA, over SSH:
  `sudo hermes-ngrok-admin mfa reset`. You cannot do it.

## Verification

- `mcp_ngrok_tunnel_status(verify=true)` re-tests every tunnel from the Internet without
  counting as usage.
- After a server restart all tunnels are closed. That is expected.
