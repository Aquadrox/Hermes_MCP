"""NAS file manager: a small web app serving one directory, reachable only through an MFA-gated tunnel.

It runs as the separate, sandboxed ``hermes-nas`` service (socket-activated on 127.0.0.1).
Users authenticate with the basic-auth credentials generated for the current NAS tunnel,
which the MCP server hands to the NAS (and revokes when the tunnel closes) and sends to the
user on Telegram only. The MCP server itself uses :data:`ACCESS_KEY_HEADER`, a key shared
through root-only configuration files. Local processes (the agent included) therefore cannot
use the NAS without going through ``nas_open`` and the user's MFA code.
"""

ACCESS_KEY_HEADER = "X-Hermes-NAS-Key"
HEALTH_PATH = "/api/health"
CREDENTIALS_PATH = "/api/admin/credentials"

__all__ = ["ACCESS_KEY_HEADER", "CREDENTIALS_PATH", "HEALTH_PATH"]
