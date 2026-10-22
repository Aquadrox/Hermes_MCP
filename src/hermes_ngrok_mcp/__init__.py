"""On-demand, MFA-protected ngrok tunnels for the Hermes agent, exposed as an MCP server."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("hermes-ngrok-mcp")
except PackageNotFoundError:  # pragma: no cover - only when running from a raw checkout
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
