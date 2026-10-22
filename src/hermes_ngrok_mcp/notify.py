"""Direct notifications to the user through the Telegram Bot API.

The MCP server cannot push messages through Hermes, so it talks to Telegram itself, with
the same bot. This channel also delivers secrets (TOTP enrollment, basic-auth passwords)
straight to the user without routing them through the language model.

Transient failures (network errors, rate limits) are retried a few times; persistent ones
are logged (with the bot token redacted) and reported to the caller as ``None``/``False``,
never raised, so that a Telegram outage cannot break tunnel management.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Protocol

import httpx2

log = logging.getLogger(__name__)

# Longer rate-limit pauses are not waited for: the caller gives up and reports the failure.
_MAX_RETRY_DELAY = 10.0


class Notifier(Protocol):
    @property
    def enabled(self) -> bool: ...

    async def send_text(self, text: str, *, protect: bool = False) -> int | None:
        """Send an HTML-formatted message; return its id, or ``None`` on failure."""
        ...

    async def send_photo(self, image: bytes, caption: str, *, protect: bool = True) -> int | None: ...

    async def delete(self, message_id: int) -> bool: ...

    async def aclose(self) -> None: ...


class NullNotifier:
    """Used when Telegram is not configured."""

    @property
    def enabled(self) -> bool:
        return False

    async def send_text(self, text: str, *, protect: bool = False) -> int | None:
        return None

    async def send_photo(self, image: bytes, caption: str, *, protect: bool = True) -> int | None:
        return None

    async def delete(self, message_id: int) -> bool:
        return False

    async def aclose(self) -> None:
        return None


class TelegramNotifier:
    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        api_base: str = "https://api.telegram.org",
        client: httpx2.AsyncClient | None = None,
        timeout: float = 15.0,
        attempts: int = 3,
        backoff: float = 1.0,
    ) -> None:
        self._token = token
        self._chat_id = chat_id
        self._base = f"{api_base.rstrip('/')}/bot{token}"
        self._client = client or httpx2.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._attempts = max(1, attempts)
        self._backoff = backoff

    @property
    def enabled(self) -> bool:
        return True

    async def send_text(self, text: str, *, protect: bool = False) -> int | None:
        result = await self._call(
            "sendMessage",
            json_body={
                "chat_id": self._chat_id,
                "text": text,
                "parse_mode": "HTML",
                "protect_content": protect,
                "link_preview_options": {"is_disabled": True},
            },
        )
        return _message_id(result)

    async def send_photo(self, image: bytes, caption: str, *, protect: bool = True) -> int | None:
        result = await self._call(
            "sendPhoto",
            form={
                "chat_id": self._chat_id,
                "caption": caption,
                "parse_mode": "HTML",
                "protect_content": json.dumps(protect),
            },
            files={"photo": ("qr.png", image, "image/png")},
        )
        return _message_id(result)

    async def delete(self, message_id: int) -> bool:
        result = await self._call(
            "deleteMessage", json_body={"chat_id": self._chat_id, "message_id": message_id}
        )
        return result is True

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _call(
        self,
        method: str,
        *,
        json_body: dict[str, Any] | None = None,
        form: dict[str, Any] | None = None,
        files: dict[str, tuple[str, bytes, str]] | None = None,
    ) -> Any:
        for attempt in range(1, self._attempts + 1):
            delay: float | None = None
            try:
                response = await self._client.post(
                    f"{self._base}/{method}", json=json_body, data=form, files=files
                )
                payload = response.json()
            except (httpx2.HTTPError, ValueError) as exc:
                log.warning("Telegram %s failed: %s", method, self._redact(f"{type(exc).__name__}: {exc}"))
                delay = self._backoff * attempt
            else:
                if isinstance(payload, dict) and payload.get("ok"):
                    return payload.get("result")
                description = payload.get("description") if isinstance(payload, dict) else None
                log.warning("Telegram %s rejected (HTTP %s): %s", method, response.status_code, description)
                if response.status_code == 429 or response.status_code >= 500:
                    parameters = payload.get("parameters") if isinstance(payload, dict) else None
                    retry_after = parameters.get("retry_after") if isinstance(parameters, dict) else None
                    if isinstance(retry_after, int | float):
                        delay = float(retry_after)
                    else:
                        delay = self._backoff * attempt
            if delay is None or attempt == self._attempts or delay > _MAX_RETRY_DELAY:
                return None
            await asyncio.sleep(delay)
        return None

    def _redact(self, text: str) -> str:
        return text.replace(self._token, "<redacted>")


def _message_id(result: Any) -> int | None:
    if isinstance(result, dict) and isinstance(result.get("message_id"), int):
        return int(result["message_id"])
    return None
