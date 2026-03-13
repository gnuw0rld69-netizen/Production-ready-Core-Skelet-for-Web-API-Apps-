from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings


class TurnstileService:
    @staticmethod
    def verify(token: str | None, ip: str | None = None) -> bool:
        if not settings.TURNSTILE_SECRET_KEY:
            return True
        if not token:
            return False

        payload: dict[str, Any] = {
            "secret": settings.TURNSTILE_SECRET_KEY,
            "response": token,
        }
        if ip:
            payload["remoteip"] = ip

        try:
            response = httpx.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=payload,
                timeout=10,
            )
            data = response.json()
            return bool(data.get("success"))
        except httpx.HTTPError:
            return False
