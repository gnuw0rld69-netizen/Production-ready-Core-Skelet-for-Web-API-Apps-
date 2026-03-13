import json
from typing import Any, cast

from app.core.config import settings
from app.core.redis import get_redis_client


USER_CACHE_PREFIX = "cache:user"


class CacheService:
    @staticmethod
    def _user_cache_key(user_id: int) -> str:
        return f"{USER_CACHE_PREFIX}:{user_id}"

    @staticmethod
    def get_user(user_id: int) -> dict[str, Any] | None:
        client = get_redis_client()
        try:
            payload = client.get(CacheService._user_cache_key(user_id))
        except Exception:
            return None
        if not isinstance(payload, str):
            return None
        payload_str = cast(str, payload)
        try:
            return json.loads(payload_str)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def set_user(user_id: int, payload: dict[str, Any]) -> None:
        client = get_redis_client()
        try:
            client.setex(
                CacheService._user_cache_key(user_id),
                settings.CACHE_TTL_SECONDS,
                json.dumps(payload, default=str),
            )
        except Exception:
            return

    @staticmethod
    def invalidate_user(user_id: int) -> None:
        client = get_redis_client()
        try:
            client.delete(CacheService._user_cache_key(user_id))
        except Exception:
            return
