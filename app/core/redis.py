from functools import lru_cache

from redis import Redis

from app.core.config import settings


@lru_cache(maxsize=1)
def get_redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def close_redis_client() -> None:
    client = get_redis_client()
    client.close()
    client.connection_pool.disconnect()
    get_redis_client.cache_clear()
