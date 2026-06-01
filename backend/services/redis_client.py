"""Redis client with graceful fallback to in-memory storage."""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_redis_client = None
_redis_available = False


async def get_redis():
    """Get Redis client, returns None if unavailable."""
    global _redis_client, _redis_available

    if _redis_client is not None:
        return _redis_client if _redis_available else None

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        _redis_available = False
        return None

    try:
        import redis.asyncio as aioredis
        _redis_client = aioredis.from_url(redis_url, decode_responses=True)
        await _redis_client.ping()
        _redis_available = True
        logger.info(f"Redis connected: {redis_url}")
        return _redis_client
    except ImportError:
        logger.error("redis package not installed, falling back to in-memory rate limiting")
        _redis_available = False
        return None
    except Exception as e:
        logger.error(f"Redis unavailable, falling back to in-memory rate limiting: {e}")
        _redis_available = False
        return None


async def redis_incr_with_ttl(key: str, ttl_seconds: int) -> int:
    """Increment a Redis counter with TTL. Returns new count."""
    client = await get_redis()
    if client is None:
        return -1  # Signal to use in-memory fallback

    try:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_seconds)
        results = await pipe.execute()
        return results[0]  # The incremented value
    except Exception as e:
        logger.error(f"Redis rate limiting failed, falling back to in-memory: {e}")
        return -1
