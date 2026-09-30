import json
from redis.asyncio import Redis
from .settings import settings

redis = Redis.from_url(settings.redis_url, decode_responses=True)
QUEUE = "dadadevourer:scan:headers"

async def enqueue_scan(scan_id: int):
    await redis.rpush(QUEUE, json.dumps({"scan_id": scan_id}))

async def close_queue():
    await redis.aclose()
