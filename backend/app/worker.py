import asyncio
import json
from datetime import datetime, timezone
from redis.asyncio import Redis
from sqlalchemy import select
from .db import SessionLocal
from .models import Scan, Target, Finding
from .queue import QUEUE
from .settings import settings
from .scanners.headers import run

async def process(scan_id: int):
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or scan.status not in {"queued", "retry"}:
            return
        target = await db.get(Target, scan.target_id)
        if not target:
            scan.status = "failed"; scan.error = "Target not found"; await db.commit(); return
        scan.status = "running"; scan.started_at = datetime.now(timezone.utc); await db.commit()
        try:
            result = await run(target.url)
            for item in result["findings"]:
                db.add(Finding(scan_id=scan.id, check=item["check"], severity=item["severity"], status=item["status"], value=item["value"]))
            scan.status = "completed"
        except Exception as exc:
            scan.status = "failed"; scan.error = str(exc)[:2000]
        scan.finished_at = datetime.now(timezone.utc)
        await db.commit()

async def main():
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        while True:
            item = await redis.blpop(QUEUE, timeout=5)
            if item:
                try:
                    await process(json.loads(item[1])["scan_id"])
                except Exception:
                    pass
    finally:
        await redis.aclose()

if __name__ == "__main__":
    asyncio.run(main())
