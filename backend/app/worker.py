import asyncio
import json
import logging
from datetime import datetime, timezone

from redis.asyncio import Redis
from sqlalchemy import delete

from .db import SessionLocal
from .models import Finding, Scan, Target
from .queue import QUEUE
from .scanners.headers import run
from .settings import settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


async def process(scan_id: int):
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or scan.status not in {"queued", "retry"}:
            return

        target = await db.get(Target, scan.target_id)
        if not target:
            scan.status = "failed"
            scan.error = "Target not found"
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.error = None
        await db.commit()

        try:
            result = await run(target.url)
            # A retry must replace the previous result rather than duplicate findings.
            await db.execute(delete(Finding).where(Finding.scan_id == scan.id))
            for item in result["findings"]:
                db.add(
                    Finding(
                        scan_id=scan.id,
                        check=item["check"],
                        severity=item["severity"],
                        status=item["status"],
                        value=item["value"],
                    )
                )
            scan.status = "completed"
        except Exception as exc:
            logger.exception("Scan %s failed", scan.id)
            scan.status = "failed"
            scan.error = str(exc)[:2000]
        scan.finished_at = datetime.now(timezone.utc)
        await db.commit()


async def main():
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        while True:
            try:
                item = await redis.blpop(QUEUE, timeout=5)
                if item:
                    payload = json.loads(item[1])
                    scan_id = int(payload["scan_id"])
                    await process(scan_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Worker loop error; reconnecting")
                await asyncio.sleep(2)
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
