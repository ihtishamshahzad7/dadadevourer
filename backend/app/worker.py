import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from redis.asyncio import Redis
from sqlalchemy import delete, select, update

from .db import SessionLocal
from .models import Finding, Scan, Target
from .queue import QUEUE
from .scanners.headers import run
from .settings import settings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

STALE_SCAN_SECONDS = 120
RECOVERY_INTERVAL_SECONDS = 30
RETRY_BASE_DELAY_SECONDS = 2


def is_retryable(exc: Exception) -> bool:
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, ConnectionError, OSError))


async def enqueue_retry(redis: Redis, scan_id: int, delay: float) -> None:
    await asyncio.sleep(delay)
    await redis.rpush(QUEUE, json.dumps({"scan_id": scan_id}))


async def process(scan_id: int, redis: Redis):
    lease_id = uuid.uuid4().hex
    async with SessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if not scan or scan.status not in {"queued", "retry"}:
            return

        if scan.attempts >= scan.max_attempts:
            scan.status = "failed"
            scan.error = "Maximum scan attempts exceeded"
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return

        target = await db.get(Target, scan.target_id)
        if not target:
            scan.status = "failed"
            scan.error = "Target not found"
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return

        scan.status = "running"
        scan.attempts += 1
        scan.started_at = datetime.now(timezone.utc)
        scan.heartbeat_at = scan.started_at
        scan.lease_id = lease_id
        scan.error = None
        await db.commit()

        try:
            result = await run(target.url)

            # Only the current lease may publish results. A stale worker cannot
            # overwrite a scan that has already been recovered and requeued.
            owned = (
                await db.execute(
                    select(Scan.id).where(
                        Scan.id == scan.id,
                        Scan.status == "running",
                        Scan.lease_id == lease_id,
                    )
                )
            ).scalar_one_or_none()
            if owned is None:
                logger.warning("Scan %s lease lost before result commit", scan.id)
                return

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
            scan.error = None
            scan.heartbeat_at = datetime.now(timezone.utc)
            scan.lease_id = None
            scan.finished_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as exc:
            logger.exception("Scan %s attempt %s failed", scan.id, scan.attempts)
            owned = (
                await db.execute(
                    select(Scan).where(
                        Scan.id == scan.id,
                        Scan.status == "running",
                        Scan.lease_id == lease_id,
                    )
                )
            ).scalar_one_or_none()
            if owned is None:
                return

            owned.error = str(exc)[:2000]
            owned.heartbeat_at = datetime.now(timezone.utc)
            owned.lease_id = None
            if is_retryable(exc) and owned.attempts < owned.max_attempts:
                owned.status = "retry"
                owned.finished_at = None
                delay = RETRY_BASE_DELAY_SECONDS * (2 ** (owned.attempts - 1))
                await db.commit()
                asyncio.create_task(enqueue_retry(redis, owned.id, delay))
            else:
                owned.status = "failed"
                owned.finished_at = datetime.now(timezone.utc)
                await db.commit()


async def recover_stale_scans(redis: Redis) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=STALE_SCAN_SECONDS)
    async with SessionLocal() as db:
        stale = (
            await db.execute(
                select(Scan).where(
                    Scan.status == "running",
                    Scan.heartbeat_at.is_not(None),
                    Scan.heartbeat_at < cutoff,
                )
            )
        ).scalars().all()
        for scan in stale:
            scan.lease_id = None
            scan.error = "Worker lease expired; scan recovered"
            if scan.attempts < scan.max_attempts:
                scan.status = "retry"
                scan.finished_at = None
                await db.commit()
                await redis.rpush(QUEUE, json.dumps({"scan_id": scan.id}))
                logger.warning("Recovered stale scan %s", scan.id)
            else:
                scan.status = "failed"
                scan.finished_at = datetime.now(timezone.utc)
                await db.commit()
                logger.error("Stale scan %s exhausted its attempts", scan.id)


async def main():
    redis = Redis.from_url(settings.redis_url, decode_responses=True)
    last_recovery = datetime.now(timezone.utc)
    try:
        while True:
            try:
                now = datetime.now(timezone.utc)
                if (now - last_recovery).total_seconds() >= RECOVERY_INTERVAL_SECONDS:
                    await recover_stale_scans(redis)
                    last_recovery = now

                item = await redis.blpop(QUEUE, timeout=5)
                if item:
                    payload = json.loads(item[1])
                    scan_id = int(payload["scan_id"])
                    await process(scan_id, redis)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Worker loop error; reconnecting")
                await asyncio.sleep(2)
    finally:
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
