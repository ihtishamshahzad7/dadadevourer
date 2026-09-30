from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_db
from ..deps import get_current_user
from ..models import Finding, Scan, Target, User
from ..queue import enqueue_scan

router = APIRouter()

class ScanRequest(BaseModel):
    target_id: int

@router.post("")
async def create_scan(data: ScanRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    target = (await db.execute(select(Target).where(Target.id == data.target_id, Target.owner_id == user.id))).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target not found")
    scan = Scan(owner_id=user.id, target_id=target.id, scanner="headers", status="queued", max_attempts=3)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    try:
        await enqueue_scan(scan.id)
    except Exception as exc:
        scan.status = "failed"
        scan.error = "Unable to queue scan"
        await db.commit()
        raise HTTPException(503, "Scan queue unavailable") from exc
    return {"id": scan.id, "status": scan.status, "target_id": target.id, "attempts": scan.attempts, "max_attempts": scan.max_attempts}

@router.get("/{scan_id}")
async def get_scan(scan_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id, Scan.owner_id == user.id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan.id))).scalars().all()
    return {
        "id": scan.id,
        "status": scan.status,
        "scanner": scan.scanner,
        "error": scan.error,
        "attempts": scan.attempts,
        "max_attempts": scan.max_attempts,
        "heartbeat_at": scan.heartbeat_at,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "findings": [{"check": f.check, "severity": f.severity, "status": f.status, "value": f.value} for f in findings],
    }
