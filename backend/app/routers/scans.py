from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_db
from ..deps import get_current_user
from ..models import Scan, User

router = APIRouter()

@router.get("")
async def list_scans(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(select(Scan).where(Scan.owner_id == user.id).order_by(Scan.created_at.desc()).limit(100))).scalars().all()
    return [{"id": s.id, "target_id": s.target_id, "scanner": s.scanner, "status": s.status, "created_at": s.created_at, "finished_at": s.finished_at} for s in scans]
