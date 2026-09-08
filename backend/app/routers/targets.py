from fastapi import APIRouter, Depends
from pydantic import BaseModel, HttpUrl
from urllib.parse import urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..db import get_db
from ..deps import get_current_user
from ..models import User, Target

router = APIRouter()

class TargetCreate(BaseModel):
    url: HttpUrl
    name: str | None = None

@router.post("/validate")
async def validate_target(data: TargetCreate, user: User = Depends(get_current_user)):
    parsed = urlparse(str(data.url))
    return {"valid": parsed.scheme in {"http", "https"}, "host": parsed.hostname, "url": str(data.url)}

@router.post("")
async def create_target(data: TargetCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    target = Target(owner_id=user.id, url=str(data.url), name=data.name)
    db.add(target); await db.commit(); await db.refresh(target)
    return {"id": target.id, "name": target.name, "url": target.url}

@router.get("")
async def list_targets(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Target).where(Target.owner_id == user.id).order_by(Target.id.desc()))).scalars().all()
    return [{"id": x.id, "name": x.name, "url": x.url} for x in rows]
