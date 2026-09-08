from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import get_current_user
from ..models import Target, User

router = APIRouter()


class TargetPayload(BaseModel):
    url: HttpUrl
    name: str | None = Field(default=None, max_length=200)


def normalize_target(data: TargetPayload) -> tuple[str, str | None]:
    raw_url = str(data.url)
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Only HTTP(S) targets are allowed")
    if parsed.username or parsed.password:
        raise HTTPException(400, "Target URLs must not contain embedded credentials")
    if parsed.port not in {None, 80, 443}:
        raise HTTPException(400, "Only ports 80 and 443 are allowed")
    name = data.name.strip() if data.name else None
    return raw_url, name or None


@router.post("/validate")
async def validate_target(data: TargetPayload, user: User = Depends(get_current_user)):
    url, name = normalize_target(data)
    parsed = urlparse(url)
    return {"valid": True, "host": parsed.hostname, "url": url, "name": name}


@router.post("")
async def create_target(
    data: TargetPayload,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    url, name = normalize_target(data)
    target = Target(owner_id=user.id, url=url, name=name)
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return {"id": target.id, "name": target.name, "url": target.url}


@router.get("")
async def list_targets(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(Target)
            .where(Target.owner_id == user.id)
            .order_by(Target.id.desc())
        )
    ).scalars().all()
    return [{"id": x.id, "name": x.name, "url": x.url} for x in rows]


@router.patch("/{target_id}")
async def update_target(
    target_id: int,
    data: TargetPayload,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    target = (
        await db.execute(
            select(Target).where(Target.id == target_id, Target.owner_id == user.id)
        )
    ).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target not found")

    url, name = normalize_target(data)
    target.url = url
    target.name = name
    await db.commit()
    await db.refresh(target)
    return {"id": target.id, "name": target.name, "url": target.url}


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        delete(Target).where(Target.id == target_id, Target.owner_id == user.id)
    )
    if result.rowcount == 0:
        raise HTTPException(404, "Target not found")
    await db.commit()
