from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl
from urllib.parse import urlparse

router = APIRouter()

class TargetCreate(BaseModel):
    url: HttpUrl
    name: str | None = None

@router.post("/validate")
async def validate_target(data: TargetCreate):
    parsed = urlparse(str(data.url))
    return {"valid": parsed.scheme in {"http", "https"}, "host": parsed.hostname, "url": str(data.url)}
