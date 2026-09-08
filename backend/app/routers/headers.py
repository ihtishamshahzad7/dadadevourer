import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from ..deps import get_current_user
from ..models import User

router = APIRouter()
REQUIRED = {
    "content-security-policy": "High",
    "strict-transport-security": "High",
    "x-content-type-options": "Medium",
    "x-frame-options": "Medium",
    "referrer-policy": "Low",
    "permissions-policy": "Low",
}

class HeaderScanRequest(BaseModel):
    url: HttpUrl

def is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
        return all(not any(ipaddress.ip_address(i[4][0]).is_private for _ in [0]) and not ipaddress.ip_address(i[4][0]).is_loopback and not ipaddress.ip_address(i[4][0]).is_link_local for i in infos)
    except (ValueError, socket.gaierror):
        return False

@router.post("")
async def scan_headers(data: HeaderScanRequest, user: User = Depends(get_current_user)):
    url = str(data.url); parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise HTTPException(400, "Only publicly routable HTTP(S) targets are allowed")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Target request failed: {exc}")
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = [{"header": h, "severity": s, "status": "present" if h in headers else "missing", "value": headers.get(h)} for h, s in REQUIRED.items()]
    return {"url": str(response.url), "status_code": response.status_code, "findings": findings}
