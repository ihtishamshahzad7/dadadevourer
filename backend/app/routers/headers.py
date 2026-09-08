import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

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
        return all(not (ipaddress.ip_address(i[4][0]).is_private or ipaddress.ip_address(i[4][0]).is_loopback or ipaddress.ip_address(i[4][0]).is_link_local) for i in infos)
    except (ValueError, socket.gaierror):
        return False

@router.post("")
async def scan_headers(data: HeaderScanRequest):
    url = str(data.url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise HTTPException(400, "Only publicly routable HTTP(S) targets are allowed")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Target request failed: {exc}")
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    for header, severity in REQUIRED.items():
        present = header in headers
        findings.append({"header": header, "severity": severity, "status": "present" if present else "missing", "value": headers.get(header)})
    return {"url": str(response.url), "status_code": response.status_code, "findings": findings}
