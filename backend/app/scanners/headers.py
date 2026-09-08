import ipaddress
import socket
from urllib.parse import urlparse
import httpx

REQUIRED = {
    "content-security-policy": "High",
    "strict-transport-security": "High",
    "x-content-type-options": "Medium",
    "x-frame-options": "Medium",
    "referrer-policy": "Low",
    "permissions-policy": "Low",
}

def is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            address = ipaddress.ip_address(info[4][0])
            if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                return False
        return True
    except (ValueError, socket.gaierror):
        return False

async def run(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not is_public_host(parsed.hostname):
        raise ValueError("Only publicly routable HTTP(S) targets are allowed")
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        response = await client.get(url)
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = [{"check": header, "severity": severity, "status": "present" if header in headers else "missing", "value": headers.get(header)} for header, severity in REQUIRED.items()]
    return {"url": str(response.url), "status_code": response.status_code, "findings": findings}
