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
ALLOWED_PORTS = {80, 443}


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP(S) targets are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Target URLs must not contain credentials")
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise ValueError("Only ports 80 and 443 are allowed")
    infos = socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)
    if not infos:
        raise ValueError("Target hostname could not be resolved")
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (address.is_private or address.is_loopback or address.is_link_local or
                address.is_reserved or address.is_multicast or address.is_unspecified):
            raise ValueError("Only publicly routable HTTP(S) targets are allowed")


async def run(url: str) -> dict:
    validate_target_url(url)
    current_url = url
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for _ in range(5):
            validate_target_url(current_url)
            response = await client.get(current_url)
            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("location")
            if not location:
                break
            current_url = str(response.url.join(location))
        else:
            raise ValueError("Too many redirects")
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = [{"check": h, "severity": s, "status": "present" if h in headers else "missing", "value": headers.get(h)} for h, s in REQUIRED.items()]
    return {"url": str(response.url), "status_code": response.status_code, "findings": findings}
