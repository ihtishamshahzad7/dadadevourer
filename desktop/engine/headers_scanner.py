import asyncio, json, socket, ssl
from urllib.parse import urlparse, urljoin
import httpx

REQUIRED = {
    "content-security-policy": ("High", "Restricts executable content and reduces XSS impact."),
    "strict-transport-security": ("High", "Enforces HTTPS for supporting clients."),
    "x-content-type-options": ("Medium", "Reduces MIME sniffing."),
    "x-frame-options": ("Medium", "Reduces framing/clickjacking exposure."),
    "referrer-policy": ("Low", "Controls referrer information leakage."),
    "permissions-policy": ("Low", "Restricts browser feature access."),
}
REDIRECTS={301,302,303,307,308}
ALLOWED_PORTS={80,443}

def validate_target_url(url:str)->None:
    parsed=urlparse(url)
    if parsed.scheme not in {"http","https"} or not parsed.hostname: raise ValueError("Only HTTP(S) targets are allowed")
    if parsed.username or parsed.password: raise ValueError("Target URLs must not contain credentials")
    if parsed.port and parsed.port not in ALLOWED_PORTS: raise ValueError("Only ports 80 and 443 are allowed")
    socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme=="https" else 80), type=socket.SOCK_STREAM)

async def fetch(url:str):
    validate_target_url(url); current=url; chain=[]
    timeout=httpx.Timeout(10.0,connect=5.0)
    async with httpx.AsyncClient(follow_redirects=False,timeout=timeout,headers={"User-Agent":"DadaDevourer/0.2 authorized-assessment"}) as client:
        for _ in range(6):
            validate_target_url(current); response=await client.get(current)
            chain.append({"url":str(response.url),"status_code":response.status_code})
            if response.status_code not in REDIRECTS: return response,chain
            location=response.headers.get("location")
            if not location: return response,chain
            current=urljoin(str(response.url),location)
        raise ValueError("Too many redirects")
    return response,chain

async def headers_scan(url:str)->dict:
    response,chain=await fetch(url); headers={k.lower():v for k,v in response.headers.items()}
    findings=[]
    for name,(severity,description) in REQUIRED.items():
        present=name in headers
        findings.append({"check":"security-header:"+name,"title":f"Security header {name}","severity":severity if not present else "Informational","status":"present" if present else "missing","description":description,"evidence":headers.get(name),"recommendation":f"Configure {name} according to the application's security requirements." if not present else "Keep the header reviewed and aligned with application behavior.","value":headers.get(name)})
    cookies=headers.get("set-cookie","")
    if cookies:
        for token,severity in [("secure","Medium"),("httponly","Medium"),("samesite","Low")]:
            if token not in cookies.lower():
                findings.append({"check":"cookie:"+token,"title":f"Cookie attribute {token}","severity":severity,"status":"review","description":f"Observed Set-Cookie response does not clearly include {token}.","evidence":cookies[:1000],"recommendation":f"Review session cookies and add {token} where appropriate.","value":cookies[:1000]})
    if response.url.scheme=="http":
        findings.append({"check":"transport:https","title":"HTTPS not enforced","severity":"High","status":"review","description":"The final URL uses HTTP.","evidence":str(response.url),"recommendation":"Serve sensitive application traffic over HTTPS and redirect HTTP to HTTPS where appropriate.","value":str(response.url)})
    return {"url":str(response.url),"status_code":response.status_code,"redirect_chain":chain,"findings":findings}

async def tls_scan(url:str)->dict:
    validate_target_url(url); parsed=urlparse(url); host=parsed.hostname
    if parsed.scheme!="https": return {"url":url,"status_code":None,"findings":[{"check":"tls:transport","title":"TLS not evaluated","severity":"Informational","status":"not-applicable","description":"The target URL is HTTP.","recommendation":"Use HTTPS for sensitive applications."}]}
    port=parsed.port or 443
    ctx=ssl.create_default_context()
    with socket.create_connection((host,port),timeout=5) as raw:
        with ctx.wrap_socket(raw,server_hostname=host) as s:
            cert=s.getpeercert(); cipher=s.cipher(); version=s.version(); subject=cert.get("subject",()); issuer=cert.get("issuer",())
    findings=[]
    if version in {"TLSv1","TLSv1.1"}: findings.append({"check":"tls:protocol","title":"Legacy TLS protocol","severity":"High","status":"detected","description":"A legacy TLS protocol was negotiated.","evidence":version,"recommendation":"Disable legacy TLS protocols and prefer TLS 1.2 or newer.","value":version})
    else: findings.append({"check":"tls:protocol","title":"TLS protocol","severity":"Informational","status":"detected","description":"Negotiated TLS protocol.","evidence":version,"recommendation":"Keep TLS configuration current.","value":version})
    findings.append({"check":"tls:cipher","title":"Negotiated TLS cipher","severity":"Informational","status":"detected","description":"Cipher negotiated during the assessment connection.","evidence":str(cipher),"value":str(cipher)})
    findings.append({"check":"tls:certificate","title":"Certificate presented","severity":"Informational","status":"detected","description":"The server presented a certificate.","evidence":str({"subject":subject,"issuer":issuer,"expires":cert.get("notAfter")}),"value":cert.get("notAfter")})
    return {"url":url,"status_code":None,"findings":findings}

async def tech_scan(url:str)->dict:
    response,_=await fetch(url); headers={k.lower():v for k,v in response.headers.items()}
    findings=[]
    server=headers.get("server")
    powered=headers.get("x-powered-by")
    if server: findings.append({"check":"technology:server","title":"Web server disclosure","severity":"Low","status":"detected","description":"The Server response header discloses server information.","evidence":server,"recommendation":"Minimize unnecessary version disclosure where practical.","value":server})
    if powered: findings.append({"check":"technology:powered-by","title":"Framework disclosure","severity":"Low","status":"detected","description":"The X-Powered-By response header discloses implementation information.","evidence":powered,"recommendation":"Remove unnecessary framework/version disclosure where practical.","value":powered})
    return {"url":str(response.url),"status_code":response.status_code,"findings":findings}

async def run(command:str,target:str)->dict:
    if command=="headers_scan": return await headers_scan(target)
    if command=="tls_scan": return await tls_scan(target)
    if command=="tech_scan": return await tech_scan(target)
    if command=="assessment_scan":
        results=[]
        for fn in (headers_scan,tls_scan,tech_scan):
            try: results.append(await fn(target))
            except Exception as exc: results.append({"findings":[{"check":"scanner:error","title":"Scanner module error","severity":"Informational","status":"error","description":str(exc),"value":str(exc)}]})
        findings=[f for r in results for f in r.get("findings",[])]
        first=results[0] if results else {}
        return {"url":first.get("url",target),"status_code":first.get("status_code"),"findings":findings,"modules":["headers","tls","technology"]}
    raise ValueError("Unsupported scanner command")
