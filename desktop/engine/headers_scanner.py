import asyncio, re, socket, ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse
import httpx

ALLOWED_PORTS = {80, 443}
REDIRECTS = {301, 302, 303, 307, 308}
UA = "DadaDevourer/0.3 authorized-assessment"

def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP(S) targets are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Target URLs must not contain credentials")
    if parsed.port and parsed.port not in ALLOWED_PORTS:
        raise ValueError("Only ports 80 and 443 are allowed")
    socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)

async def fetch(url: str, *, origin: str | None = None):
    validate_target_url(url)
    current, chain = url, []
    timeout = httpx.Timeout(10.0, connect=5.0)
    headers = {"User-Agent": UA}
    if origin:
        headers["Origin"] = origin
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, headers=headers) as client:
        for _ in range(6):
            validate_target_url(current)
            response = await client.get(current)
            chain.append({"url": str(response.url), "status_code": response.status_code})
            if response.status_code not in REDIRECTS:
                return response, chain
            location = response.headers.get("location")
            if not location:
                return response, chain
            current = urljoin(str(response.url), location)
    raise ValueError("Too many redirects")

def finding(check, title, severity, description, evidence=None, recommendation="", reference="OWASP"):
    return {
        "check": check, "title": title, "severity": severity, "status": "open",
        "description": description, "evidence": evidence,
        "recommendation": recommendation, "reference": reference,
    }

def informational(check, title, description, evidence=None, recommendation="", reference="OWASP"):
    return finding(check, title, "Info", description, evidence, recommendation, reference)

def header_value(headers, name):
    return headers.get(name.lower())

def parse_set_cookie(headers):
    cookies = []
    for raw in headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else True for p in parts[1:]}
        cookies.append((name, attrs, raw[:1200]))
    return cookies

def looks_like_session(name):
    return bool(re.search(r"(session|sess|auth|token|jwt|sid|login|identity|access|refresh)", name, re.I))

def parse_max_age(value):
    m = re.search(r"max-age\s*=\s*(\d+)", value or "", re.I)
    return int(m.group(1)) if m else None

def is_html(response):
    return "text/html" in response.headers.get("content-type", "").lower()

def analyze_html(url, body):
    findings = []
    lower = body.lower()
    password_fields = re.findall(r"<input\b[^>]*type\s*=\s*[\"']?password[^>]*>", body, re.I)
    if password_fields:
        for field in password_fields[:5]:
            if not re.search(r"autocomplete\s*=\s*[\"']?off[\"']?", field, re.I):
                findings.append(finding("authentication:password_autocomplete", "Password field missing autocomplete=off", "Low",
                    "A login password field was detected without an explicit autocomplete=off attribute.",
                    field[:500], "Review browser password-autofill behavior for the login flow.", "OWASP ASVS"))
                break
        findings.append(informational("authentication:login_page", "Login page detected",
            "The response contains a password input field.", url, "Review the authentication flow and apply appropriate security controls.", "OWASP Authentication"))
    external_scripts = re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"'](https?://[^\"']+)[\"'][^>]*>", body, re.I)
    missing_sri = [src for src in external_scripts if not re.search(r"\bintegrity\s*=", re.search(r"<script\b[^>]*\bsrc\s*=\s*[\"']"+re.escape(src)+r"[\"'][^>]*>", body, re.I).group(0), re.I)]
    if missing_sri:
        findings.append(finding("content:external_script_sri", "External scripts without Subresource Integrity", "Medium",
            "External JavaScript resources were detected without an integrity attribute.",
            "\n".join(missing_sri[:10]), "Add SRI hashes for externally hosted scripts where practical.", "OWASP / SRI"))
    mixed = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)", body, re.I)
    if mixed and "upgrade-insecure-requests" not in lower:
        findings.append(finding("transport:mixed_content", "Potential mixed content", "Medium",
            "The HTTPS page references HTTP resources and does not advertise upgrade-insecure-requests.",
            "\n".join(mixed[:10]), "Serve page resources over HTTPS and consider CSP upgrade-insecure-requests.", "OWASP Transport Layer Protection"))
    versions = re.findall(r"(?:jquery(?:\.min)?\.js|jquery)[^\"'\s<>]*?(\d+\.\d+(?:\.\d+)?)", body, re.I)
    if versions:
        version = versions[0]
        findings.append(informational("content:jquery_version", "jQuery version detected", f"A jQuery version was detected in page resources.", version, "Review the detected version against current vendor security advisories.", "Retire.js"))
    generators = re.findall(r"<meta[^>]+name\s*=\s*[\"']generator[\"'][^>]+content\s*=\s*[\"']([^\"']+)", body, re.I)
    for generator in generators[:3]:
        findings.append(finding("technology:generator", "Technology generator disclosure", "Low",
            "A meta generator value discloses application technology information.", generator, "Minimize unnecessary implementation disclosure where practical.", "OWASP Information Exposure"))
    return findings

def header_findings(response, chain, body):
    h = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    csp = h.get("content-security-policy")
    if not csp:
        findings.append(finding("security_header:content_security_policy", "Content-Security-Policy missing", "High",
            "The response does not define a Content-Security-Policy header.", None,
            "Deploy a restrictive CSP appropriate to the application.", "OWASP Secure Headers"))
    else:
        if re.search(r"unsafe-inline", csp, re.I) and not re.search(r"nonce-[^\s;']+", csp, re.I):
            findings.append(finding("security_header:csp_unsafe_inline", "CSP allows unsafe-inline", "Medium",
                "The Content-Security-Policy contains unsafe-inline without a detectable nonce.",
                csp, "Replace inline execution with nonces or hashes where practical.", "OWASP CSP"))
        if re.search(r"unsafe-eval", csp, re.I):
            findings.append(finding("security_header:csp_unsafe_eval", "CSP allows unsafe-eval", "Medium",
                "The Content-Security-Policy contains unsafe-eval.", csp, "Remove unsafe-eval unless explicitly required and risk-assessed.", "OWASP CSP"))
    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append(finding("security_header:hsts", "Strict-Transport-Security missing", "High",
            "The response does not advertise HTTP Strict Transport Security.", None, "Enable HSTS on HTTPS responses with an appropriate max-age.", "RFC 6797"))
    else:
        age = parse_max_age(hsts)
        if age is not None and age < 15552000:
            findings.append(finding("security_header:hsts_short_max_age", "HSTS max-age is below 180 days", "Medium",
                "The configured HSTS max-age is shorter than the requested baseline.", hsts, "Use an HSTS max-age of at least 180 days after validating deployment.", "RFC 6797"))
        if "includesubdomains" not in hsts.lower():
            findings.append(finding("security_header:hsts_subdomains", "HSTS lacks includeSubDomains", "Low",
                "HSTS does not include subdomains.", hsts, "Add includeSubDomains when all subdomains are HTTPS-ready.", "RFC 6797"))
        if "preload" not in hsts.lower():
            findings.append(informational("security_header:hsts_preload", "HSTS preload directive not present",
                "The HSTS header does not advertise preload.", hsts, "Consider preload only after meeting preload requirements.", "hstspreload.org"))
    xfo = h.get("x-frame-options")
    if not xfo:
        findings.append(finding("security_header:x_frame_options", "X-Frame-Options missing", "Medium",
            "The response lacks X-Frame-Options.", None, "Use CSP frame-ancestors and/or X-Frame-Options according to browser compatibility needs.", "OWASP Clickjacking Defense"))
    elif "allow-from" in xfo.lower():
        findings.append(finding("security_header:x_frame_allow_from", "Deprecated X-Frame-Options ALLOW-FROM", "Low",
            "X-Frame-Options uses the deprecated ALLOW-FROM directive.", xfo, "Prefer CSP frame-ancestors.", "MDN X-Frame-Options"))
    xcto = h.get("x-content-type-options")
    if not xcto:
        findings.append(finding("security_header:x_content_type_options", "X-Content-Type-Options missing", "Low",
            "The response lacks X-Content-Type-Options.", None, "Set X-Content-Type-Options: nosniff.", "OWASP Secure Headers"))
    elif xcto.lower().strip() != "nosniff":
        findings.append(finding("security_header:x_content_type_options_value", "X-Content-Type-Options is not nosniff", "Low",
            "X-Content-Type-Options is present but does not equal nosniff.", xcto, "Set the value to nosniff.", "OWASP Secure Headers"))
    referrer = h.get("referrer-policy")
    if not referrer:
        findings.append(finding("security_header:referrer_policy", "Referrer-Policy missing", "Low",
            "The response lacks Referrer-Policy.", None, "Set a deliberate Referrer-Policy such as strict-origin-when-cross-origin.", "OWASP Secure Headers"))
    elif re.search(r"unsafe-url|no-referrer-when-downgrade", referrer, re.I):
        findings.append(finding("security_header:referrer_policy_weak", "Weak Referrer-Policy", "Low",
            "The Referrer-Policy permits broader referrer disclosure than modern restrictive policies.", referrer, "Use a restrictive modern policy.", "MDN Referrer-Policy"))
    permissions = h.get("permissions-policy")
    if not permissions:
        findings.append(finding("security_header:permissions_policy", "Permissions-Policy missing", "Low",
            "The response does not define Permissions-Policy.", None, "Restrict browser capabilities not required by the application.", "MDN Permissions-Policy"))
    else:
        findings.append(informational("security_header:permissions_detected", "Permissions-Policy detected",
            "Permissions-Policy directives were detected.", permissions, "Review the allowed features against application requirements.", "MDN Permissions-Policy"))
    xss = h.get("x-xss-protection")
    if xss:
        findings.append(informational("security_header:x_xss_protection", "Deprecated X-XSS-Protection header present",
            "X-XSS-Protection is deprecated but remains present.", xss, "Prefer modern browser protections such as CSP.", "OWASP Secure Headers"))
    else:
        findings.append(informational("security_header:x_xss_protection_missing", "X-XSS-Protection missing",
            "X-XSS-Protection is not present. This legacy header is informational only.", None, "Do not add it solely as a modern security control.", "OWASP Secure Headers"))
    if "cross-origin-opener-policy" not in h:
        findings.append(finding("security_header:coop", "Cross-Origin-Opener-Policy missing", "Low",
            "The response lacks Cross-Origin-Opener-Policy.", None, "Set an appropriate COOP policy where isolation is required.", "OWASP Secure Headers"))
    if "cross-origin-resource-policy" not in h:
        findings.append(informational("security_header:corp", "Cross-Origin-Resource-Policy missing",
            "The response lacks Cross-Origin-Resource-Policy.", None, "Consider an appropriate CORP policy for cross-origin resource isolation.", "OWASP Secure Headers"))
    cache = h.get("cache-control", "")
    if re.search(r"(login|account|session|admin|dashboard|profile)", urlparse(str(response.url)).path, re.I) and "no-store" not in cache.lower():
        findings.append(finding("security_header:cache_control", "Sensitive page lacks no-store", "Low",
            "The assessed sensitive-looking URL does not advertise Cache-Control: no-store.", cache or None, "Use no-store for responses containing sensitive user or session data.", "OWASP Session Management"))
    cookies = parse_set_cookie(response.headers)
    for name, attrs, raw in cookies:
        if looks_like_session(name) and "secure" not in attrs:
            findings.append(finding("cookie:secure", "Session cookie missing Secure flag", "High",
                "A session-like cookie was observed without the Secure attribute.", name, "Set Secure on cookies carrying session or authentication state.", "OWASP Cookie Security"))
        if looks_like_session(name) and "httponly" not in attrs:
            findings.append(finding("cookie:httponly", "Session cookie missing HttpOnly flag", "High",
                "A session-like cookie was observed without HttpOnly.", name, "Set HttpOnly on cookies that do not need JavaScript access.", "OWASP Cookie Security"))
        if looks_like_session(name) and "samesite" not in attrs:
            findings.append(finding("cookie:samesite", "Session cookie missing SameSite", "Medium",
                "A session-like cookie was observed without SameSite.", name, "Set an appropriate SameSite policy.", "OWASP Cookie Security"))
        if not (name.startswith("__Host-") or name.startswith("__Secure-")) and looks_like_session(name):
            findings.append(informational("cookie:prefix", "Session cookie lacks a __Host- or __Secure- prefix",
                "A session-like cookie does not use a cookie prefix.", name, "Consider __Host- or __Secure- prefixes where their requirements can be met.", "MDN Secure Cookie Configuration"))
    server = h.get("server")
    if server:
        severity = "Medium" if re.search(r"/\d|\b\d+\.\d+", server) else "Info"
        findings.append(finding("disclosure:server", "Server header reveals implementation", severity,
            "The Server response header discloses server information.", server, "Minimize unnecessary server/version disclosure where practical.", "OWASP Information Exposure"))
    powered = h.get("x-powered-by")
    if powered:
        findings.append(finding("disclosure:x_powered_by", "X-Powered-By header present", "Medium",
            "The response discloses implementation details through X-Powered-By.", powered, "Remove unnecessary X-Powered-By disclosure.", "OWASP Information Exposure"))
    for name, severity in [("x-aspnet-version","Medium"),("x-generator","Low")]:
        if h.get(name):
            findings.append(finding(f"disclosure:{name.replace('-', '_')}", f"{name} header present", severity,
                f"The response exposes the {name} header.", h[name], "Remove unnecessary implementation disclosure.", "OWASP Information Exposure"))
    if "retry-after" not in h and not any(k.lower().startswith("x-ratelimit-") for k in h):
        findings.append(informational("rate_limit:headers", "Rate-limit response headers not detected",
            "No Retry-After or X-RateLimit-* response header was observed on the assessed request.", None, "Consider documenting rate limiting and exposing useful response headers where appropriate.", "OWASP API Security"))
    if is_html(response) and body:
        findings.extend(analyze_html(str(response.url), body))
    if response.status_code >= 500 and re.search(r"(traceback|stack trace|exception|at [\w.$]+\(|/var/www/|c:\\|\.cs:\d+|\.java:\d+)", body, re.I):
        findings.append(finding("error_pages:stack_trace", "Error page reveals stack-trace details", "High",
            "A server error response contains patterns associated with stack traces or local file paths.", body[:1500], "Return generic error pages and keep detailed diagnostics server-side.", "OWASP Error Handling"))
    return findings

async def common_content_checks(base_url, body):
    findings=[]
    parsed=urlparse(base_url)
    for path, check, label in [
        ("/robots.txt","content:robots","robots.txt"),
        ("/.well-known/security.txt","content:security_txt","security.txt"),
        ("/sitemap.xml","content:sitemap","sitemap.xml"),
    ]:
        try:
            response,_=await fetch(urljoin(base_url,path))
            text=response.text[:200000]
            if response.status_code == 200:
                if label=="robots.txt":
                    sensitive=[line.strip() for line in text.splitlines() if re.search(r"disallow:\s*/(?:admin|api|internal|private|backup)",line,re.I)]
                    if sensitive:
                        findings.append(informational(check,"robots.txt discloses sensitive paths","robots.txt contains disallowed sensitive-looking paths.", "\n".join(sensitive[:10]), "Review whether these paths should be disclosed publicly.", "OWASP Information Exposure"))
                elif label=="security.txt":
                    findings.append(informational(check,"security.txt present","A security.txt file is published.",urljoin(base_url,path),"Keep contact and policy details current.","RFC 9116"))
                else:
                    urls=len(re.findall(r"<(?:loc|url)\b",text,re.I))
                    findings.append(informational(check,"sitemap.xml present","A sitemap.xml file is published.",f"{urls} URL entries detected.","Review whether the sitemap exposes only intended public URLs.","Sitemaps protocol"))
            elif label=="security.txt":
                findings.append(informational(check,"security.txt missing","No /.well-known/security.txt file was detected.",urljoin(base_url,path),"Publish security.txt if the project uses coordinated vulnerability disclosure.","RFC 9116"))
        except Exception:
            continue
    return findings

async def cors_check(url):
    try:
        response,_=await fetch(url, origin="https://evil.example.com")
        allow_origin=response.headers.get("access-control-allow-origin")
        allow_credentials=response.headers.get("access-control-allow-credentials","").lower()=="true"
        if allow_origin=="*" and allow_credentials:
            return [finding("cors:wildcard_credentials","CORS wildcard with credentials enabled","Critical",
                "The response combines Access-Control-Allow-Origin: * with credential allowance.", f"Allow-Origin: {allow_origin}; Allow-Credentials: true", "Use an explicit trusted origin and avoid credentialed wildcard CORS.", "OWASP CORS")]
        if allow_origin=="*":
            return [finding("cors:wildcard","CORS allows any origin","Medium","The response allows requests from arbitrary origins.",allow_origin,"Restrict allowed origins to the application's trusted origins.","OWASP CORS")]
        if allow_origin and allow_origin.lower()=="https://evil.example.com":
            return [finding("cors:origin_reflection","CORS reflects an untrusted Origin","High","The server reflected the assessment Origin header.",allow_origin,"Use a strict allowlist of trusted origins.","OWASP CORS")]
    except Exception:
        pass
    return []

async def http_redirect_checks(url, chain):
    findings=[]
    parsed=urlparse(url)
    if parsed.scheme=="http":
        if any(urlparse(x["url"]).scheme=="https" for x in chain):
            first=chain[0]["status_code"] if chain else None
            if first==302:
                findings.append(finding("redirect:http_https_302","HTTP to HTTPS uses a temporary redirect","Low","HTTP redirects to HTTPS with status 302."," -> ".join(f'{x["status_code"]} {x["url"]}' for x in chain),"Use a permanent redirect such as 301 after validating the application.","OWASP Transport Layer Protection"))
            else:
                findings.append(informational("redirect:http_https","HTTP redirects to HTTPS","The target redirects HTTP traffic to HTTPS.", " -> ".join(f'{x["status_code"]} {x["url"]}' for x in chain), "Keep the HTTPS redirect enforced.","OWASP Transport Layer Protection"))
        else:
            findings.append(finding("redirect:http_https_missing","HTTP to HTTPS redirect missing","High","The assessed HTTP target did not redirect to HTTPS.",str(chain),"Redirect sensitive HTTP traffic to HTTPS.","OWASP Transport Layer Protection"))
    return findings

async def headers_scan(url: str) -> dict:
    started=asyncio.get_running_loop().time()
    response,chain=await fetch(url)
    body=response.text[:500000] if is_html(response) else ""
    findings=header_findings(response,chain,body)
    findings.extend(await http_redirect_checks(url,chain))
    findings.extend(await cors_check(str(response.url)))
    findings.extend(await common_content_checks(str(response.url),body))
    return finalize_result(str(response.url),response.status_code,chain,findings,started,["headers"])

def cert_days_left(not_after):
    try:
        dt=parsedate_to_datetime(not_after)
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        return (dt.astimezone(timezone.utc)-datetime.now(timezone.utc)).total_seconds()/86400
    except Exception:
        return None

async def tls_scan(url: str) -> dict:
    started=asyncio.get_running_loop().time()
    validate_target_url(url); parsed=urlparse(url); host=parsed.hostname
    if parsed.scheme!="https":
        return finalize_result(url,None,[],[informational("tls:transport","TLS not evaluated","The target URL uses HTTP.",url,"Use HTTPS for sensitive applications.","OWASP Transport Layer Protection")],started,["tls"])
    port=parsed.port or 443
    findings=[]
    cert=None
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as raw:
            with ctx.wrap_socket(raw,server_hostname=host) as s:
                cert=s.getpeercert(); cipher=s.cipher(); version=s.version(); cert_der=s.getpeercert(binary_form=True)
        if version=="TLSv1.0":
            findings.append(finding("tls:version_1_0","TLS 1.0 supported","Critical","The assessment connection negotiated TLS 1.0.",version,"Disable TLS 1.0.","RFC 8996"))
        elif version=="TLSv1.1":
            findings.append(finding("tls:version_1_1","TLS 1.1 supported","High","The assessment connection negotiated TLS 1.1.",version,"Disable TLS 1.1 and prefer TLS 1.2 or newer.","RFC 8996"))
        elif version=="TLSv1.2":
            findings.append(informational("tls:version_1_2","TLS 1.2 negotiated","TLS 1.2 was negotiated successfully.",version,"Keep TLS 1.2 enabled while adopting TLS 1.3 where supported.","RFC 8996"))
        elif version=="TLSv1.3":
            findings.append(informational("tls:version_1_3","TLS 1.3 negotiated","TLS 1.3 was negotiated successfully.",version,"Keep TLS 1.3 enabled.","RFC 8446"))
        cipher_name=(cipher[0] if cipher else "")
        if re.search(r"RC4|3DES|DES|NULL|EXPORT",cipher_name,re.I):
            findings.append(finding("tls:weak_cipher","Weak cipher suite negotiated","Critical","The assessment connection negotiated a weak or obsolete cipher suite.",str(cipher),"Disable obsolete cipher suites and prefer modern AEAD suites.","OWASP TLS Cheat Sheet"))
        else:
            findings.append(informational("tls:cipher","Negotiated TLS cipher","The assessment connection negotiated a modern cipher suite.",str(cipher),"Keep cipher configuration aligned with current TLS guidance.","OWASP TLS Cheat Sheet"))
    except ssl.CertificateError as exc:
        findings.append(finding("tls:hostname_mismatch","Certificate hostname mismatch","Critical","The TLS certificate hostname does not match the target hostname.",str(exc),"Install a certificate valid for the target hostname.","RFC 6125"))
        cert_der=None
    except ssl.SSLError as exc:
        findings.append(finding("tls:connection","TLS connection validation failed","High","The TLS connection could not be validated using the system trust store.",str(exc),"Review certificate, protocol and trust-chain configuration.","OWASP TLS Cheat Sheet"))
        cert_der=None
    if cert:
        subject=dict(x[0] for x in cert.get("subject",()) if x)
        issuer=dict(x[0] for x in cert.get("issuer",()) if x)
        expires=cert.get("notAfter")
        days=cert_days_left(expires)
        if days is not None:
            sev="Critical" if days<=7 else "High" if days<=30 else "Medium" if days<=90 else "Info"
            findings.append(finding("tls:certificate_expiry","Certificate expiry status",sev,
                "The certificate expiry date was evaluated against the assessment date.",f"{expires} ({days:.1f} days remaining)",
                "Renew the certificate before expiry and maintain automated certificate monitoring.","OWASP TLS Cheat Sheet"))
        if subject and issuer and subject==issuer:
            findings.append(finding("tls:self_signed","Self-signed certificate detected","High","The certificate subject and issuer are identical.",str(subject),"Use a certificate chain trusted by intended clients.","OWASP TLS Cheat Sheet"))
        sans=[v for typ,vals in cert.get("subjectAltName",()) for v in [vals] if typ=="DNS"]
        if host and sans and not any(ssl.match_hostname({"subjectAltName":[("DNS",x) for x in sans]},host) is None for _ in [0]):
            pass
        if not cert.get("issuer"):
            findings.append(finding("tls:chain","Certificate chain information incomplete","Medium","The certificate did not expose a complete issuer structure to the scanner.",str(cert),"Serve the complete certificate chain from the TLS endpoint.","OWASP TLS Cheat Sheet"))
        if expires:
            findings.append(informational("tls:certificate","Certificate details","The server presented a certificate.",str({"subject":subject,"issuer":issuer,"expires":expires}),"Keep certificate monitoring current.","OWASP TLS Cheat Sheet"))
    return finalize_result(url,None,[],findings,started,["tls"])

async def tech_scan(url: str) -> dict:
    started=asyncio.get_running_loop().time()
    response,chain=await fetch(url)
    headers={k.lower():v for k,v in response.headers.items()}
    findings=[]
    findings.extend([f for f in header_findings(response,chain,response.text[:300000] if is_html(response) else "") if f["check"].startswith("disclosure:") or f["check"].startswith("content:jquery")])
    if not findings:
        findings.append(informational("technology:none","No technology disclosure detected","No obvious Server, X-Powered-By or jQuery version disclosure was found on the assessed response.",str(response.url),"Review application technology fingerprinting exposure periodically.","OWASP Information Exposure"))
    return finalize_result(str(response.url),response.status_code,chain,findings,started,["technology"])

async def dns_checks(url):
    findings=[]
    host=urlparse(url).hostname
    if not host: return findings
    try:
        import dns.resolver
        resolver=dns.resolver.Resolver()
        resolver.timeout=3; resolver.lifetime=4
        txt=[]
        try:
            for answer in resolver.resolve(host,"TXT"):
                txt.append(b"".join(answer.strings).decode("utf-8","ignore"))
        except Exception: pass
        spf=[x for x in txt if x.lower().startswith("v=spf1")]
        if not spf:
            findings.append(finding("dns:spf_missing","SPF record missing","No SPF TXT record was detected for the target domain.",host,"Publish an SPF policy for domains that send email.","RFC 7208"))
        elif any(re.search(r"\+all\b",x,re.I) for x in spf):
            findings.append(finding("dns:spf_plus_all","SPF uses +all","The SPF record permits all senders.",spf[0],"Replace +all with a restrictive SPF policy.","RFC 7208"))
        else:
            findings.append(informational("dns:spf","SPF record detected","An SPF record was detected.",spf[0],"Review SPF mechanisms periodically.","RFC 7208"))
        dmarc=[]
        try:
            for answer in resolver.resolve("_dmarc."+host,"TXT"):
                dmarc.append(b"".join(answer.strings).decode("utf-8","ignore"))
        except Exception: pass
        if not dmarc:
            findings.append(finding("dns:dmarc_missing","DMARC record missing","No DMARC TXT record was detected.", "_dmarc."+host,"Publish a DMARC policy for domains that send email.","RFC 7489"))
        elif any(re.search(r"\bp=none\b",x,re.I) for x in dmarc):
            findings.append(finding("dns:dmarc_none","DMARC policy is p=none","DMARC is present but configured for monitoring rather than enforcement.",dmarc[0],"Consider moving toward quarantine or reject after validating legitimate mail flows.","RFC 7489"))
        else:
            findings.append(informational("dns:dmarc","DMARC record detected","A DMARC record was detected.",dmarc[0],"Review DMARC alignment and reporting.","RFC 7489"))
    except Exception as exc:
        findings.append(informational("dns:check_unavailable","DNS policy checks unavailable","The optional DNS resolver could not complete SPF/DMARC checks.",str(exc),"Install the bundled DNS dependency for DNS policy assessment.","RFC 7208 / RFC 7489"))
    findings.append(informational("dns:dkim","DKIM not directly detectable","DKIM requires knowledge of the selector used by the sending service.","No selector was supplied.","Validate DKIM separately when an email-sending selector is known.","RFC 6376"))
    return findings

def finalize_result(url,status_code,chain,findings,started,modules):
    counts={k:0 for k in ("critical","high","medium","low","info")}
    normalized=[]
    for item in findings:
        item=dict(item)
        sev=str(item.get("severity","Info")).lower()
        if sev=="informational": sev="info"
        item["severity"]=sev if sev in counts else "info"
        item["status"]=item.get("status") or "open"
        normalized.append(item); counts[item["severity"]]+=1
    return {"url":url,"status_code":status_code,"redirect_chain":chain,"findings":normalized,"modules":modules,
            "summary":{"type":"summary","target":url,"final_url":url,"http_status":status_code,
                       "scan_duration_ms":round((asyncio.get_running_loop().time()-started)*1000),
                       "findings_count":counts}}

async def run(command: str, target: str, progress=None) -> dict:
    if command=="headers_scan":
        if progress: progress("headers")
        result=await headers_scan(target)
    elif command=="tls_scan":
        if progress: progress("tls")
        result=await tls_scan(target)
    elif command=="tech_scan":
        if progress: progress("technology")
        result=await tech_scan(target)
    elif command=="assessment_scan":
        results=[]
        for name,fn in (("headers",headers_scan),("tls",tls_scan),("technology",tech_scan)):
            if progress: progress(name)
            try: results.append(await fn(target))
            except Exception as exc:
                results.append({"findings":[finding("scanner:module_error","Scanner module error","Info","A scanner module returned an error.",str(exc),"Review the module error before relying on scan completeness.","DadaDevourer") ]})
        if progress: progress("dns")
        try: results.append({"findings":await dns_checks(target)})
        except Exception: results.append({"findings":[]})
        findings=[f for r in results for f in r.get("findings",[])]
        first=next((r for r in results if r.get("url")), {})
        return finalize_result(first.get("url",target),first.get("status_code"),first.get("redirect_chain",[]),findings,asyncio.get_running_loop().time(),["headers","tls","technology","dns"])
    else:
        raise ValueError("Unsupported scanner command")
