from __future__ import annotations

import asyncio
import json
import re
import uuid
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from headers_scanner import fetch, finding, finalize_result
from .models import ScanContext, ScanProfile

MAX_PARAMETERS = 12
MAX_FORMS = 12
MAX_RESPONSE_BYTES = 750_000
MAX_SCRIPT_BYTES = 400_000
CANARY_PREFIX = "DADA_XSS_PROBE_"

SOURCE_PATTERNS = {
    "location": r"\b(?:window\.)?(?:location(?:\.(?:search|hash|href|pathname))?|document\.URL|document\.documentURI|document\.baseURI|document\.referrer|window\.name)\b",
    "storage": r"\b(?:localStorage|sessionStorage|indexedDB)\b",
    "cookie": r"\bdocument\.cookie\b",
    "history": r"\b(?:history\.state|history\.pushState|history\.replaceState)\b",
    "message": r"\b(?:event\.)?data\b.*(?:addEventListener\s*\(\s*[\"\']message|onmessage)",
    "url_parameters": r"\b(?:URLSearchParams|location\.search|location\.hash)\b",
}
SINK_PATTERNS = {
    "innerHTML": r"\b(?:innerHTML|outerHTML)\s*=",
    "document.write": r"\bdocument\.write(?:ln)?\s*\(",
    "insertAdjacentHTML": r"\binsertAdjacentHTML\s*\(",
    "DOMParser": r"\bDOMParser\s*\(\).*\.parseFromString\s*\(",
    "createContextualFragment": r"\bcreateContextualFragment\s*\(",
    "setHTMLUnsafe": r"\.(?:setHTMLUnsafe|setHTML)\s*\(",
    "srcdoc": r"\bsrcdoc\s*=",
    "eval": r"\beval\s*\(",
    "Function": r"\bFunction\s*\(",
    "setTimeout": r"\bsetTimeout\s*\(",
    "setInterval": r"\bsetInterval\s*\(",
    "location": r"\b(?:window\.)?location\.(?:href|assign|replace)\s*=",
    "javascript URL": r"[\"\']javascript:\\s*",
    "dangerous setAttribute": r"\bsetAttribute\s*\(\s*[\"\'](?:on[a-z]+|src|href|action|formaction|style|srcdoc)[\"\']",
}

class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.current: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): (str(v) if v is not None else "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            if len(self.forms) >= MAX_FORMS:
                self.current = None
                return
            self.current = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
        elif self.current is not None and tag in {"input", "textarea", "select"}:
            name = a.get("name", "").strip()
            if name:
                self.current["inputs"].append({
                    "name": name,
                    "type": a.get("type", "text").lower(),
                    "value": a.get("value", ""),
                })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None

def _parameter_names(target: str) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True):
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names[:MAX_PARAMETERS]

def _replace_query_parameter(target: str, parameter: str, value: str) -> str:
    parts = urlsplit(target)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated = []
    for name, current in query:
        if name == parameter and not replaced:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, current))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment))

def _reflection_context(body: str, marker: str) -> str:
    index = body.find(marker)
    if index < 0:
        return "none"
    window = body[max(0, index - 1000): index + len(marker) + 1000]
    if re.search(r"<script\b[^>]*>[^<]{0,1000}" + re.escape(marker), window, re.I | re.S):
        return "javascript"
    if re.search(r"<[a-z][^>]*\s+[a-z_:][-a-z0-9_:.]*\s*=\s*[^>]*" + re.escape(marker), window, re.I | re.S):
        return "attribute"
    if re.search(r"<style\b[^>]*>[^<]{0,1000}" + re.escape(marker), window, re.I | re.S):
        return "css"
    if re.search(r"<!--[^>]{0,1000}" + re.escape(marker), window, re.I | re.S):
        return "comment"
    if re.search(r"<[^>]*" + re.escape(marker), window, re.I | re.S):
        return "html"
    return "text"

def _candidate(marker: str, parameter: str, context_name: str, status: int, final_url: str, mode: str):
    severity = {"javascript":"High", "attribute":"High", "html":"Medium", "css":"Medium", "comment":"Low", "text":"Low"}.get(context_name, "Low")
    return finding(
        f"xss:{mode}:{parameter}",
        "Potential reflected XSS",
        severity,
        f"A controlled XSS canary was reflected in {context_name} context. Reflection is not treated as confirmed script execution.",
        json.dumps({"parameter": parameter, "context": context_name, "marker": marker, "status_code": status, "final_url": final_url, "mode": mode}),
        "Apply context-appropriate output encoding/sanitization. Use browser confirmation before treating this as confirmed XSS.",
        "CWE-79 / OWASP A03",
    )

def _forms(html: str) -> list[dict]:
    parser = _FormParser()
    parser.feed(html[:MAX_RESPONSE_BYTES])
    return parser.forms

def _safe_form(form: dict) -> bool:
    blob = json.dumps(form).lower()
    return not any(word in blob for word in ("logout", "delete", "destroy", "remove", "deactivate"))

async def _reflected_get(target: str, findings: list):
    names = _parameter_names(target)
    for parameter in names:
        marker = f"{CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
        probe = f'"><dada-devourer-xss data-probe="{marker}">'
        try:
            response, _ = await fetch(_replace_query_parameter(target, parameter, probe))
        except Exception:
            continue
        body = response.text[:MAX_RESPONSE_BYTES]
        if marker in body:
            findings.append(_candidate(marker, parameter, _reflection_context(body, marker), response.status_code, str(response.url), "reflected-get"))

async def _form_probes(target: str, findings: list, deep: bool):
    try:
        response, _ = await fetch(target)
    except Exception:
        return
    if "text/html" not in response.headers.get("content-type", "").lower():
        return
    for index, form in enumerate(_forms(response.text), 1):
        if not _safe_form(form) or not form["inputs"]:
            continue
        action = urljoin(str(response.url), form["action"] or str(response.url))
        marker = f"{CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
        data = {}
        for field in form["inputs"]:
            if field["type"] in {"submit", "button", "checkbox", "radio", "file", "hidden"}:
                data[field["name"]] = field["value"] or "1"
            else:
                data[field["name"]] = f'"><dada-devourer-xss data-probe="{marker}">'
        try:
            if form["method"] == "get":
                parts = urlsplit(action)
                query = parse_qsl(parts.query, keep_blank_values=True)
                probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query + list(data.items())), parts.fragment))
                checked, _ = await fetch(probe_url)
            elif deep:
                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True) as client:
                    checked = await client.post(action, data=data, headers={"User-Agent": "DadaDevourer/0.3 authorized-assessment"})
            else:
                continue
        except Exception:
            continue
        body = checked.text[:MAX_RESPONSE_BYTES]
        if marker in body:
            context_name = _reflection_context(body, marker)
            findings.append(_candidate(marker, f"form#{index}", context_name, checked.status_code, str(checked.url), "form-post" if form["method"] == "post" else "form-get"))
        elif form["method"] == "post" and deep:
            findings.append(finding(
                f"xss:stored:candidate:{index}",
                "Stored-XSS input point requires follow-up verification",
                "Info",
                "An authorized POST form accepted a controlled XSS canary without immediate reflection. This may represent a stored-XSS input point, but persistence was not proven automatically.",
                json.dumps({"form": index, "action": action, "method": form["method"], "marker": marker}),
                "Revisit the affected resource/workflow and verify whether the canary is rendered later. Avoid treating this observation as confirmed XSS.",
                "CWE-79 / OWASP Stored XSS",
            ))

async def _dom_analysis(target: str, html: str, findings: list):
    scripts = re.findall(r"<script\b[^>]*\bsrc=[\\\"']([^\\\"']+)[\\\"'][^>]*>", html, re.I)[:20]
    inline = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.I | re.S)
    sources = [name for name, pattern in SOURCE_PATTERNS.items() if re.search(pattern, html, re.I | re.S)]
    scripts_data: list[tuple[str, str]] = [(str(target), s) for s in inline]
    for src in scripts:
        try:
            response, _ = await fetch(urljoin(target, src))
            scripts_data.append((str(response.url), response.text[:MAX_SCRIPT_BYTES]))
        except Exception:
            continue
    for source_url, script in scripts_data:
        source_hits = [name for name, pattern in SOURCE_PATTERNS.items() if re.search(pattern, script, re.I | re.S)]
        sink_hits = [name for name, pattern in SINK_PATTERNS.items() if re.search(pattern, script, re.I | re.S)]
        if source_hits and sink_hits:
            findings.append(finding(
                "xss:dom:source-sink",
                "Potential DOM XSS source-to-sink flow",
                "Medium",
                "Client-side JavaScript contains an untrusted-input source and a dangerous DOM/code sink. Static analysis cannot prove data flow or exploitability.",
                json.dumps({"script": source_url, "sources": source_hits, "sinks": sink_hits}),
                "Trace the source-to-sink data flow and use safe DOM APIs, context-aware encoding, sanitization, and Trusted Types where appropriate.",
                "CWE-79 / OWASP DOM XSS",
            ))
        elif sink_hits:
            findings.append(finding(
                "xss:dom:dangerous-sink",
                "Dangerous DOM/code sink detected",
                "Low",
                "Client-side JavaScript uses a DOM or code-execution sink that requires review for attacker-controlled input.",
                json.dumps({"script": source_url, "sinks": sink_hits, "detected_sources": sources}),
                "Review data flow into the sink; prefer textContent/safe DOM APIs and avoid eval-like execution.",
                "OWASP DOM XSS",
            ))
    if re.search(r"require-trusted-types-for\s+[\"']script[\"']", html, re.I):
        findings.append(finding("xss:control:trusted-types", "Trusted Types enforcement detected", "Info", "The page advertises Trusted Types enforcement for script sinks.", "Content-Security-Policy", "Keep Trusted Types policies narrowly scoped and audited.", "OWASP XSS Prevention"))
    else:
        findings.append(finding("xss:control:trusted-types-missing", "Trusted Types enforcement not detected", "Info", "Trusted Types was not detected. This is a defense-in-depth observation, not proof of XSS.", None, "Consider require-trusted-types-for 'script' for applications with meaningful DOM XSS risk.", "OWASP XSS Prevention"))

def _browser_executable() -> str | None:
    import os
    import shutil
    candidates = [shutil.which("msedge"), shutil.which("chrome"),
        os.environ.get("PROGRAMFILES", "") + r"\Microsoft\Edge\Application\msedge.exe",
        os.environ.get("PROGRAMFILES(X86)", "") + r"\\Microsoft\\Edge\\Application\\msedge.exe",
        os.environ.get("LOCALAPPDATA", "") + r"\Google\Chrome\Application\chrome.exe",
        os.environ.get("PROGRAMFILES", "") + r"\\Google\\Chrome\\Application\\chrome.exe"]
    for path in candidates:
        if path:
            try:
                if os.path.isfile(path): return path
            except OSError: pass
    return None

async def _browser_confirm(target: str, findings: list):
    try:
        from playwright.async_api import async_playwright
    except Exception:
        findings.append(finding("xss:browser:unavailable", "Browser confirmation unavailable", "Info", "Playwright is not available in this scanner build, so browser execution confirmation was skipped.", None, "Use a scanner build containing Playwright and a supported Chromium browser.", "DadaDevourer"))
        return
    parameter_names = _parameter_names(target)
    marker = f"{CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
    html_payload = f"<img src=x onerror=window.__DADA_XSS_PROBE__='{marker}'>"
    executable = _browser_executable()
    try:
        async with async_playwright() as p:
            launch_args = {"headless": True}
            if executable: launch_args["executable_path"] = executable
            browser = await p.chromium.launch(**launch_args)
            page = await browser.new_page(); confirmed = False
            for parameter in parameter_names:
                await page.goto(_replace_query_parameter(target, parameter, html_payload), wait_until="domcontentloaded", timeout=15000)
                if await page.evaluate("window.__DADA_XSS_PROBE__ || null") == marker:
                    findings.append(finding("xss:browser:confirmed", "Reflected XSS confirmed by browser execution", "High", "A controlled, non-exfiltrating XSS probe executed in a real Chromium-family browser.", json.dumps({"marker": marker, "parameter": parameter, "url": page.url, "browser": executable or "playwright chromium"}), "Fix the vulnerable output context and retest with browser confirmation.", "CWE-79 / OWASP A03"))
                    confirmed = True; break
            if not confirmed:
                dom_marker = f"{CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
                await page.goto(target, wait_until="domcontentloaded", timeout=15000)
                await page.evaluate("(value) => { location.hash = value; }", dom_marker)
                await page.wait_for_timeout(250)
                if await page.evaluate("window.__DADA_XSS_PROBE__ || null") == dom_marker:
                    findings.append(finding("xss:dom:browser-confirmed", "DOM XSS confirmed by browser execution", "High", "A controlled fragment canary reached an executable DOM sink in a real browser context.", json.dumps({"marker": dom_marker, "url": page.url, "browser": executable or "playwright chromium"}), "Trace the fragment source to the DOM sink and replace the unsafe sink with a safe DOM API or appropriate sanitization.", "CWE-79 / OWASP DOM XSS"))
            await browser.close()
    except Exception as exc:
        findings.append(finding("xss:browser:error", "Browser XSS confirmation could not complete", "Info", "The browser-based confirmation step could not complete; no confirmed XSS was recorded from this step.", str(exc), "Verify that Microsoft Edge/Chrome is installed or provide a compatible Playwright Chromium runtime, then rerun.", "DadaDevourer"))

async def scan(target: str, context: ScanContext) -> dict:
    started = asyncio.get_running_loop().time()
    if context.profile == ScanProfile.PASSIVE:
        raise ValueError("XSS scanning requires the Safe Active or Deep assessment profile")
    findings = []
    await _reflected_get(target, findings)
    try:
        response, _ = await fetch(target)
        html = response.text[:MAX_RESPONSE_BYTES] if "text/html" in response.headers.get("content-type", "").lower() else ""
    except Exception:
        html = ""
    if html:
        await _form_probes(target, findings, context.profile == ScanProfile.DEEP)
        await _dom_analysis(target, html, findings)
    if context.options.get("browser_confirmation", True):
        await _browser_confirm(target, findings)
    if not findings:
        findings.append(finding("xss:assessment:no-evidence", "No XSS evidence detected by enabled checks", "Info", "The XSS module completed its enabled reflected, form, DOM static, and browser checks without identifying evidence.", None, "Continue testing authenticated, stateful, stored, API, and client-side workflows where applicable.", "OWASP XSS"))
    return finalize_result(target, None, [], findings, started, ["xss:reflected-get", "xss:forms", "xss:dom", "xss:browser"])
