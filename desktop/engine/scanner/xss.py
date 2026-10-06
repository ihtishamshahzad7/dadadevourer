from __future__ import annotations

import asyncio
import html
import re
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from headers_scanner import fetch, finding, finalize_result
from .models import ScanContext, ScanProfile


MAX_PARAMETERS = 8
MAX_RESPONSE_BYTES = 750_000

# Deliberately inert canaries. They contain HTML metacharacters but no script,
# event handler, javascript: URL, or other executable browser payload.
CANARY_PREFIX = "DADA_XSS_PROBE_"


def _parameter_names(target: str) -> list[str]:
    query = parse_qsl(urlsplit(target).query, keep_blank_values=True)
    seen: set[str] = set()
    names: list[str] = []
    for name, _ in query:
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names[:MAX_PARAMETERS]


def _replace_query_parameter(target: str, parameter: str, value: str) -> str:
    parts = urlsplit(target)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, current in query:
        if name == parameter and not replaced:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, current))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment)
    )


def _reflection_context(body: str, marker: str) -> str:
    """Classify where an inert marker is reflected.

    This is intentionally conservative: a reflected marker is not reported as
    confirmed XSS. The result is a candidate requiring browser/DOM validation.
    """

    index = body.find(marker)
    if index < 0:
        return "none"

    window = body[max(0, index - 700): index + len(marker) + 700]

    if re.search(r"<script\b[^>]*>[^<]{0,700}" + re.escape(marker), window, re.I | re.S):
        return "javascript"

    if re.search(r"(?:href|src|action|formaction|location)\s*=\s*['\"][^'\"]{0,700}"
                 + re.escape(marker), window, re.I | re.S):
        return "attribute"

    if re.search(r"<[a-z][^>]{0,700}" + re.escape(marker), window, re.I | re.S):
        return "html"

    return "text"


def _candidate_description(context: str) -> tuple[str, str]:
    if context == "javascript":
        return (
            "High",
            "The controlled XSS canary was reflected inside a JavaScript context. "
            "This is a strong reflected-XSS candidate, but no executable payload was sent.",
        )
    if context == "attribute":
        return (
            "High",
            "The controlled XSS canary was reflected inside an HTML attribute context. "
            "This is a strong reflected-XSS candidate, but no executable payload was sent.",
        )
    if context == "html":
        return (
            "Medium",
            "The controlled XSS canary was reflected into HTML markup. "
            "This indicates an output-encoding weakness that requires context-specific validation.",
        )
    return (
        "Low",
        "The controlled XSS canary was reflected in the response. "
        "Reflection alone does not prove script execution.",
    )


async def scan(target: str, context: ScanContext) -> dict:
    started = asyncio.get_running_loop().time()
    if context.profile == ScanProfile.PASSIVE:
        raise ValueError("XSS scanning requires the Safe Active or Deep assessment profile")

    parameter_names = _parameter_names(target)
    findings = []

    if not parameter_names:
        findings.append(
            finding(
                "xss:reflected:no_query_parameters",
                "No query parameters available for reflected XSS testing",
                "Info",
                "The supplied target URL does not contain query parameters that can be safely probed by this module.",
                target,
                "Run the XSS module against a discovered endpoint with query parameters or an authenticated application workflow.",
                "OWASP Cross Site Scripting Prevention",
            )
        )
        return finalize_result(target, None, [], findings, started, ["xss:reflected"])

    for parameter in parameter_names:
        marker = f"{CANARY_PREFIX}{uuid.uuid4().hex[:12]}"
        # The probe is intentionally inert: it cannot execute JavaScript.
        probe = f'"><dada-devourer-xss data-probe="{marker}">'
        probe_url = _replace_query_parameter(target, parameter, probe)

        try:
            response, chain = await fetch(probe_url)
        except Exception as exc:
            findings.append(
                finding(
                    "xss:reflected:request_error",
                    f"Reflected XSS probe failed for parameter '{parameter}'",
                    "Info",
                    "The endpoint could not be tested with the controlled XSS canary.",
                    str(exc),
                    "Review endpoint availability and rerun the authorized assessment.",
                    "DadaDevourer",
                )
            )
            continue

        body = response.text[:MAX_RESPONSE_BYTES]
        if marker not in body:
            continue

        context_name = _reflection_context(body, marker)
        severity, description = _candidate_description(context_name)

        # Evidence is deliberately bounded and does not include the full page.
        evidence = {
            "parameter": parameter,
            "context": context_name,
            "marker": marker,
            "status_code": response.status_code,
            "final_url": str(response.url),
        }
        findings.append(
            finding(
                f"xss:reflected:{parameter}",
                "Potential reflected XSS",
                severity,
                description,
                str(evidence),
                "Apply context-appropriate output encoding and validate untrusted input before rendering. "
                "Use a browser/DOM validation step before treating this as confirmed XSS.",
                "CWE-79 / OWASP A03",
            )
        )

    return finalize_result(
        target,
        None,
        [],
        findings,
        started,
        ["xss:reflected"],
    )
