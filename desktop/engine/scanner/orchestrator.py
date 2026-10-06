from __future__ import annotations

from headers_scanner import headers_scan, tech_scan, run as legacy_run, tls_scan

from .models import ScanContext, ScanProfile, ScannerCommand
from .xss import scan as xss_scan
from .registry import ScannerModule, ScannerRegistry


async def _headers(target: str, context: ScanContext) -> dict:
    context.report("headers")
    return await headers_scan(target)


async def _tls(target: str, context: ScanContext) -> dict:
    context.report("tls")
    return await tls_scan(target)


async def _technology(target: str, context: ScanContext) -> dict:
    context.report("technology")
    return await tech_scan(target)


async def _assessment(target: str, context: ScanContext) -> dict:
    context.report("assessment")
    return await legacy_run("assessment_scan", target, context.report)


async def _xss(target: str, context: ScanContext) -> dict:
    context.report("xss")
    return await xss_scan(target, context)


def build_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    registry.register(
        ScannerModule(
            ScannerCommand.HEADERS,
            "HTTP Security Headers",
            "HTTP response headers, cookies and application-layer configuration.",
            "passive",
            _headers,
        )
    )
    registry.register(
        ScannerModule(
            ScannerCommand.TLS,
            "TLS",
            "TLS protocol and certificate observations.",
            "passive",
            _tls,
        )
    )
    registry.register(
        ScannerModule(
            ScannerCommand.TECHNOLOGY,
            "Technology",
            "Technology and application fingerprint observations.",
            "passive",
            _technology,
        )
    )
    registry.register(
        ScannerModule(
            ScannerCommand.ASSESSMENT,
            "Assessment",
            "Existing combined assessment, retained for compatibility during migration.",
            "passive",
            _assessment,
        )
    )
    registry.register(
        ScannerModule(
            ScannerCommand.XSS,
            "Reflected XSS",
            "Controlled reflected-XSS canary testing for URL query parameters.",
            "safe_active",
            _xss,
        )
    )
    return registry


REGISTRY = build_registry()


async def run(command: str, target: str, progress=None, profile: str = "passive") -> dict:
    """Run a registered scanner without changing the legacy result contract."""

    _ = legacy_run
    try:
        scan_profile = ScanProfile(profile)
    except ValueError as exc:
        raise ValueError(f"Unsupported scan profile: {profile}") from exc
    context = ScanContext(target=target, profile=scan_profile, progress=progress)
    context.options["profile"] = scan_profile.value
    module = REGISTRY.get(command)
    if scan_profile.value == "passive" and module.minimum_profile != "passive":
        raise ValueError(f"{module.name} requires the {module.minimum_profile} assessment profile")
    return await module.handler(target, context)
