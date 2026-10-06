from __future__ import annotations

from headers_scanner import (
    assessment_scan,
    headers_scan,
    tech_scan,
    run as legacy_run,
    tls_scan,
)

from .models import ScanContext, ScannerCommand
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
    return await assessment_scan(target)


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
    return registry


REGISTRY = build_registry()


async def run(command: str, target: str, progress=None, profile: str = "passive") -> dict:
    """Run a registered scanner without changing the legacy result contract."""

    _ = legacy_run
    context = ScanContext(target=target, progress=progress)
    context.options["profile"] = profile
    module = REGISTRY.get(command)
    return await module.handler(target, context)
