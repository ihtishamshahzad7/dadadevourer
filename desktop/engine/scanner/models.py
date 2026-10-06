from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ScanProfile(str, Enum):
    """Safety/authorization profile for an assessment."""

    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    DEEP = "deep"


class ScannerCommand(str, Enum):
    HEADERS = "headers_scan"
    TLS = "tls_scan"
    TECHNOLOGY = "tech_scan"
    ASSESSMENT = "assessment_scan"
    XSS = "xss_scan"


ProgressCallback = Callable[[str], None]


@dataclass(slots=True)
class ScanContext:
    """Immutable-ish context shared by scanner modules."""

    target: str
    profile: ScanProfile = ScanProfile.PASSIVE
    progress: ProgressCallback | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def report(self, module: str) -> None:
        if self.progress:
            self.progress(module)
