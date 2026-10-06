"""DadaDevourer scanner architecture.

The scanner package provides the stable orchestration boundary used by the
desktop sidecar. Individual assessment modules can be added without changing
the JSON-lines protocol or desktop integration.
"""
from .models import ScanContext, ScanProfile, ScannerCommand
from .orchestrator import run

__all__ = ["ScanContext", "ScanProfile", "ScannerCommand", "run"]
