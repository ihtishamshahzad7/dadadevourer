from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from .models import ScanContext, ScannerCommand


ScanHandler = Callable[[str, ScanContext], Awaitable[dict]]


@dataclass(frozen=True, slots=True)
class ScannerModule:
    command: ScannerCommand
    name: str
    description: str
    minimum_profile: str
    handler: ScanHandler


class ScannerRegistry:
    """Central command registry for independently testable scanner modules."""

    def __init__(self) -> None:
        self._modules: dict[ScannerCommand, ScannerModule] = {}

    def register(self, module: ScannerModule) -> None:
        if module.command in self._modules:
            raise ValueError(f"Scanner command already registered: {module.command.value}")
        self._modules[module.command] = module

    def get(self, command: str | ScannerCommand) -> ScannerModule:
        key = command if isinstance(command, ScannerCommand) else ScannerCommand(command)
        try:
            return self._modules[key]
        except KeyError as exc:
            raise ValueError(f"Unsupported scanner command: {key.value}") from exc

    def commands(self) -> tuple[ScannerCommand, ...]:
        return tuple(self._modules)
