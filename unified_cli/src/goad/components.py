"""Static component registry used by delegation, doctor, and orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class Component:
    command: str
    module: str
    distributions: tuple[str, ...]
    description: str


_COMPONENTS = {
    "passwords": Component(
        command="passwords",
        module="password_generator.cli",
        distributions=("password-generator", "password_generator"),
        description="Generate password candidates",
    ),
    "logins": Component(
        command="logins",
        module="logingen.cli",
        distributions=("logingen",),
        description="Collect names and emails; optionally generate login candidates",
    ),
    "discover": Component(
        command="discover",
        module="authpoints.cli",
        distributions=("pointfinder", "authpoints"),
        description="Discover authentication entry points",
    ),
    "check": Component(
        command="check",
        module="authchecker.cli",
        distributions=("authchecker",),
        description="Check credential candidates",
    ),
}

COMPONENTS: Mapping[str, Component] = MappingProxyType(_COMPONENTS)
STAGE_ORDER: tuple[str, ...] = tuple(_COMPONENTS)

