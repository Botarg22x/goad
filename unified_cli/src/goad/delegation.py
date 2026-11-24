"""Lazy delegation to component CLI modules."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from types import ModuleType
from typing import Any, TextIO
import sys

from .components import Component


class DelegationError(RuntimeError):
    """A component cannot be loaded or does not expose the CLI contract."""


Importer = Callable[[str], ModuleType]


def _exit_code(value: Any, *, stderr: TextIO) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    raise DelegationError(
        "component main(argv) must return int or None, "
        f"got {type(value).__name__}"
    )


def _system_exit_code(value: Any, *, stderr: TextIO) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    print(value, file=stderr)
    return 1


def delegate(
    component: Component,
    argv: list[str],
    *,
    importer: Importer = import_module,
    stderr: TextIO = sys.stderr,
) -> int:
    """Import *component* on demand and invoke its ``main(argv)`` contract.

    ``argv`` is passed as the same list object. No wrapper parsing, normalization,
    or token rewriting occurs.
    """

    try:
        module = importer(component.module)
    except (ImportError, ModuleNotFoundError) as exc:
        raise DelegationError(
            f"cannot import {component.module!r} for {component.command!r}: {exc}"
        ) from exc

    entrypoint = getattr(module, "main", None)
    if not callable(entrypoint):
        raise DelegationError(
            f"{component.module!r} does not expose callable main(argv)"
        )

    try:
        return _exit_code(entrypoint(argv), stderr=stderr)
    except SystemExit as exc:
        return _system_exit_code(exc.code, stderr=stderr)

