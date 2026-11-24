"""Installation diagnostics for the component packages."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from importlib import import_module, metadata
from importlib.resources import files
from types import ModuleType
from typing import TextIO
import argparse
import json
import sys

from .components import COMPONENTS, Component


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    command: str
    module: str
    available: bool
    version: str | None
    error: str | None


def _module_version(module: ModuleType, component: Component) -> str | None:
    direct = getattr(module, "__version__", None)
    if direct is not None:
        return str(direct)

    package_name = component.module.partition(".")[0]
    try:
        package = import_module(package_name)
    except ImportError:
        package = None
    if package is not None:
        package_version = getattr(package, "__version__", None)
        if package_version is not None:
            return str(package_version)

    for distribution in component.distributions:
        try:
            return metadata.version(distribution)
        except metadata.PackageNotFoundError:
            continue
    return None


def inspect_component(
    component: Component,
    *,
    importer: Callable[[str], ModuleType] = import_module,
    version_resolver: Callable[[ModuleType, Component], str | None] = _module_version,
) -> ComponentHealth:
    try:
        module = importer(component.module)
        entrypoint = getattr(module, "main", None)
        if not callable(entrypoint):
            raise TypeError("callable main(argv) is missing")
        version = version_resolver(module, component)
    except (ImportError, ModuleNotFoundError, TypeError) as exc:
        return ComponentHealth(
            command=component.command,
            module=component.module,
            available=False,
            version=None,
            error=str(exc),
        )
    return ComponentHealth(
        command=component.command,
        module=component.module,
        available=True,
        version=version,
        error=None,
    )


def collect_health() -> list[ComponentHealth]:
    return [inspect_component(component) for component in COMPONENTS.values()]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goad doctor",
        description="Проверить установку четырёх модулей.",
    )
    parser.add_argument("--json", action="store_true", help="вывести результат в JSON")
    return parser


def doctor_main(
    argv: list[str],
    *,
    stdout: TextIO = sys.stdout,
    health_provider: Callable[[], Iterable[ComponentHealth]] = collect_health,
) -> int:
    if any(token in {"-h", "--help"} for token in argv):
        help_text = files("goad").joinpath("doctor_help.txt").read_text(encoding="utf-8-sig")
        print(help_text.rstrip(), file=stdout)
        return 0
    args = _parser().parse_args(argv)
    health = list(health_provider())

    if args.json:
        json.dump(
            {"components": [asdict(item) for item in health]},
            stdout,
            ensure_ascii=False,
            indent=2,
        )
        stdout.write("\n")
    else:
        for item in health:
            if item.available:
                version = item.version or "unknown"
                print(f"{item.command}: OK ({item.module}, version {version})", file=stdout)
            else:
                print(f"{item.command}: MISSING ({item.module}: {item.error})", file=stdout)

    return 0 if all(item.available for item in health) else 1

