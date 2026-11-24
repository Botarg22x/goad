"""Top-level console entry point."""

from __future__ import annotations

from collections.abc import Sequence
from importlib.resources import files
from typing import TextIO
import sys

from . import __version__
from .components import COMPONENTS
from .delegation import DelegationError, delegate
from .direct_run import direct_run_main, is_direct_run
from .doctor import doctor_main
from .orchestrator import run_main


_FALLBACK_HELP = """Использование: goad КОМАНДА [АРГУМЕНТЫ...]

Команды:
  passwords   создать passwords.txt
  logins      создать logins.txt
  discover    создать report.json
  check       проверить учётные данные по отчёту модуля 3
  doctor      проверить установку модулей
  run         собрать данные, найти точки входа и проверить цель или файл ссылок

Полная справка временно недоступна.
Используйте 'goad КОМАНДА -h' для справки по отдельной команде.
"""


def _read_help_resource() -> str:
    """Read the user-editable top-level help bundled with the package."""

    return files("goad").joinpath("help.txt").read_text(encoding="utf-8-sig")


def _load_help() -> str:
    """Return editable help or a small built-in fail-safe message."""

    try:
        text = _read_help_resource()
    except (FileNotFoundError, ModuleNotFoundError, OSError, UnicodeError):
        text = _FALLBACK_HELP
    if not text.strip():
        text = _FALLBACK_HELP
    return text.rstrip() + "\n"


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help"}:
        print(_load_help(), file=stdout, end="")
        return 0
    if arguments[0] in {"-V", "--version"}:
        print(f"goad {__version__}", file=stdout)
        return 0

    command = arguments[0]
    command_argv = arguments[1:]
    if command in COMPONENTS:
        try:
            return delegate(COMPONENTS[command], command_argv, stderr=stderr)
        except DelegationError as exc:
            print(f"goad {command}: error: {exc}", file=stderr)
            return 127
    if command == "doctor":
        return doctor_main(command_argv, stdout=stdout)
    if command == "run":
        if is_direct_run(command_argv):
            return direct_run_main(command_argv, stdout=stdout, stderr=stderr)
        return run_main(command_argv, stdout=stdout, stderr=stderr)

    print(f"goad: unknown command: {command}", file=stderr)
    print("Run 'goad --help' for usage.", file=stderr)
    return 2
