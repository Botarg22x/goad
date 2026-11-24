"""Compatibility entry point for ``python passgen.py`` and ``python -m passgen``."""

from __future__ import annotations

from collections.abc import Sequence

from password_generator.cli import main as _cli_main


def main(argv: Sequence[str] | None = None) -> int:
    return _cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
