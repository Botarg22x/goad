"""Load the editable command-line help bundled with the package."""

from __future__ import annotations

from importlib.resources import files


HELP_RESOURCE = "data/cli_help.txt"


def load_cli_help() -> str:
    """Return the UTF-8 CLI help text shipped as a package resource."""

    return files("logingen").joinpath(HELP_RESOURCE).read_text(encoding="utf-8")


__all__ = ["HELP_RESOURCE", "load_cli_help"]
