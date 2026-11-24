from __future__ import annotations

import os
import shutil
from pathlib import Path


class ToolError(RuntimeError):
    pass


def resolve_executable(executable: str) -> str:
    value = executable.strip()
    if not value:
        raise ToolError("executable name is empty")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ToolError("invalid executable name")
    candidate = Path(value)
    if candidate.parent != Path("."):
        if candidate.is_file():
            return str(candidate.resolve())
        raise ToolError(f"executable not found: {value}")
    for local_candidate in _local_executable_candidates(value):
        if local_candidate.is_file() and (
            os.name == "nt" or os.access(local_candidate, os.X_OK)
        ):
            return str(local_candidate.resolve())
    resolved = shutil.which(value)
    if not resolved:
        raise ToolError(f"executable not found locally or in PATH: {value}")
    return resolved


def _local_executable_candidates(value: str) -> list[Path]:
    """Prefer the project-local tool folders, then let PATH handle the rest."""
    tool_name = Path(value).stem
    if Path(value).suffix:
        filenames = [value]
    elif os.name == "nt":
        filenames = [f"{value}.exe", value]
    else:
        filenames = [value]
    roots = [Path.cwd(), Path(__file__).resolve().parents[3]]
    candidates: list[Path] = []
    for root in dict.fromkeys(roots):
        candidates.extend(root / tool_name / filename for filename in filenames)
    return candidates
