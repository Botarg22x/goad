from __future__ import annotations

import platform
import re
import subprocess
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import NmapConfig
from .runners.common import ToolError, resolve_executable
from .runners.katana import katana_environment
from .runners.nmap import resolve_nmap_version_db


MINIMUM_KATANA_VERSION = (1, 6, 1)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(slots=True)
class ToolStatus:
    name: str
    available: bool
    path: str = ""
    version: str = ""
    error: str = ""


def check_environment(
    nmap_executable: str,
    katana_executable: str,
    nmap_version_db: str = "",
    subfinder_executable: str = "subfinder",
) -> dict[str, object]:
    nmap_status = _check_tool("nmap", nmap_executable, ["--version"])
    if nmap_status.available:
        try:
            resolve_nmap_version_db(
                NmapConfig(
                    executable=nmap_status.path,
                    version_db=nmap_version_db,
                ),
                executable=nmap_status.path,
            )
        except (OSError, ToolError) as exc:
            nmap_status.available = False
            nmap_status.error = str(exc)
    katana_status = _check_tool("katana", katana_executable, ["-version"])
    subfinder_status = _check_tool(
        "subfinder", subfinder_executable, ["-version"]
    )
    tools = [nmap_status, katana_status, subfinder_status]
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "tools": [asdict(tool) for tool in tools],
        "ready": all(tool.available for tool in tools),
    }


def _check_tool(name: str, executable: str, version_args: list[str]) -> ToolStatus:
    try:
        resolved = resolve_executable(executable)
    except ToolError as exc:
        return ToolStatus(name=name, available=False, error=str(exc))
    try:
        with ExitStack() as stack:
            environment = None
            working_directory = None
            if name == "katana":
                directory = Path(
                    stack.enter_context(
                        tempfile.TemporaryDirectory(prefix="authpoints-katana-version-")
                    )
                )
                environment = katana_environment(directory)
                working_directory = directory
            result = subprocess.run(
                [resolved, *version_args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                cwd=working_directory,
                timeout=10,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolStatus(name=name, available=False, path=resolved, error=str(exc))
    version = _ANSI_ESCAPE.sub(
        "",
        next((line.strip() for line in result.stdout.splitlines() if line.strip()), ""),
    )[:300]
    compatible = True
    compatibility_error = ""
    if name == "katana" and result.returncode == 0:
        parsed_version = _parse_version(result.stdout)
        if parsed_version is not None and parsed_version < MINIMUM_KATANA_VERSION:
            compatible = False
            compatibility_error = "Katana 1.6.1 or newer is required"
    return ToolStatus(
        name=name,
        available=result.returncode == 0 and compatible,
        path=resolved,
        version=version,
        error=(
            compatibility_error
            if compatibility_error
            else ""
            if result.returncode == 0
            else f"exit code {result.returncode}"
        ),
    )


def _parse_version(output: str) -> tuple[int, int, int] | None:
    match = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", output, flags=re.IGNORECASE)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]
