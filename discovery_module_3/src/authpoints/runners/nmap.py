from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from pathlib import Path

from ..config import NmapConfig
from ..normalize import normalize_hostname
from .common import ToolError, resolve_executable


def build_nmap_command(
    config: NmapConfig,
    targets: list[str],
    *,
    ipv6: bool = False,
    udp: bool = False,
    input_file: Path | None = None,
) -> list[str]:
    if not targets:
        raise ValueError("Nmap requires at least one target")
    if not 1 <= config.top_ports <= 65535:
        raise ValueError("top_ports must be between 1 and 65535")
    if config.timeout_seconds < 1:
        raise ValueError("Nmap timeout must be positive")
    if not 0 <= config.timing_template <= 5:
        raise ValueError("Nmap timing template must be between 0 and 5")
    for target in targets:
        _validate_nmap_target(target)
    executable = resolve_executable(config.executable)
    version_db = resolve_nmap_version_db(config, executable=executable)
    command = [executable]
    if ipv6:
        command.append("-6")
    if udp:
        command.append("-sU")
    command.extend(
        [
            "-sV",
            "--version-light",
            "--versiondb",
            str(version_db),
        ]
    )
    if config.all_ports:
        command.append("-p-")
    else:
        command.extend(("--top-ports", str(config.top_ports)))
    command.extend(
        [
            f"-T{config.timing_template}",
            "--no-stylesheet",
            "--noninteractive",
            "-oX",
            "-",
        ]
    )
    if input_file is not None:
        command.extend(("-iL", str(input_file)))
    else:
        command.extend(targets)
    return command


def run_nmap(
    config: NmapConfig,
    targets: list[str],
    *,
    ipv6: bool = False,
    udp: bool = False,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="authpoints-nmap-") as directory:
        input_file = Path(directory) / "targets.txt"
        input_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command = build_nmap_command(
            config,
            targets,
            ipv6=ipv6,
            udp=udp,
            input_file=input_file,
        )
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=nmap_environment(Path(directory)),
                cwd=directory,
                timeout=config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"Nmap timed out after {config.timeout_seconds} seconds") from exc
        except OSError as exc:
            raise ToolError(f"could not start Nmap: {exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()[:2000]
        raise ToolError(f"Nmap exited with code {result.returncode}: {stderr}")
    if not result.stdout.strip():
        raise ToolError("Nmap returned an empty XML document")
    return result.stdout


def resolve_nmap_version_db(
    config: NmapConfig,
    *,
    executable: str | None = None,
) -> Path:
    if config.version_db:
        configured = Path(config.version_db).expanduser().resolve()
        if configured.is_file():
            return configured
        raise ToolError(f"Nmap version probes file not found: {configured}")

    resolved_executable = Path(
        executable or resolve_executable(config.executable)
    ).resolve()
    candidates = [
        resolved_executable.parent / "nmap-service-probes",
        resolved_executable.parent.parent / "share" / "nmap" / "nmap-service-probes",
        Path("/usr/share/nmap/nmap-service-probes"),
        Path("/usr/local/share/nmap/nmap-service-probes"),
        Path("/opt/homebrew/share/nmap/nmap-service-probes"),
        Path("/opt/local/share/nmap/nmap-service-probes"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ToolError(
        "trusted nmap-service-probes was not found; use --nmap-versiondb"
    )


def nmap_environment(isolated_root: Path) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("NMAP")
    }
    home = isolated_root / "home"
    xdg_config = isolated_root / "xdg-config"
    app_data = isolated_root / "app-data"
    local_app_data = isolated_root / "local-app-data"
    for path in (home, xdg_config, app_data, local_app_data):
        path.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(xdg_config),
            "APPDATA": str(app_data),
            "LOCALAPPDATA": str(local_app_data),
        }
    )
    return environment


def partition_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    ipv4_or_hostnames: list[str] = []
    ipv6: list[str] = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            ipv4_or_hostnames.append(target)
            continue
        if network.version == 6:
            ipv6.append(target)
        else:
            ipv4_or_hostnames.append(target)
    return ipv4_or_hostnames, ipv6


def _validate_nmap_target(target: str) -> None:
    value = target.strip()
    if not value or value != target or value.startswith("-"):
        raise ValueError("invalid Nmap target")
    if "-" in value and re.fullmatch(r"[0-9.-]+", value):
        raise ValueError("Nmap octet ranges are unsupported; use CIDR")
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        if "/" in value or "://" in value:
            raise ValueError("invalid Nmap target") from None
        try:
            normalize_hostname(value)
        except ValueError as exc:
            raise ValueError("invalid Nmap target") from exc
