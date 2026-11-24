from __future__ import annotations

import ipaddress
import subprocess
import tempfile
from pathlib import Path

from ..config import SubfinderConfig
from ..normalize import normalize_hostname
from .common import ToolError, resolve_executable


def build_subfinder_command(
    config: SubfinderConfig,
    domains: list[str],
    *,
    input_file: Path,
) -> list[str]:
    if not domains:
        raise ValueError("Subfinder requires at least one domain")
    if config.timeout_seconds < 1:
        raise ValueError("Subfinder timeout must be positive")
    if config.rate_limit_per_second < 1:
        raise ValueError("Subfinder rate limit must be positive")
    if not 1 <= config.max_results <= 5000:
        raise ValueError("Subfinder max results must be between 1 and 5000")
    normalized_domains = [_valid_domain(domain) for domain in domains]
    input_file.write_text("\n".join(normalized_domains) + "\n", encoding="utf-8")
    command = [
        resolve_executable(config.executable),
        "-silent",
        "-nc",
        "-duc",
        "-dL",
        str(input_file),
        "-rl",
        str(config.rate_limit_per_second),
    ]
    if config.all_sources:
        command.append("-all")
    if config.proxy:
        command.extend(("-proxy", config.proxy))
    return command


def run_subfinder(config: SubfinderConfig, domains: list[str]) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="authpoints-subfinder-") as directory:
        root = Path(directory)
        input_file = root / "domains.txt"
        command = build_subfinder_command(config, domains, input_file=input_file)
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=root,
                timeout=config.timeout_seconds,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(
                f"Subfinder timed out after {config.timeout_seconds} seconds"
            ) from exc
        except OSError as exc:
            raise ToolError(f"could not start Subfinder: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip()[:2000]
        raise ToolError(f"Subfinder exited with code {result.returncode}: {detail}")
    return parse_subfinder_output(
        result.stdout,
        domains=domains,
        max_results=config.max_results,
    )


def parse_subfinder_output(
    output: str,
    *,
    domains: list[str],
    max_results: int,
) -> list[str]:
    roots = tuple(_valid_domain(domain) for domain in domains)
    results: list[str] = []
    for raw_line in output.splitlines():
        value = raw_line.strip().rstrip(".").lower()
        if not value or value.startswith("["):
            continue
        try:
            host = normalize_hostname(value)
        except ValueError:
            continue
        if host in roots or not any(host.endswith("." + root) for root in roots):
            continue
        if host not in results:
            results.append(host)
        if len(results) >= max_results:
            break
    return results


def _valid_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("Subfinder accepts domain names, not IP addresses")
    host = normalize_hostname(candidate)
    if host == "localhost" or "." not in host:
        raise ValueError("Subfinder requires a qualified domain name")
    return host
