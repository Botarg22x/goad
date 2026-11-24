from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..config import (
    DEFAULT_USER_AGENT,
    KatanaConfig,
    validate_proxy_url,
    validate_user_agent,
)
from ..normalize import (
    is_logout_url,
    normalize_hostname,
    normalize_url,
)
from ..models import Issue
from ..parsers.katana_jsonl import MAX_JSONL_LINE, parse_katana_jsonl
from .common import ToolError, resolve_executable


MAX_KATANA_OUTPUT_BYTES = 96 * 1024 * 1024
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_AUTH_NAVIGATION = re.compile(
    r"(?:^|[/_.-])(?:log[-_]?in|logon|sign[-_]?in|"
    r"auth(?:enticate|entication|orize|orization)?|accounts?|sessions?)"
    r"(?:$|[/_.-])",
    re.IGNORECASE,
)
_STATIC_RESOURCE_SUFFIXES = {
    ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg",
    ".js", ".map", ".mp3", ".mp4", ".pdf", ".png", ".svg", ".ttf",
    ".webm", ".webp", ".woff", ".woff2",
}
_DATA_RESOURCE_SUFFIXES = {".json", ".txt", ".webmanifest", ".xml"}
_PAGE_LOAD_STRATEGIES = {
    "domcontentloaded",
    "load",
    "heuristic",
    "networkidle",
    "none",
}
_BLOCKED_ENVIRONMENT_VARIABLES = {
    "AUTH_CREDENTIALS",
    "CAPTCHA_SOLVER_KEY",
    "CAPTCHA_SOLVER_PROVIDER",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
}
class KatanaPartialError(ToolError):
    """A crawl completed with per-page failures and recoverable observations."""

    def __init__(self, output: str, issues: list[Issue]) -> None:
        self.output = output
        self.issues = tuple(issues)
        super().__init__(
            f"Katana crawl was incomplete: {len(issues)} error(s); "
            "successful page results were preserved"
        )


@dataclass(slots=True)
class _KatanaLevelResult:
    pages: list[tuple[str, str]]
    issues: list[Issue]


def build_katana_command(
    config: KatanaConfig,
    *,
    input_file: Path,
    output_file: Path,
    include_subdomains: bool,
    scope_hosts: set[str],
    seeds: list[str] | None = None,
) -> list[str]:
    _validate_katana_config(config)
    executable = resolve_executable(config.executable)
    command = [executable]
    if config.headless and seeds:
        # Katana 1.7 can finish with an empty output when pure headless mode is
        # combined with -list. Repeated -u values keep all candidates in the
        # same browser process and preserve its cookies/session.
        for seed in seeds:
            command.extend(("-u", seed))
    else:
        command.extend(("-list", str(input_file)))
    command.extend(
        (
        "-jsonl",
        "-silent",
        "-nc",
        "-duc",
        "-d",
        str(config.depth if config.headless else 1),
        "-ct",
        config.crawl_duration,
        "-timeout",
        str(config.request_timeout_seconds),
        "-retry",
        "0",
        "-fs",
        katana_field_scope_pattern(
            scope_hosts,
            include_subdomains=include_subdomains,
        ),
        "-c",
        str(config.concurrency),
        "-p",
        str(config.parallelism if config.headless else 1),
        "-rl",
        str(config.rate_limit_per_second),
        "-mdp",
        str(config.max_domain_pages if config.headless else 1),
        "-mrs",
        str(config.max_response_bytes),
        "-cos",
        r"(?i)^https?://[^/?#]*@",
        "-cos",
        r"(?i)/(?:logout|logoff|signout|signoff|end[-_.]?session|disconnect)"
        r"(?:[-_.][a-z0-9]+)*(?:[/?#;]|$)",
        "-fx",
        "-eof",
        "raw",
        "-o",
        str(output_file),
        )
    )
    if not config.headless or config.user_agent != DEFAULT_USER_AGENT:
        command.extend(("-H", f"User-Agent: {validate_user_agent(config.user_agent)}"))
    if config.headless:
        command.extend(
            (
                "-hl",
                "-xhr",
                "-pls",
                config.page_load_strategy,
                "-cdd",
                str(input_file.parent / "chrome-data"),
            )
        )
        if config.page_load_strategy == "domcontentloaded":
            command.extend(("-dwt", str(config.dom_wait_seconds)))
        chromium = resolve_headless_chromium(config, executable)
        if chromium is not None:
            command.extend(("-scp", str(chromium)))
        else:
            command.append("-sc")
    else:
        command.append("-dr")
    for pattern in katana_scope_patterns(scope_hosts, include_subdomains=include_subdomains):
        command.extend(("-cs", pattern))
    if config.proxy:
        proxy = validate_proxy_url(config.proxy)
        command.extend(("-proxy", proxy))
        if config.headless:
            command.extend(("-ho", f"proxy-server={proxy}"))
            if not config.ca_cert:
                command.extend(("-ho", "ignore-certificate-errors"))
    elif config.headless:
        # Chromium also reads the Windows/system proxy configuration. PointFinder
        # must use a proxy only when the operator explicitly supplied --proxy.
        command.extend(("-ho", "no-proxy-server"))
    if config.js_crawl:
        command.append("-jc")
    return command


def run_katana(
    config: KatanaConfig,
    seeds: list[str],
    *,
    include_subdomains: bool,
    scope_hosts: set[str],
    on_progress: Callable[[str], None] | None = None,
) -> str:
    """Crawl safe seeds, retaining completed pages in ``KatanaPartialError``.

    Expected per-page failures do not cancel siblings or later crawl levels.
    Callers must consume both ``output`` and ``issues`` when a crawl is partial.
    """
    if not seeds:
        return ""
    _validate_katana_config(config)
    allowed_hosts = {
        normalize_hostname(host)
        for host in scope_hosts
        if host
    }
    frontier: list[str] = []
    for raw_seed in seeds:
        seed = normalize_url(raw_seed, redact_query=False)
        if "," in seed:
            raise ToolError(
                "Katana seed contains a literal comma and cannot be passed safely"
            )
        safe_seed = _safe_katana_candidate(
            seed,
            allowed_hosts,
            include_subdomains=include_subdomains,
        )
        if safe_seed is not None:
            frontier.append(safe_seed)
    frontier = list(dict.fromkeys(frontier))
    if not frontier:
        return ""
    if config.max_total_pages is not None:
        frontier = frontier[: config.max_total_pages]

    if config.headless:
        _emit(
            on_progress,
            f"[KATANA] Headless Chrome: запуск для {len(frontier)} начальных URL",
        )
        for seed in frontier:
            _emit(on_progress, f"[KATANA] HEADLESS {_display_url(seed)}")
        output = _run_katana_headless(
            config,
            frontier,
            include_subdomains=include_subdomains,
            scope_hosts=allowed_hosts,
            timeout_seconds=float(config.timeout_seconds),
        )
        observations, _errors = parse_katana_jsonl(output)
        for observation in observations:
            if observation.status_code is not None:
                _emit(
                    on_progress,
                    f"[KATANA] HTTP {observation.status_code} "
                    f"{_display_url(observation.url)}",
                )
        _emit(
            on_progress,
            f"[KATANA] Headless-обход завершён: {len(observations)} записей",
        )
        return output

    deadline = time.monotonic() + config.timeout_seconds
    visited: set[str] = set()
    page_counts: defaultdict[str, int] = defaultdict(int)
    chunks: list[str] = []
    issues: list[Issue] = []
    output_size = 0
    total_limit_reached = False
    output_limit_reached = False

    # Use the explicit seed-fetch depth supported by Katana 1.7. Each process
    # remains at that single depth, so Python still validates every URL before
    # scheduling the next crawl level.
    # Python validates discovered records before scheduling the next crawl level.
    for level in range(config.depth):
        # Dict insertion order breaks ties by discovery order. A URL found again
        # as a redirect can improve its priority without losing that order.
        next_frontier: dict[str, int] = {}
        level_seeds: list[str] = []
        for seed in frontier:
            if (
                config.max_total_pages is not None
                and len(visited) >= config.max_total_pages
            ):
                total_limit_reached = True
                break
            if seed in visited:
                continue
            host = normalize_hostname(urlsplit(seed).hostname or "")
            if page_counts[host] >= config.max_domain_pages:
                continue
            visited.add(seed)
            page_counts[host] += 1
            level_seeds.append(seed)

        if not level_seeds:
            break
        _emit(
            on_progress,
            f"[KATANA] Уровень {level + 1}/{config.depth}: "
            f"{len(level_seeds)} страниц",
        )
        level_results = _run_katana_level(
            config,
            level_seeds,
            include_subdomains=include_subdomains,
            scope_hosts=allowed_hosts,
            deadline=deadline,
            on_progress=on_progress,
        )
        issues.extend(level_results.issues)
        for seed, chunk in level_results.pages:
            normalized_chunk = chunk.rstrip("\r\n") + "\n" if chunk else ""
            encoded_size = len(normalized_chunk.encode("utf-8", errors="replace"))
            output_size += encoded_size
            if output_size > MAX_KATANA_OUTPUT_BYTES:
                issue = Issue(
                    stage="katana",
                    target=_display_url(seed),
                    message=(
                        f"Katana output exceeded the {MAX_KATANA_OUTPUT_BYTES}-byte "
                        "safety limit; earlier page results were preserved"
                    ),
                )
                issues.append(issue)
                _emit(on_progress, f"[ERROR] Katana {issue.target}: {issue.message}")
                output_limit_reached = True
                break
            chunks.append(normalized_chunk)

            observations, _errors = parse_katana_jsonl(
                chunk,
                redact_urls=False,
            )
            for observation in observations:
                if observation.method != "GET":
                    continue
                discovered_urls = [
                    (observation.url, False),
                    (observation.redirect_target, True),
                    *((link, False) for link in observation.links),
                ]
                for discovered_url, is_redirect in discovered_urls:
                    if not discovered_url:
                        continue
                    candidate = _safe_katana_candidate(
                        discovered_url,
                        allowed_hosts,
                        include_subdomains=include_subdomains,
                    )
                    if candidate is not None and candidate not in visited:
                        priority = _navigation_priority(candidate, is_redirect=is_redirect)
                        next_frontier[candidate] = min(
                            priority, next_frontier.get(candidate, priority)
                        )
        frontier = sorted(next_frontier, key=next_frontier.__getitem__)
        if output_limit_reached or total_limit_reached or not frontier:
            break
    if total_limit_reached:
        _emit(
            on_progress,
            f"[KATANA] Достигнут общий лимит: {config.max_total_pages} страниц",
        )
    _emit(on_progress, f"[KATANA] Обход завершён: обработано {len(visited)} страниц")
    output = "".join(chunks)
    if issues:
        raise KatanaPartialError(output, issues)
    return output


def _navigation_priority(url: str, *, is_redirect: bool = False) -> int:
    """Prefer login navigation when a small crawl budget cannot cover all links.

    Resources remain eligible: some sites expose real auth endpoints as JSON or
    XML, and explicitly supplied seeds never pass through this ranking step.
    """
    if is_redirect:
        return 0
    parts = urlsplit(url)
    path = unquote(parts.path).lower()
    suffix = Path(path).suffix
    if suffix in _STATIC_RESOURCE_SUFFIXES:
        return 3
    if _AUTH_NAVIGATION.search(path) or _AUTH_NAVIGATION.search(parts.hostname or ""):
        return 1
    if (
        suffix in _DATA_RESOURCE_SUFFIXES
        or path.rsplit("/", 1)[-1] in {"manifest", "opensearch", "robots", "sitemap"}
    ):
        return 3
    return 2


def _run_katana_level(
    config: KatanaConfig,
    seeds: list[str],
    *,
    include_subdomains: bool,
    scope_hosts: set[str],
    deadline: float,
    on_progress: Callable[[str], None] | None = None,
) -> _KatanaLevelResult:
    if not seeds:
        return _KatanaLevelResult(pages=[], issues=[])
    results: dict[str, str] = {}
    issues: list[Issue] = []
    futures: dict[Future[str], str] = {}
    interval = 1.0 / config.rate_limit_per_second
    next_launch = time.monotonic()
    workers = min(config.parallelism, len(seeds))
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="authpoints-katana",
    ) as pool:
        for index, seed in enumerate(seeds):
            delay = next_launch - time.monotonic()
            if delay > 0:
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for unstarted_seed in seeds[index:]:
                    issue = Issue(
                        stage="katana",
                        target=_display_url(unstarted_seed),
                        message=(
                            f"Katana orchestration timed out after "
                            f"{config.timeout_seconds} seconds; page was not started"
                        ),
                    )
                    issues.append(issue)
                    _emit(on_progress, f"[ERROR] Katana {issue.target}: {issue.message}")
                break
            _emit(on_progress, f"[KATANA] GET {_display_url(seed)}")
            future = pool.submit(
                _run_katana_once,
                config,
                seed,
                include_subdomains=include_subdomains,
                scope_hosts=scope_hosts,
                timeout_seconds=remaining,
                allow_empty_output=True,
            )
            futures[future] = seed
            next_launch = time.monotonic() + interval
        for future in as_completed(futures):
            seed = futures[future]
            try:
                chunk = future.result()
                results[seed] = chunk
            except KatanaPartialError as exc:
                chunk = exc.output
                results[seed] = chunk
                issues.extend(
                    replace(issue, target=issue.target or _display_url(seed))
                    for issue in exc.issues
                )
                _emit(on_progress, f"[ERROR] Katana {_display_url(seed)}: {exc}")
            except (ToolError, ValueError) as exc:
                issues.append(
                    Issue(stage="katana", target=_display_url(seed), message=str(exc))
                )
                _emit(on_progress, f"[ERROR] Katana {_display_url(seed)}: {exc}")
                continue
            observations, _errors = parse_katana_jsonl(chunk)
            for observation in observations:
                if observation.method == "GET" and observation.status_code is not None:
                    _emit(
                        on_progress,
                        f"[KATANA] HTTP {observation.status_code} "
                        f"{_display_url(observation.url)}",
                    )
            _emit(on_progress, f"[KATANA] Готово {_display_url(seed)}")
    return _KatanaLevelResult(
        pages=[(seed, results[seed]) for seed in seeds if seed in results],
        issues=issues,
    )


def _display_url(url: str) -> str:
    try:
        return normalize_url(url)
    except ValueError:
        return "<некорректный URL>"


def _emit(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _validate_katana_config(config: KatanaConfig) -> None:
    validate_user_agent(config.user_agent)
    validate_proxy_url(config.proxy)
    if not 1 <= config.depth <= 10:
        raise ValueError("Katana depth must be between 1 and 10")
    if not 1 <= config.parallelism <= 32:
        raise ValueError("Katana parallelism must be between 1 and 32")
    if not 1 <= config.concurrency <= 100:
        raise ValueError("Katana concurrency must be between 1 and 100")
    if config.page_load_strategy not in _PAGE_LOAD_STRATEGIES:
        raise ValueError(
            "Katana page load strategy must be one of: "
            + ", ".join(sorted(_PAGE_LOAD_STRATEGIES))
        )
    if not 0 <= config.dom_wait_seconds <= 120:
        raise ValueError("Katana DOM wait must be between 0 and 120 seconds")
    for name, value in (
        ("timeout_seconds", config.timeout_seconds),
        ("auto_headless_timeout_seconds", config.auto_headless_timeout_seconds),
        ("request_timeout_seconds", config.request_timeout_seconds),
        ("rate_limit_per_second", config.rate_limit_per_second),
        ("max_domain_pages", config.max_domain_pages),
        ("max_response_bytes", config.max_response_bytes),
        ("max_dom_bytes", config.max_dom_bytes),
    ):
        if value < 1:
            raise ValueError(f"Katana {name} must be positive")
    if config.max_total_pages is not None and config.max_total_pages < 1:
        raise ValueError("Katana max_total_pages must be positive")
    if not re.fullmatch(r"[1-9][0-9]*(?:ms|s|m|h)", config.crawl_duration):
        raise ValueError("Katana crawl_duration must use forms such as 500ms, 30s, or 2m")


def _run_katana_once(
    config: KatanaConfig,
    seed: str,
    *,
    include_subdomains: bool,
    scope_hosts: set[str],
    timeout_seconds: float,
    allow_empty_output: bool = False,
) -> str:
    has_control_character = any(
        ord(character) < 0x20 or ord(character) == 0x7F
        for character in seed
    )
    if "," in seed or has_control_character:
        raise ToolError("unsafe Katana seed syntax")
    normalized_scope_hosts = {
        normalize_hostname(host)
        for host in scope_hosts
        if host
    }
    safe_seed = _safe_katana_candidate(
        seed,
        normalized_scope_hosts,
        include_subdomains=include_subdomains,
    )
    if safe_seed is None:
        raise ToolError("Katana seed failed the pre-spawn safety policy")
    return _execute_katana(
        config,
        [safe_seed],
        include_subdomains=include_subdomains,
        scope_hosts=normalized_scope_hosts,
        timeout_seconds=timeout_seconds,
        allow_empty_output=allow_empty_output,
    )


def _run_katana_headless(
    config: KatanaConfig,
    seeds: list[str],
    *,
    include_subdomains: bool,
    scope_hosts: set[str],
    timeout_seconds: float,
) -> str:
    normalized_scope_hosts = {
        normalize_hostname(host)
        for host in scope_hosts
        if host
    }
    safe_seeds: list[str] = []
    for seed in seeds:
        has_control_character = any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in seed
        )
        if "," in seed or has_control_character:
            raise ToolError("unsafe Katana seed syntax")
        candidate = _safe_katana_candidate(
            seed,
            normalized_scope_hosts,
            include_subdomains=include_subdomains,
        )
        if candidate is None:
            raise ToolError("Katana seed failed the pre-spawn safety policy")
        safe_seeds.append(candidate)
    return _execute_katana(
        config,
        list(dict.fromkeys(safe_seeds)),
        include_subdomains=include_subdomains,
        scope_hosts=normalized_scope_hosts,
        timeout_seconds=timeout_seconds,
    )


def _execute_katana(
    config: KatanaConfig,
    seeds: list[str],
    *,
    include_subdomains: bool,
    scope_hosts: set[str],
    timeout_seconds: float,
    allow_empty_output: bool = False,
) -> str:
    with tempfile.TemporaryDirectory(
        prefix="authpoints-katana-",
        ignore_cleanup_errors=True,
    ) as directory:
        directory_path = Path(directory)
        input_file = directory_path / "seeds.txt"
        output_file = directory_path / "results.jsonl"
        if config.headless:
            (directory_path / "chrome-data").mkdir()
        input_file.write_text("\n".join(seeds) + "\n", encoding="utf-8")
        command = build_katana_command(
            config,
            input_file=input_file,
            output_file=output_file,
            include_subdomains=include_subdomains,
            scope_hosts=scope_hosts,
            seeds=seeds,
        )
        try:
            # The browser profile is already isolated by -cdd. Replacing
            # LOCALAPPDATA/HOME as well breaks some installed Chrome builds on
            # Windows: Chrome starts, but Katana receives no page records.
            # Keep the normal OS environment for headless Chrome while still
            # stripping proxy/credential variables in katana_environment().
            isolated_environment_root = None if config.headless else directory_path
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=katana_environment(isolated_environment_root),
                cwd=directory_path,
                timeout=max(0.1, timeout_seconds),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            mode = "headless crawl" if config.headless else "single-page extraction"
            raise _katana_execution_error(
                f"Katana {mode} timed out", seeds=seeds, output_file=output_file
            ) from exc
        except OSError as exc:
            raise ToolError(f"could not start Katana: {exc}") from exc
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        error_detail = _katana_error_detail(stderr)
        if result.returncode != 0:
            detail = f": {error_detail}" if error_detail else ""
            raise _katana_execution_error(
                f"Katana exited with code {result.returncode}{detail}",
                seeds=seeds,
                output_file=output_file,
            )
        error_marker = any(
            marker in stderr.lower()
            for marker in (
                "[err]",
                "[ftl]",
                "could not create runner",
                "could not execute crawling",
            )
        )
        if error_marker:
            detail = f": {error_detail}" if error_detail else ""
            raise _katana_execution_error(
                f"Katana reported an initialization or runtime error{detail}",
                seeds=seeds,
                output_file=output_file,
            )
        if not output_file.exists():
            raise ToolError("Katana produced no output file")
        size = output_file.stat().st_size
        if size == 0:
            # Katana can intentionally suppress an otherwise successful seed
            # (for example robots.txt) through its default extension filter.
            # One filtered page must not discard results from the whole crawl.
            if allow_empty_output:
                return ""
            detail = f": {error_detail}" if error_detail else ""
            raise ToolError(f"Katana produced an empty output file{detail}")
        if size > MAX_KATANA_OUTPUT_BYTES:
            raise _katana_execution_error(
                f"Katana output exceeded the {MAX_KATANA_OUTPUT_BYTES}-byte safety limit",
                seeds=seeds,
                output_file=output_file,
            )
        return output_file.read_text(encoding="utf-8", errors="replace")


def _katana_execution_error(
    message: str,
    *,
    seeds: list[str],
    output_file: Path,
) -> ToolError:
    """Keep bounded, complete JSONL records produced before process failure."""
    try:
        with output_file.open("rb") as stream:
            data = stream.read(MAX_KATANA_OUTPUT_BYTES + 1)
    except FileNotFoundError:
        return ToolError(message)
    except OSError as exc:
        return ToolError(f"{message}; could not recover Katana output: {exc}")

    limited = len(data) > MAX_KATANA_OUTPUT_BYTES
    data = data[:MAX_KATANA_OUTPUT_BYTES]
    records: list[str] = []
    output_bytes = 0
    omitted = 0
    for raw_line in data.splitlines():
        if not raw_line.strip():
            continue
        if len(raw_line) > MAX_JSONL_LINE:
            omitted += 1
            continue
        try:
            line = raw_line.decode("utf-8")
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError, RecursionError):
            omitted += 1
            continue
        if not isinstance(record, dict):
            omitted += 1
            continue
        # Newlines are included in the recovery budget. A record cut by the
        # byte limit or an interrupted write is omitted rather than repaired.
        normalized = line.rstrip("\r\n") + "\n"
        record_bytes = len(normalized.encode("utf-8"))
        if output_bytes + record_bytes > MAX_KATANA_OUTPUT_BYTES:
            limited = True
            omitted += 1
            break
        records.append(normalized)
        output_bytes += record_bytes

    if limited:
        message += (
            f"; recovery limited to {MAX_KATANA_OUTPUT_BYTES} bytes "
            "of complete JSONL records"
        )
    if omitted:
        message += f"; omitted {omitted} incomplete, invalid or oversized JSONL record(s)"
    if not records:
        return ToolError(message)
    return KatanaPartialError(
        "".join(records),
        [
            Issue(stage="katana", target=_display_url(seed), message=message)
            for seed in seeds
        ],
    )


def _katana_error_detail(stderr: str) -> str:
    if not stderr:
        return ""
    cleaned = _ANSI_ESCAPE.sub("", stderr)
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    relevant = [
        line
        for line in lines
        if any(marker in line.lower() for marker in ("[err]", "[ftl]", "error", "failed"))
    ]
    selected = relevant[-2:] if relevant else lines[-1:]
    return " | ".join(selected)[:800]


def resolve_bundled_chromium(katana_executable: str) -> Path | None:
    """Return a Chromium installed next to the Katana executable, if present."""
    katana_directory = Path(katana_executable).resolve().parent
    chromium_directory = katana_directory / "chromium"
    candidates = (
        chromium_directory / "chrome.exe",
        chromium_directory / "chrome",
        chromium_directory / "chrome-linux" / "chrome",
        chromium_directory / "Chromium.app" / "Contents" / "MacOS" / "Chromium",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def resolve_system_chromium() -> Path | None:
    candidates: list[Path] = []
    if os.name == "nt":
        for variable, relative in (
            ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
            ("PROGRAMFILES(X86)", "Google/Chrome/Application/chrome.exe"),
            ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
            ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
            ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
        ):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / Path(relative))
    elif sys.platform == "darwin":
        candidates.extend(
            (
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            )
        )
    for name in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
        "microsoft-edge",
    ):
        resolved = shutil.which(name)
        if resolved:
            candidates.append(Path(resolved))
    return next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)


def resolve_headless_chromium(
    config: KatanaConfig,
    katana_executable: str,
) -> Path | None:
    if config.chrome_executable:
        candidate = Path(config.chrome_executable).expanduser()
        if not candidate.is_file():
            raise ToolError(f"Chrome executable not found: {candidate}")
        return candidate.resolve()
    return resolve_system_chromium() or resolve_bundled_chromium(katana_executable)


def katana_environment(isolated_root: Path | None = None) -> dict[str, str]:
    """Return an environment that cannot silently enable authenticated crawling."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not _blocked_environment_key(key)
    }
    if isolated_root is not None:
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


def _blocked_environment_key(key: str) -> bool:
    upper = key.upper()
    return (
        upper in _BLOCKED_ENVIRONMENT_VARIABLES
        or upper.endswith("_PROXY")
        or upper.startswith("KATANA_")
    )


def _safe_katana_candidate(
    url: str,
    allowed_hosts: set[str],
    *,
    include_subdomains: bool,
) -> str | None:
    try:
        normalized = normalize_url(url, redact_query=False)
    except ValueError:
        return None
    if "," in normalized or is_logout_url(normalized):
        return None
    host = urlsplit(normalized).hostname
    if not host:
        return None
    normalized_host = normalize_hostname(host)
    if normalized_host in allowed_hosts:
        return normalized
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        if include_subdomains and any(
            normalized_host.endswith("." + allowed)
            for allowed in allowed_hosts
            if not _is_ip_address(allowed)
        ):
            return normalized
    return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def katana_scope_patterns(
    hosts: set[str],
    *,
    include_subdomains: bool,
) -> list[str]:
    patterns: list[str] = []
    for raw_host in sorted(host for host in hosts if host):
        host = raw_host.lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            escaped = re.escape(host)
            authority = (
                rf"(?:[a-z0-9-]+\.)*{escaped}"
                if include_subdomains
                else escaped
            )
        else:
            authority = (
                rf"\[{re.escape(str(address))}\]"
                if address.version == 6
                else re.escape(str(address))
            )
        # Katana parses -cs as a string-array flag and splits each value on a
        # literal comma. Avoid the usual ``{1,5}`` quantifier: its comma would
        # turn this into two invalid scope expressions before regex parsing.
        port = r"[0-9][0-9]?[0-9]?[0-9]?[0-9]?"
        patterns.append(rf"(?i)^https?://{authority}(?::{port})?(?:[/?#]|$)")
    if not patterns:
        raise ValueError("Katana requires at least one explicit scope host")
    return patterns


def katana_field_scope_pattern(
    hosts: set[str],
    *,
    include_subdomains: bool,
) -> str:
    """Build the DNS-scope regex Katana applies before its URL scope rules."""
    host_patterns: list[str] = []
    for raw_host in sorted(host for host in hosts if host):
        host = raw_host.lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            escaped = re.escape(host)
            host_patterns.append(
                rf"(?:[a-z0-9-]+\.)*{escaped}"
                if include_subdomains
                else escaped
            )
        else:
            host_patterns.append(re.escape(str(address)))
    if not host_patterns:
        raise ValueError("Katana requires at least one explicit field-scope host")
    return rf"(?i)^(?:{'|'.join(host_patterns)})\.?$"
