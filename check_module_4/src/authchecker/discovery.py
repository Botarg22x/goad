from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .adapters.http import TargetScope, validate_target_url
from .defaults import DEFAULT_USER_AGENT
from .importer import PointFinderReport, parse_report


def discover_login_url(
    url: str,
    *,
    proxy: str | None = None,
    timeout_seconds: float,
    user_agent: str = DEFAULT_USER_AGENT,
    target_scope: TargetScope | None = None,
    ca_cert: Path | None = None,
    save_report: Path | None = None,
    browser_fallback: bool = True,
) -> PointFinderReport:
    """Ask PointFinder to inspect exactly one in-scope URL."""

    parts = validate_target_url(url, target_scope)
    exact_path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    raw_report = _run_pointfinder(
        url=url,
        exact_path=exact_path,
        proxy=proxy,
        user_agent=user_agent,
        ca_cert=ca_cert,
        timeout_seconds=max(1, math.ceil(timeout_seconds)),
        browser_fallback=browser_fallback,
    )
    try:
        payload = raw_report.to_dict()
    except AttributeError as exc:
        raise ValueError("PointFinder returned an unsupported report object") from exc
    report = parse_report(payload)
    if save_report is not None:
        _write_json_atomic(payload, save_report)
    return report


def discover_login_pages(
    urls: list[str],
    *,
    template: str | None = None,
    proxy: str | None = None,
    timeout_seconds: float,
    user_agent: str = DEFAULT_USER_AGENT,
    target_scope: TargetScope,
    ca_cert: Path | None = None,
    save_report: Path | None = None,
) -> PointFinderReport:
    """Inspect supplied pages only; keep the PointFinder report in memory."""

    if not urls:
        raise ValueError("укажите хотя бы одну страницу входа")
    for url in urls:
        validate_target_url(url, target_scope)
    try:
        from authpoints.config import HttpConfig, KatanaConfig, NmapConfig, ScanConfig
        from authpoints.login_templates import parse_template_selection
        from authpoints.pipeline import run_active_scan
    except (ImportError, ModuleNotFoundError) as exc:
        raise ValueError("для проверки страниц нужен PointFinder (модуль 3)") from exc

    selected = parse_template_selection([template]) if template else ()
    cert = str(ca_cert.expanduser().resolve()) if ca_cert else ""
    report = run_active_scan(
        [], urls,
        ScanConfig(
            page_only=True,
            include_subdomains=target_scope.include_subdomains,
            login_templates=selected,
            nmap=NmapConfig(enabled=False),
            katana=KatanaConfig(
                enabled=False,
                timeout_seconds=max(1, math.ceil(timeout_seconds)),
                request_timeout_seconds=max(1, math.ceil(timeout_seconds)),
                auto_headless_timeout_seconds=max(1, math.ceil(timeout_seconds)),
                proxy=proxy or "",
                user_agent=user_agent,
                ca_cert=cert,
            ),
            http=HttpConfig(
                enabled=True,
                timeout_seconds=max(1, math.ceil(timeout_seconds)),
                concurrency=1,
                request_delay_seconds=1.0,
                proxy=proxy or "",
                user_agent=user_agent,
                ca_cert=cert,
            ),
        ),
    )
    payload = report.to_dict()
    if save_report is not None:
        _write_json_atomic(payload, save_report)
    return parse_report(payload)


def _run_pointfinder(
    *,
    url: str,
    exact_path: str,
    proxy: str | None,
    user_agent: str,
    ca_cert: Path | None,
    timeout_seconds: int,
    browser_fallback: bool = True,
) -> Any:
    try:
        from authpoints.browser_render import render_pages
        from authpoints.classifier import classify_web
        from authpoints.config import HttpConfig, KatanaConfig, NmapConfig, ScanConfig
        from authpoints.http_diagnostics import describe_http_access_problem
        from authpoints.models import Issue
        from authpoints.parsers.katana_jsonl import parse_katana_jsonl
        from authpoints.pipeline import run_active_scan
        from authpoints.runners.common import ToolError
        from authpoints.scope import Scope
    except (ImportError, ModuleNotFoundError) as exc:
        raise ValueError(
            "--url requires PointFinder (module 3); run 'goad doctor'"
        ) from exc

    config = ScanConfig(
        standard_paths=[exact_path],
        nmap=NmapConfig(enabled=False),
        katana=KatanaConfig(enabled=False),
        http=HttpConfig(
            enabled=True,
            timeout_seconds=timeout_seconds,
            concurrency=1,
            proxy=proxy or "",
            user_agent=user_agent,
            ca_cert=str(ca_cert.expanduser().resolve()) if ca_cert else "",
        ),
    )
    report = run_active_scan([], [url], config)
    if browser_fallback and not report.issues and not any(
        finding.auth_type in {"password_form", "http_basic"}
        for finding in report.findings
    ):
        browser_config = KatanaConfig(
            enabled=True,
            timeout_seconds=timeout_seconds,
            auto_headless_timeout_seconds=timeout_seconds,
            request_timeout_seconds=timeout_seconds,
            dom_wait_seconds=2,
            user_agent=user_agent,
            proxy=proxy or "",
            ca_cert=str(ca_cert.expanduser().resolve()) if ca_cert else "",
        )
        try:
            rendered = render_pages(
                [url],
                config=browser_config,
                scope=Scope.from_inputs([], [url]),
            )
        except ToolError as exc:
            raise ValueError(f"PointFinder browser fallback failed: {exc}") from exc
        observations, errors = parse_katana_jsonl(rendered)
        if errors:
            raise ValueError(f"PointFinder browser fallback parse failed: {errors[0]}")
        for observation in observations:
            problem = describe_http_access_problem(observation)
            if problem is not None:
                report.issues.append(
                    Issue(
                        stage="browser_render",
                        target=observation.url,
                        message=problem,
                    )
                )
            for finding in classify_web(observation):
                report.add_or_merge_finding(finding)
    return report


def _write_json_atomic(payload: dict[str, Any], destination: Path) -> None:
    output = destination.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=output.name + ".",
            suffix=".tmp",
            dir=output.parent,
            delete=False,
        ) as temporary:
            json.dump(payload, temporary, ensure_ascii=False, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, output)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
