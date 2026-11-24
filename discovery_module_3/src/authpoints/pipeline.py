from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from .classifier import (
    classify_service,
    classify_web,
    web_seed_from_service,
)
from .browser_render import render_pages
from .config import KatanaConfig, ScanConfig, validate_browser_resource_domain
from .http_probe import probe_urls
from .http_diagnostics import describe_http_access_problem
from .models import Finding, FindingKind, Issue, Report, Source, WebObservation
from .normalize import (
    is_logout_url, normalize_url,
)
from .parsers.katana_jsonl import parse_katana_jsonl
from .parsers.nmap_xml import parse_nmap_xml
from .runners.common import ToolError
from .runners.katana import KatanaPartialError, run_katana
from .runners.nmap import partition_targets, run_nmap
from .runners.subfinder import run_subfinder
from .scope import Scope
from .standard_paths import expand_standard_paths


_AUTO_RENDER_TEXT = re.compile(
    r"\b(?:log\s*in|sign\s*in|username|authentication)\b|"
    r"(?:войти|вход|авторизац|аутентификац|имя пользователя|парол)",
    re.IGNORECASE,
)
_AUTO_RENDER_CLIENT_MARKER = re.compile(
    r"\b(?:login|signin|sign-in|auth)[_-]?"
    r"(?:component|container|dialog|feature|modal|popup|root|widget)\b",
    re.IGNORECASE,
)
_AUTO_RENDER_PATH = re.compile(
    r"(?:^|/)(?:auth|login|log-in|signin|sign-in|authenticate|"
    r"account/login|accounts/login|admin/login|user/login|users/sign_in|"
    r"session/new|sessions/new|sso/login|oauth2?/authorize|oidc/authorize|"
    r"saml/login)(?:[/?#.]|$)",
    re.IGNORECASE,
)


def run_active_scan(
    targets: list[str],
    urls: list[str],
    config: ScanConfig,
    *,
    allow_large_networks: bool = False,
    on_finding: Callable[[Finding], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> Report:
    selected_templates = frozenset(config.login_templates)
    if selected_templates and on_finding is not None:
        original_callback = on_finding
        emitted_findings: set[int] = set()

        def on_finding(finding: Finding) -> None:
            if finding.metadata.get("login_template") in selected_templates and id(finding) not in emitted_findings:
                emitted_findings.add(id(finding))
                original_callback(finding)

    clean_targets = _clean_values(targets)
    transport_urls = [
        normalize_url(value, redact_query=False) for value in _clean_values(urls)
    ]
    report_urls = [normalize_url(value) for value in transport_urls]
    scope = Scope.from_inputs(
        clean_targets,
        transport_urls,
        include_subdomains=config.include_subdomains,
        allow_large_networks=allow_large_networks,
    )
    if not scope.hosts and not scope.networks:
        raise ValueError("at least one target or URL is required")
    report = Report(
        scope=scope.describe(),
        config={"mode": "active", **config.public_dict()},
    )
    _emit(
        on_progress,
        f"[START] Целей: {len(clean_targets)}, начальных URL: {len(transport_urls)}",
    )
    web_proxy = config.katana.proxy or config.http.proxy
    if web_proxy:
        _emit(on_progress, f"[PROXY] Katana/paths -> {web_proxy}")
        if config.nmap.enabled:
            _emit(on_progress, "[PROXY] Nmap использует прямое TCP/UDP-подключение")

    subfinder_domains = _subfinder_domains(clean_targets, transport_urls)
    discovered_subdomains: list[str] = []
    if config.subfinder.enabled and subfinder_domains:
        _emit(
            on_progress,
            f"[SUBFINDER] Пассивный поиск: {len(subfinder_domains)} доменов",
        )
        try:
            discovered_subdomains = run_subfinder(config.subfinder, subfinder_domains)
            _emit(
                on_progress,
                f"[SUBFINDER] Найдено поддоменов: {len(discovered_subdomains)}",
            )
        except (ToolError, ValueError) as exc:
            _record_issue(
                report,
                Issue(stage="subfinder", message=str(exc)),
                on_progress,
            )
    elif config.subfinder.enabled:
        _emit(on_progress, "[SUBFINDER] Нет подходящих доменных целей")
    else:
        _emit(on_progress, "[SUBFINDER] Пропущен")
    subfinder_config = report.config.get("subfinder")
    if isinstance(subfinder_config, dict):
        subfinder_config["domains"] = subfinder_domains
        subfinder_config["discovered_subdomains"] = discovered_subdomains

    if config.nmap.enabled and clean_targets:
        ipv4_targets, ipv6_targets = partition_targets(clean_targets)
        for family_targets, ipv6 in ((ipv4_targets, False), (ipv6_targets, True)):
            if not family_targets:
                continue
            protocols = [False, True] if config.nmap.udp_enabled else [False]
            for udp in protocols:
                stage = "nmap_udp" if udp else "nmap"
                if ipv6:
                    stage += "_ipv6"
                protocol = "UDP" if udp else "TCP"
                family = "IPv6" if ipv6 else "IPv4/hostname"
                _emit(
                    on_progress,
                    f"[NMAP] Запуск {protocol} {family}: {len(family_targets)} целей",
                )
                try:
                    xml = run_nmap(
                        config.nmap,
                        family_targets,
                        ipv6=ipv6,
                        udp=udp,
                    )
                    services = parse_nmap_xml(xml)
                    report.services.extend(services)
                    _emit(
                        on_progress,
                        f"[NMAP] {protocol} {family} завершён: "
                        f"{len(services)} открытых служб",
                    )
                except (ToolError, ValueError) as exc:
                    _record_issue(
                        report,
                        Issue(stage=stage, message=str(exc)),
                        on_progress,
                    )
    elif config.nmap.enabled:
        _emit(on_progress, "[NMAP] Нет целей для запуска")
    else:
        _emit(on_progress, "[NMAP] Пропущен")

    crawl_seeds = [
        *transport_urls,
        *_subdomain_web_seeds(discovered_subdomains, transport_urls),
    ]
    if config.page_only:
        existing_hosts = {urlsplit(url).hostname for url in transport_urls}
        for target in clean_targets:
            if "/" in target:
                continue
            try:
                address = ipaddress.ip_address(target)
            except ValueError:
                parsed_target = urlsplit(f"//{target}")
                if not parsed_target.hostname or parsed_target.hostname in existing_hosts:
                    continue
                host = parsed_target.netloc
            else:
                if str(address) in existing_hosts:
                    continue
                host = f"[{address}]" if address.version == 6 else str(address)
            crawl_seeds.extend((f"https://{host}/", f"http://{host}/"))
    for service in report.services:
        try:
            finding = classify_service(service)
        except ValueError as exc:
            _record_issue(
                report,
                Issue(
                    stage="service_classification",
                    target=service.host,
                    message=str(exc),
                ),
                on_progress,
            )
            finding = None
        if finding is not None:
            if report.add_or_merge_finding(finding) and on_finding is not None:
                on_finding(finding)
        try:
            seed = web_seed_from_service(service)
        except ValueError as exc:
            _record_issue(
                report,
                Issue(
                    stage="nmap",
                    target=service.host,
                    message=f"invalid web service host: {exc}",
                ),
                on_progress,
            )
            continue
        if seed and scope.allows_url(seed):
            crawl_seeds.append(seed)
    crawl_seeds = list(dict.fromkeys(crawl_seeds))
    standard_path_seeds = list(
        dict.fromkeys(expand_standard_paths(crawl_seeds, config.standard_paths))
    )

    observations = (
        []
        if config.page_only
        else [
            WebObservation(url=url, source=Source.URL_LIST)
            for url in report_urls
        ]
    )
    classified_observation_count = 0
    page_resolved_urls: dict[str, str] = {}
    safe_crawl_seeds = _safe_network_urls(
        crawl_seeds,
        report=report,
        on_progress=on_progress,
    )
    safe_standard_path_seeds = _safe_network_urls(
        standard_path_seeds,
        report=report,
        on_progress=on_progress,
    )
    if config.page_only and config.http.enabled:
        progress_tag = "[PAGE]"
        _emit(
            on_progress,
            f"{progress_tag} Проверка стартовых URL: {len(safe_crawl_seeds)}",
        )
        page_progress = (
            lambda message: on_progress(message.replace("[HTTP]", progress_tag, 1))
            if on_progress is not None
            else None
        )
        for result in probe_urls(
            safe_crawl_seeds,
            scope,
            config.http,
            on_progress=page_progress,
        ):
            if result.observation is not None:
                observations.append(result.observation)
                if result.requested_url:
                    page_resolved_urls[result.requested_url] = normalize_url(
                        result.observation.url, redact_query=False,
                    )
                _record_server_error(
                    report,
                    result.observation,
                    stage="page_only",
                    on_progress=on_progress,
                )
            if result.issue is not None:
                result.issue.stage = "page_only"
                report.issues.append(result.issue)
        if config.page_only:
            _classify_observations(
                report, observations, on_finding=on_finding,
                on_progress=on_progress,
            )
            classified_observation_count = len(observations)
            for seed in safe_crawl_seeds:
                seed_url = normalize_url(seed, redact_query=False)
                resolved_url = page_resolved_urls.get(seed_url, seed_url)
                if _page_has_finding(report, resolved_url):
                    continue
                _emit(on_progress, f"[PAGE] Браузерный анализ {normalize_url(seed)}")
                previous_observation_count = len(observations)
                try:
                    output = render_pages(
                        [seed], config=config.katana, scope=scope,
                        same_page_only=True,
                    )
                    _consume_katana_output(
                        _same_page_browser_records(output), report=report, observations=observations,
                        scope=scope, stage="page_only_browser",
                        on_progress=on_progress,
                    )
                except KatanaPartialError as exc:
                    _consume_partial_katana_output(
                        KatanaPartialError(_same_page_browser_records(exc.output), list(exc.issues)),
                        report=report, observations=observations,
                        scope=scope, stage="page_only_browser",
                        on_progress=on_progress,
                    )
                except (ToolError, ValueError) as exc:
                    _record_issue(
                        report,
                        Issue(stage="page_only_browser", target=normalize_url(seed), message=str(exc)),
                        on_progress,
                    )
                if len(observations) > previous_observation_count:
                    page_resolved_urls[seed_url] = normalize_url(
                        observations[previous_observation_count].url, redact_query=False,
                    )

    if config.standard_paths and config.http.enabled and safe_standard_path_seeds:
        _emit(
            on_progress,
            f"[PATHS] Проверка стандартных путей: {len(safe_standard_path_seeds)} URL",
        )
        path_progress = (
            lambda message: on_progress(message.replace("[HTTP]", "[PATHS]", 1))
            if on_progress is not None
            else None
        )
        for result in probe_urls(
            safe_standard_path_seeds,
            scope,
            config.http,
            on_progress=path_progress,
        ):
            if result.observation is not None:
                observations.append(result.observation)
                _record_server_error(
                    report,
                    result.observation,
                    stage="standard_paths",
                    on_progress=on_progress,
                )
            if result.issue is not None:
                result.issue.stage = "standard_paths"
                report.issues.append(result.issue)
    elif config.standard_paths and config.http.enabled:
        _emit(on_progress, "[PATHS] В файле нет путей для проверки")
    else:
        _emit(on_progress, "[PATHS] Проверка стандартных путей не включена")

    katana_seeds: list[str] = []
    for seed in safe_crawl_seeds:
        if config.katana.enabled and "," in seed:
            _record_issue(
                report,
                Issue(
                    stage="url_safety",
                    target=normalize_url(seed),
                    message=(
                        "Katana skipped this URL because its list parser treats a literal "
                        "comma as another root"
                    ),
                ),
                on_progress,
            )
        elif config.katana.enabled:
            katana_seeds.append(seed)

    if config.katana.enabled and katana_seeds:
        scope_hosts = scope.hosts | {
            urlsplit(seed).hostname or "" for seed in katana_seeds
        }
        katana_config = config.katana
        if config.katana.auto_headless and not config.katana.headless:
            # The inexpensive crawl also extracts endpoints from JavaScript. A
            # browser is started later only for pages that can plausibly contain
            # an authentication UI.
            katana_config = replace(config.katana, js_crawl=True)
            _emit(
                on_progress,
                "[KATANA] Автоматический режим: HTML-обход и JS-discovery",
            )
        try:
            output = run_katana(
                katana_config,
                katana_seeds,
                include_subdomains=config.include_subdomains,
                scope_hosts=scope_hosts,
                on_progress=on_progress,
            )
            _consume_katana_output(
                output,
                report=report,
                observations=observations,
                scope=scope,
                stage="katana",
                on_progress=on_progress,
            )
        except KatanaPartialError as exc:
            _consume_partial_katana_output(
                exc,
                report=report,
                observations=observations,
                scope=scope,
                stage="katana",
                on_progress=on_progress,
            )
        except (ToolError, ValueError) as exc:
            _record_issue(
                report,
                Issue(stage="katana", message=str(exc)),
                on_progress,
            )

        if config.katana.auto_headless and not config.katana.headless:
            _emit(
                on_progress,
                f"[ANALYZE] Статический этап: "
                f"{sum(_has_response_material(item) for item in observations)} web-ответов",
            )
            _classify_observations(
                report,
                observations,
                on_finding=on_finding,
                on_progress=on_progress,
            )
            classified_observation_count = len(observations)
            confirmed_urls = _confirmed_web_urls(report)
            candidates = _auto_headless_candidates(
                katana_seeds,
                observations,
                scope=scope,
                limit=config.katana.max_domain_pages,
                confirmed_urls=confirmed_urls,
            )
            _emit(
                on_progress,
                f"[HEADLESS] Отобрано JS-кандидатов: {len(candidates)}",
            )
            render_config = replace(
                config.katana,
                auto_headless=False,
                headless=True,
                js_crawl=False,
                depth=1,
                parallelism=1,
                ca_cert=config.katana.ca_cert or config.http.ca_cert,
            )
            candidate_groups = _group_headless_candidates(candidates)
            headless_workers = min(config.katana.parallelism, len(candidate_groups))
            if headless_workers:
                _emit(
                    on_progress,
                    f"[HEADLESS] Параллельных Chromium-сессий: {headless_workers}",
                )
                futures: dict[Future[str], tuple[str, list[str]]] = {}
                with ThreadPoolExecutor(
                    max_workers=headless_workers,
                    thread_name_prefix="pointfinder-headless",
                ) as pool:
                    for origin, origin_candidates in candidate_groups:
                        origin_timeout = min(
                            config.katana.timeout_seconds,
                            config.katana.auto_headless_timeout_seconds
                            * len(origin_candidates),
                        )
                        # crawl_duration tells Katana how long it should keep
                        # crawling, while timeout_seconds is only a hard safety
                        # limit. Using the same value for both made every
                        # browser session wait until the timeout even after the
                        # DOM was ready.
                        per_page_crawl_seconds = max(
                            15,
                            config.katana.dom_wait_seconds + 10,
                        )
                        crawl_seconds = min(
                            max(1, origin_timeout - 5),
                            per_page_crawl_seconds * len(origin_candidates),
                        )
                        origin_config = replace(
                            render_config,
                            timeout_seconds=origin_timeout,
                            crawl_duration=f"{crawl_seconds}s",
                            max_domain_pages=len(origin_candidates),
                        )
                        future = pool.submit(
                            _run_auto_headless_origin,
                            origin,
                            origin_candidates,
                            render_config=origin_config,
                            scope=scope,
                            include_subdomains=config.include_subdomains,
                            scope_hosts=scope_hosts,
                            on_progress=on_progress,
                        )
                        futures[future] = (origin, origin_candidates)
                    for future in as_completed(futures):
                        origin, _origin_candidates = futures[future]
                        try:
                            output = future.result()
                            _consume_katana_output(
                                output,
                                report=report,
                                observations=observations,
                                scope=scope,
                                stage="katana_headless",
                                on_progress=on_progress,
                            )
                        except KatanaPartialError as exc:
                            _consume_partial_katana_output(
                                exc,
                                report=report,
                                observations=observations,
                                scope=scope,
                                stage="katana_headless",
                                on_progress=on_progress,
                            )
                        except (ToolError, ValueError) as exc:
                            _record_issue(
                                report,
                                Issue(
                                    stage="katana_headless",
                                    target=origin,
                                    message=str(exc),
                                ),
                                on_progress,
                            )
    elif config.katana.enabled:
        _emit(on_progress, "[KATANA] Нет URL для обхода")
    else:
        _emit(on_progress, "[KATANA] Пропущена")

    remaining_observations = observations[classified_observation_count:]
    stage_name = "Headless-этап" if classified_observation_count else "Web-этап"
    _emit(
        on_progress,
        f"[ANALYZE] {stage_name}: "
        f"{sum(_has_response_material(item) for item in remaining_observations)} новых ответов",
    )
    _classify_observations(
        report,
        remaining_observations,
        on_finding=on_finding,
        on_progress=on_progress,
    )
    if selected_templates:
        report.findings = [
            finding for finding in report.findings
            if finding.metadata.get("login_template") in selected_templates
        ]
        # A generic static finding may have acquired its template only after
        # merging browser evidence; emit it now if it was not shown before.
        if on_finding is not None:
            for finding in report.findings:
                on_finding(finding)
    if config.page_only:
        report.config["page_only_results"] = [
            _page_only_result(
                report, seed,
                resolved_url=page_resolved_urls.get(normalize_url(seed, redact_query=False)),
            )
            for seed in safe_crawl_seeds
        ]
    report.finish()
    _emit(
        on_progress,
        f"[DONE] Найдено точек: {len(report.findings)}, "
        f"служб: {len(report.services)}, проблем: {len(report.issues)}",
    )
    return report


def _subfinder_domains(targets: list[str], urls: list[str]) -> list[str]:
    candidates = [*targets, *(urlsplit(url).hostname or "" for url in urls)]
    domains: list[str] = []
    for raw_value in candidates:
        value = raw_value.strip().lower().rstrip(".")
        try:
            ipaddress.ip_network(value, strict=False)
            continue
        except ValueError:
            pass
        if value == "localhost" or "." not in value or "/" in value:
            continue
        if value not in domains:
            domains.append(value)
    return domains


def _subdomain_web_seeds(hosts: list[str], seed_urls: list[str]) -> list[str]:
    origins: list[tuple[str, int | None]] = []
    for url in seed_urls:
        parts = urlsplit(url)
        origin = (parts.scheme.lower(), parts.port)
        if origin not in origins:
            origins.append(origin)
    if not origins:
        origins = [("https", None)]
    seeds: list[str] = []
    for host in hosts:
        for scheme, port in origins:
            default_port = 443 if scheme == "https" else 80
            authority = host if port in (None, default_port) else f"{host}:{port}"
            seeds.append(f"{scheme}://{authority}/")
    return seeds


def analyze_offline(
    *,
    targets: list[str],
    urls: list[str],
    nmap_documents: Iterable[tuple[str, bytes]],
    katana_documents: Iterable[tuple[str, str]],
    include_subdomains: bool = False,
    allow_large_networks: bool = False,
    on_finding: Callable[[Finding], None] | None = None,
) -> Report:
    clean_targets = _clean_values(targets)
    transport_urls = [
        normalize_url(value, redact_query=False) for value in _clean_values(urls)
    ]
    report_urls = [normalize_url(value) for value in transport_urls]
    scope = Scope.from_inputs(
        clean_targets,
        transport_urls,
        include_subdomains=include_subdomains,
        allow_large_networks=allow_large_networks,
    )
    report = Report(
        scope=scope.describe(),
        config={"mode": "offline", "include_subdomains": include_subdomains},
    )

    for label, document in nmap_documents:
        try:
            report.services.extend(parse_nmap_xml(document))
        except ValueError as exc:
            report.issues.append(Issue(stage="nmap_parse", target=label, message=str(exc)))

    observations = [WebObservation(url=url, source=Source.URL_LIST) for url in report_urls]
    for label, document in katana_documents:
        parsed, errors = parse_katana_jsonl(document)
        if scope.hosts or scope.networks:
            parsed = [item for item in parsed if scope.allows_url(item.url)]
        observations.extend(parsed)
        _append_parse_issues(report, "katana_parse", errors, target=label)

    for service in report.services:
        try:
            finding = classify_service(service)
        except ValueError as exc:
            report.issues.append(
                Issue(stage="service_classification", target=service.host, message=str(exc))
            )
            continue
        if finding is not None:
            if report.add_or_merge_finding(finding) and on_finding is not None:
                on_finding(finding)
    _classify_observations(report, observations, on_finding=on_finding)
    report.finish()
    return report


def _consume_partial_katana_output(
    error: KatanaPartialError,
    *,
    report: Report,
    observations: list[WebObservation],
    scope: Scope,
    stage: str,
    on_progress: Callable[[str], None] | None,
) -> None:
    _consume_katana_output(
        error.output,
        report=report,
        observations=observations,
        scope=scope,
        stage=stage,
        on_progress=on_progress,
    )
    for issue in error.issues:
        _record_issue(report, replace(issue, stage=stage), on_progress)


def _record_browser_diagnostics(
    observation: WebObservation,
    *,
    report: Report,
    on_progress: Callable[[str], None] | None,
) -> None:
    raw = observation.discovery_diagnostics
    if not raw:
        return

    def printable(value: object, limit: int = 4096) -> str:
        if not isinstance(value, str):
            return ""
        return "".join(character for character in value if ord(character) >= 32 and ord(character) != 127)[:limit]

    def safe_url(value: object) -> str:
        try:
            parts = urlsplit(normalize_url(printable(value, 8192)))
        except ValueError:
            return ""
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

    summary: dict[str, object] = {
        "candidate_url": safe_url(raw.get("candidate_url")) or safe_url(observation.url),
        "final_url": safe_url(raw.get("final_url")) or safe_url(observation.url),
        "password_field_found": raw.get("password_field_found") is True,
        "login_form_found": raw.get("login_form_found") is True,
    }
    for key in ("blocked_count", "network_error_count", "click_count", "status_code"):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            summary[key] = value
    for key in ("dom_path", "diagnostics_path"):
        value = printable(raw.get(key))
        if value:
            summary[key] = value
    paths = raw.get("dom_paths")
    if isinstance(paths, list):
        summary["dom_paths"] = [printable(path) for path in paths[:10] if printable(path)]
    hosts: list[str] = []
    raw_hosts = raw.get("blocked_resource_hosts")
    for host in raw_hosts[:100] if isinstance(raw_hosts, list) else []:
        try:
            normalized = validate_browser_resource_domain(printable(host, 253))
        except ValueError:
            continue
        if normalized not in hosts:
            hosts.append(normalized)
    summary["blocked_resource_hosts"] = hosts[:100]
    auto_hosts: list[str] = []
    raw_auto_hosts = raw.get("auto_resource_hosts")
    for host in raw_auto_hosts[:32] if isinstance(raw_auto_hosts, list) else []:
        try:
            normalized = validate_browser_resource_domain(printable(host, 253))
        except ValueError:
            continue
        if normalized not in auto_hosts:
            auto_hosts.append(normalized)
    summary["auto_resource_hosts"] = auto_hosts
    for key, text_keys, limit in (
        ("blocked_requests", ("method", "resource_type", "reason"), 100),
        ("network_errors", ("category",), 20),
        ("clicks", ("label",), 10),
    ):
        entries = raw.get(key)
        if not isinstance(entries, list):
            continue
        sanitized = []
        for entry in entries[:limit]:
            if not isinstance(entry, dict):
                continue
            item = {name: printable(entry.get(name), 120) for name in text_keys}
            for name in ("url", "target"):
                if entry.get(name):
                    item[name] = safe_url(entry[name])
            sanitized.append(item)
        summary[key] = sanitized
    diagnostics = report.config.setdefault("browser_diagnostics", [])
    if isinstance(diagnostics, list):
        diagnostics.append(summary)

    password_found = summary["password_field_found"] is True
    login_found = summary["login_form_found"] is True
    blocked = int(summary.get("blocked_count", 0))
    errors = int(summary.get("network_error_count", 0))
    auto_label = f"внешних хостов с ресурсами: {len(auto_hosts)}; " if auto_hosts else ""
    _emit(
        on_progress,
        f"[HEADLESS] {summary['final_url']} — "
        f"поле пароля: {'найдено' if password_found else 'не найдено'}; "
        f"форма входа: {'найдена' if login_found else 'не подтверждена'}; "
        f"{auto_label}"
        f"открытий формы: {summary.get('click_count', 0)}; "
        f"заблокировано запросов: {blocked}; ошибок сети: {errors}",
    )
    blocked_requests = summary.get("blocked_requests", [])
    critical_blocked = [
        entry for entry in blocked_requests if isinstance(entry, dict)
        and entry.get("resource_type") in {"script", "stylesheet", "font"}
    ]
    if blocked and not blocked_requests:
        # Older renderer records have no per-request classification.
        critical_blocked = [{"reason": "unknown"}]
    if not login_found and (critical_blocked or errors):
        detail = (
            "Поле пароля найдено, но форма входа не подтверждена"
            if password_found else "После JavaScript форма входа не обнаружена"
        )
        retry_hosts = []
        for entry in critical_blocked:
            if entry.get("reason") not in {
                "outside_scope", "external_asset_host_limit", "external_asset_request_limit",
            }:
                continue
            try:
                host = urlsplit(str(entry.get("url", ""))).hostname
            except ValueError:
                host = None
            if host and host not in retry_hosts:
                retry_hosts.append(host)
        if not blocked_requests:
            retry_hosts = [host for host in hosts if host not in auto_hosts]
        if auto_hosts:
            detail += f"; внешние ресурсы автоматически загружены с {len(auto_hosts)} хостов"
        if retry_hosts:
            detail += "; заблокированы нужные для отрисовки ресурсы: " + ", ".join(retry_hosts[:10])
            detail += "; для нужного заблокированного JS/CSS укажите --browser-resource-domain HOST"
        elif critical_blocked:
            detail += "; часть JS/CSS заблокирована правилами поиска или лимитом ресурсов"
        if errors:
            detail += f"; ошибок загрузки: {errors}"
        if summary.get("diagnostics_path"):
            detail += f"; диагностика: {summary['diagnostics_path']}"
        _record_issue(
            report,
            Issue(stage="browser_render", target=str(summary["final_url"]), message=detail),
            on_progress,
        )


def _consume_katana_output(
    output: str,
    *,
    report: Report,
    observations: list[WebObservation],
    scope: Scope,
    stage: str,
    on_progress: Callable[[str], None] | None,
) -> None:
    parsed, errors = parse_katana_jsonl(output)
    _emit(
        on_progress,
        f"[{stage.upper()}] Разбор результата: {len(parsed)} записей, "
        f"ошибок парсинга: {len(errors)}",
    )
    for item in parsed:
        if item.method != "GET":
            if stage == "katana_headless":
                # JavaScript may emit challenge, telemetry or CORS requests.
                # They are never classified as authentication endpoints and do
                # not imply that PointFinder submitted a login form.
                continue
            if _has_response_material(item):
                _record_issue(
                    report,
                    Issue(
                        stage=stage,
                        target=item.url,
                        message=(
                            "Katana returned a response for unexpected "
                            f"{item.method} request"
                        ),
                        fatal=True,
                    ),
                    on_progress,
                )
            continue
        if scope.allows_url(item.url):
            _record_browser_diagnostics(
                item, report=report, on_progress=on_progress
            )
            unsafe_network_url = is_logout_url(item.url)
            if unsafe_network_url and _has_response_material(item):
                _record_issue(
                    report,
                    Issue(
                        stage=stage,
                        target=item.url,
                        message=(
                            "Katana returned a response for a logout URL"
                        ),
                        fatal=True,
                    ),
                    on_progress,
                )
            observations.append(item)
            _record_server_error(
                report,
                item,
                stage=f"{stage}_http",
                on_progress=on_progress,
            )
        elif _has_response_material(item) and stage != "katana_headless":
            _record_issue(
                report,
                Issue(
                    stage="scope",
                    target=item.url,
                    message="Katana returned an out-of-scope response record",
                    fatal=True,
                ),
                on_progress,
            )
    _append_parse_issues(
        report,
        stage,
        errors,
        on_progress=on_progress,
    )


def _safe_network_urls(
    urls: Iterable[str],
    *,
    report: Report,
    on_progress: Callable[[str], None] | None,
) -> list[str]:
    safe_urls: list[str] = []
    for url in urls:
        if is_logout_url(url):
            _record_issue(
                report,
                Issue(
                    stage="url_safety",
                    target=normalize_url(url),
                    message="network access skipped for a logout URL",
                ),
                on_progress,
            )
        else:
            safe_urls.append(url)
    return list(dict.fromkeys(safe_urls))


def _run_auto_headless_origin(
    origin: str,
    candidates: list[str],
    *,
    render_config: KatanaConfig,
    scope: Scope,
    include_subdomains: bool,
    scope_hosts: set[str],
    on_progress: Callable[[str], None] | None,
) -> str:
    _emit(
        on_progress,
        f"[HEADLESS] Chromium: {origin} ({len(candidates)} страниц)",
    )
    if render_config.ca_cert or render_config.browser_resource_domains:
        # Katana's Chromium session has no access to the caller-supplied CA.
        # The DOM renderer validates each scoped response with that CA instead.
        return render_pages(candidates, config=render_config, scope=scope)
    output = run_katana(
        render_config,
        candidates,
        include_subdomains=include_subdomains,
        scope_hosts=scope_hosts,
        on_progress=on_progress,
    )
    observations, _errors = parse_katana_jsonl(output)
    if any(
        field.field_type == "password"
        for observation in observations
        for form in observation.forms
        for field in form.fields
    ):
        return output
    _emit(on_progress, f"[HEADLESS] Снимок DOM после JavaScript: {len(candidates)} страниц")
    try:
        rendered = render_pages(candidates, config=render_config, scope=scope)
    except KatanaPartialError as exc:
        if output:
            raise KatanaPartialError(
                "\n".join(part for part in (output, exc.output) if part),
                list(exc.issues),
            ) from exc
        raise
    except (ToolError, ValueError) as exc:
        if output:
            raise KatanaPartialError(
                output,
                [Issue(stage="katana_headless", target=origin, message=str(exc))],
            ) from exc
        raise
    return "\n".join(part for part in (output, rendered) if part)


def _group_headless_candidates(candidates: Iterable[str]) -> list[tuple[str, list[str]]]:
    groups: dict[str, list[str]] = {}
    for candidate in candidates:
        parts = urlsplit(candidate)
        origin = f"{parts.scheme}://{parts.netloc}"
        groups.setdefault(origin, []).append(candidate)
    return list(groups.items())


def _confirmed_web_urls(report: Report) -> set[str]:
    web_kinds = {
        FindingKind.WEB_LOGIN,
        FindingKind.HTTP_AUTH,
        FindingKind.SSO,
    }
    confirmed: set[str] = set()
    for finding in report.findings:
        if finding.kind not in web_kinds:
            continue
        if finding.auth_type == "js_login":
            # The page is known, but no usable form has been extracted yet.
            continue
        try:
            confirmed.add(normalize_url(finding.endpoint, redact_query=False))
        except ValueError:
            continue
    return confirmed


def _page_has_finding(report: Report, url: str) -> bool:
    """Do not render a page that already yielded a usable auth entry."""

    page_url = normalize_url(url, redact_query=False)
    for finding in report.findings:
        if finding.auth_type not in {"password_form", "http_basic", "passwordless_form"}:
            continue
        if _finding_on_page(finding, page_url):
            return True
    return False


def _finding_on_page(finding: Finding, page_url: str) -> bool:
    locations = finding.metadata.get("discovered_on", [])
    return bool(
        finding.endpoint == page_url
        or (isinstance(locations, list) and page_url in locations)
        or finding.metadata.get("page_url") == page_url
    )


def _page_only_result(
    report: Report, seed: str, *, resolved_url: str | None = None,
) -> dict[str, object]:
    page_url = normalize_url(seed, redact_query=False)
    final_url = normalize_url(resolved_url, redact_query=False) if resolved_url else page_url
    result: dict[str, object] = {"url": page_url}
    if final_url != page_url:
        result["final_url"] = final_url
    kinds = list(dict.fromkeys(
        finding.auth_type for finding in report.findings
        if _finding_on_page(finding, final_url)
    ))
    confirmed_kinds = [kind for kind in kinds if kind != "js_login"]
    if confirmed_kinds:
        return {**result, "status": "found", "auth_types": confirmed_kinds}
    problems = [issue.message for issue in report.issues if issue.target in {page_url, final_url}]
    if problems:
        return {**result, "status": "unverified", "detail": problems[0]}
    if "js_login" in kinds:
        return {**result,
            "status": "unverified",
            "detail": "есть признаки JavaScript-входа, но форма не подтверждена",
        }
    return {**result, "status": "not_found"}


def _same_page_browser_records(output: str) -> str:
    """Keep modal states, but do not classify pages reached by clicking a link."""

    first_url = ""
    kept: list[str] = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
            url = record.get("request", {}).get("endpoint", "")
        except (ValueError, AttributeError):
            kept.append(line)
            continue
        if not isinstance(url, str) or not url:
            continue
        if not first_url:
            first_url = url
        if url == first_url:
            kept.append(line)
    return "\n".join(kept)


def _auto_headless_candidates(
    roots: list[str],
    observations: Iterable[WebObservation],
    *,
    scope: Scope,
    limit: int,
    confirmed_urls: set[str],
) -> list[str]:
    candidates: list[str] = []
    per_host: defaultdict[str, int] = defaultdict(int)
    marker_origins: set[tuple[str, str, int | None]] = set()

    def add(raw_url: str, *, root: bool = False) -> None:
        try:
            url = normalize_url(raw_url, redact_query=False)
        except ValueError:
            return
        if (
            url in candidates
            or url in confirmed_urls
            or "," in url
            or not scope.allows_url(url)
            or is_logout_url(url)
        ):
            return
        host = urlsplit(url).hostname or ""
        if not root and per_host[host] >= limit:
            return
        candidates.append(url)
        per_host[host] += 1

    confirmed_origins = {
        (parts.scheme, parts.hostname or "", parts.port)
        for url in confirmed_urls
        for parts in (urlsplit(url),)
    }

    # Render an explicit root once only while its origin has no confirmed
    # authentication endpoint. A successful static finding makes a blind
    # browser retry redundant; explicit markers below can still select another
    # page on the same origin (for example, a distinct login modal).
    for root in roots:
        try:
            normalized_root = normalize_url(root, redact_query=False)
        except ValueError:
            continue
        parts = urlsplit(normalized_root)
        origin = (parts.scheme, parts.hostname or "", parts.port)
        if origin not in confirmed_origins:
            add(normalized_root, root=True)

    for observation in observations:
        status = observation.status_code
        usable_response = status is None or 200 <= status < 400
        if not usable_response:
            continue
        page_text = f"{observation.title}\n{observation.text}"
        parts = urlsplit(observation.url)
        if _AUTO_RENDER_PATH.search(parts.path):
            add(observation.url)
        elif (
            _AUTO_RENDER_TEXT.search(page_text)
            or _AUTO_RENDER_CLIENT_MARKER.search(page_text)
        ):
            # A site-wide login button/modal is commonly repeated in every
            # page header. Render one representative page per origin instead
            # of launching Chromium for every duplicate occurrence.
            origin = (parts.scheme, parts.hostname or "", parts.port)
            if origin not in marker_origins:
                marker_origins.add(origin)
                add(observation.url)
        for link in observation.links:
            if _AUTO_RENDER_PATH.search(urlsplit(link).path):
                add(link)
    return candidates


def _classify_observations(
    report: Report,
    observations: Iterable[WebObservation],
    *,
    on_finding: Callable[[Finding], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> None:
    for observation in observations:
        try:
            findings = classify_web(observation)
        except ValueError as exc:
            _record_issue(
                report,
                Issue(
                    stage="classification",
                    target=observation.url,
                    message=str(exc),
                ),
                on_progress,
            )
            continue
        for finding in findings:
            if report.add_or_merge_finding(finding) and on_finding is not None:
                on_finding(finding)


def _append_parse_issues(
    report: Report,
    stage: str,
    errors: list[str],
    *,
    target: str = "",
    on_progress: Callable[[str], None] | None = None,
) -> None:
    for message in errors[:100]:
        _record_issue(
            report,
            Issue(stage=stage, target=target, message=message),
            on_progress,
        )
    if len(errors) > 100:
        _record_issue(
            report,
            Issue(
                stage=stage,
                target=target,
                message=f"{len(errors) - 100} more errors omitted",
            ),
            on_progress,
        )


def _record_issue(
    report: Report,
    issue: Issue,
    on_progress: Callable[[str], None] | None,
) -> None:
    report.issues.append(issue)
    target = f" {issue.target}" if issue.target else ""
    _emit(on_progress, f"[ERROR] {issue.stage}{target}: {issue.message}")


def _record_server_error(
    report: Report,
    observation: WebObservation,
    *,
    stage: str,
    on_progress: Callable[[str], None] | None,
) -> None:
    message = describe_http_access_problem(observation)
    if message is None:
        return
    _record_issue(
        report,
        Issue(
            stage=stage,
            target=observation.url,
            message=message,
        ),
        on_progress,
    )


def _emit(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _clean_values(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _has_response_material(observation: WebObservation) -> bool:
    return bool(
        observation.status_code is not None
        or observation.headers
        or observation.title
        or observation.text
        or observation.forms
        or observation.links
    )
