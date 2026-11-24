from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

from .config import (
    DEFAULT_USER_AGENT,
    HttpConfig,
    KatanaConfig,
    NmapConfig,
    ScanConfig,
    SubfinderConfig,
    validate_browser_resource_domain,
    validate_proxy_url,
    validate_user_agent,
)
from .doctor import check_environment
from .models import Finding
from .normalize import normalize_url
from .pipeline import run_active_scan
from .reporting import write_json_report, write_links_report
from .standard_paths import load_standard_paths
from .login_templates import load_login_templates, parse_template_selection, template_paths


_SPEED_PRESETS: dict[str, dict[str, int | float]] = {
    "slow": {
        "nmap_timing": 2,
        "katana_rate_limit": 1,
        "katana_parallelism": 1,
        "katana_concurrency": 1,
        "http_concurrency": 1,
        "http_request_delay": 1.0,
        "subfinder_rate_limit": 1,
    },
    "normal": {
        "nmap_timing": 3,
        "katana_rate_limit": 10,
        "katana_parallelism": 2,
        "katana_concurrency": 5,
        "http_concurrency": 5,
        "http_request_delay": 0.0,
        "subfinder_rate_limit": 10,
    },
    "fast": {
        "nmap_timing": 4,
        "katana_rate_limit": 50,
        "katana_parallelism": 4,
        "katana_concurrency": 10,
        "http_concurrency": 10,
        "http_request_delay": 0.0,
        "subfinder_rate_limit": 50,
    },
}
_TOOLS = {"katana", "nmap", "subfinder"}
_CLI_HELP_KEYS = {
    "allow_access_token_urls",
    "allow_large_networks",
    "ca_cert",
    "description",
    "doctor",
    "goals",
    "help",
    "http_concurrency",
    "http_timeout",
    "include_subdomains",
    "katana_concurrency",
    "katana_chrome",
    "katana_depth",
    "katana_executable",
    "katana_headless",
    "katana_headless_timeout",
    "katana_page_load_strategy",
    "katana_dom_wait",
    "katana_js",
    "katana_max_dom_mb",
    "katana_max_pages",
    "katana_max_total_pages",
    "katana_parallelism",
    "katana_rate_limit",
    "katana_request_timeout",
    "katana_timeout",
    "links_output",
    "nmap_executable",
    "nmap_all_ports",
    "nmap_timing",
    "nmap_timeout",
    "nmap_udp",
    "nmap_versiondb",
    "no_auto_headless",
    "output",
    "paths_file",
    "proxy",
    "schema",
    "speed",
    "standard_paths",
    "subfinder_all",
    "subfinder_executable",
    "subfinder_max_results",
    "subfinder_rate_limit",
    "subfinder_timeout",
    "targets_file",
    "tools",
    "top_ports",
    "urls_file",
    "user_agent",
}


def build_parser() -> argparse.ArgumentParser:
    editable_help = _load_cli_help()
    help_texts = {key: argparse.SUPPRESS for key in _CLI_HELP_KEYS}
    parser = _EditableHelpParser(
        prog="pointfinder",
        editable_help=editable_help,
        add_help=False,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=help_texts["help"],
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--doctor",
        action="store_true",
        help=help_texts["doctor"],
    )
    actions.add_argument(
        "--schema",
        action="store_true",
        help=help_texts["schema"],
    )
    actions.add_argument("--list-templates", action="store_true")
    parser.add_argument("-t", "--login-template", action="append", default=[], metavar="PRODUCT[,PRODUCT]")

    scan = parser
    scan.add_argument(
        "goals",
        nargs="*",
        metavar="ЦЕЛЬ",
        help=help_texts["goals"],
    )
    _add_inputs(scan, help_texts)
    _add_scope_options(scan, help_texts)
    scan.add_argument(
        "--page-only", action="store_true",
        help="Проверить только стартовые страницы и корни поддоменов без обхода ссылок; браузер при необходимости",
    )
    # Legacy compatibility: credential-like URLs no longer need this opt-in.
    scan.add_argument(
        "--allow-access-token-urls",
        action="store_true",
        help=help_texts["allow_access_token_urls"],
    )
    scan.add_argument(
        "--tools",
        type=_parse_tools,
        default=frozenset(),
        metavar="katana,nmap",
        help=help_texts["tools"],
    )
    scan.add_argument(
        "--output",
        type=Path,
        default=Path("report.json"),
        help=help_texts["output"],
    )
    scan.add_argument(
        "--links-output",
        type=Path,
        help=help_texts["links_output"],
    )
    scan.add_argument(
        "--no-json",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "--nmap-executable",
        default="nmap",
        help=help_texts["nmap_executable"],
    )
    scan.add_argument(
        "--nmap-versiondb",
        type=Path,
        help=help_texts["nmap_versiondb"],
    )
    scan.add_argument(
        "--katana-executable",
        default="katana",
        help=help_texts["katana_executable"],
    )
    scan.add_argument(
        "--katana-chrome",
        type=Path,
        help=help_texts["katana_chrome"],
    )
    speed_profile = scan.add_mutually_exclusive_group()
    speed_profile.add_argument(
        "--slow",
        dest="speed",
        action="store_const",
        const="slow",
        help=help_texts["speed"],
    )
    speed_profile.add_argument(
        "--normal",
        dest="speed",
        action="store_const",
        const="normal",
        help=help_texts["speed"],
    )
    speed_profile.add_argument(
        "--fast",
        dest="speed",
        action="store_const",
        const="fast",
        help=help_texts["speed"],
    )
    scan.set_defaults(speed="normal")
    nmap_ports = scan.add_mutually_exclusive_group()
    nmap_ports.add_argument(
        "--top-ports",
        type=_bounded_int(1, 65535),
        default=1000,
        help=help_texts["top_ports"],
    )
    nmap_ports.add_argument(
        "-p-",
        dest="nmap_all_ports",
        action="store_true",
        help=help_texts["nmap_all_ports"],
    )
    scan.add_argument(
        "--nmap-timeout",
        type=_positive_int,
        default=900,
        help=help_texts["nmap_timeout"],
    )
    scan.add_argument(
        "--nmap-timing",
        type=int,
        choices=range(6),
        help=help_texts["nmap_timing"],
    )
    scan.add_argument(
        "--nmap-udp",
        action="store_true",
        help=help_texts["nmap_udp"],
    )
    scan.add_argument(
        "--katana-depth",
        type=_bounded_int(0, 10),
        default=2,
        help=help_texts["katana_depth"],
    )
    scan.add_argument(
        "--katana-timeout",
        type=_positive_int,
        default=240,
        help=help_texts["katana_timeout"],
    )
    scan.add_argument(
        "--katana-request-timeout",
        type=_positive_int,
        default=10,
        help=help_texts["katana_request_timeout"],
    )
    scan.add_argument(
        "--katana-rate-limit",
        type=_positive_int,
        help=help_texts["katana_rate_limit"],
    )
    scan.add_argument(
        "--katana-parallelism",
        type=_bounded_int(1, 32),
        help=help_texts["katana_parallelism"],
    )
    scan.add_argument(
        "--katana-concurrency",
        type=_bounded_int(1, 100),
        help=help_texts["katana_concurrency"],
    )
    scan.add_argument(
        "--katana-max-pages",
        type=_positive_int,
        default=250,
        help=help_texts["katana_max_pages"],
    )
    scan.add_argument(
        "--katana-max-total-pages",
        type=_positive_int,
        default=None,
        help=help_texts["katana_max_total_pages"],
    )
    scan.add_argument(
        "--katana-max-dom-mb",
        type=_bounded_int(1, 32),
        default=2,
        help=help_texts["katana_max_dom_mb"],
    )
    scan.add_argument(
        "--katana-js",
        action="store_true",
        help=help_texts["katana_js"],
    )
    scan.add_argument(
        "--katana-headless",
        action="store_true",
        help=help_texts["katana_headless"],
    )
    scan.add_argument(
        "--katana-headless-timeout",
        type=_positive_int,
        default=60,
        help=help_texts["katana_headless_timeout"],
    )
    scan.add_argument(
        "--katana-page-load-strategy",
        choices=("domcontentloaded", "load", "heuristic", "networkidle", "none"),
        default="domcontentloaded",
        help=help_texts["katana_page_load_strategy"],
    )
    scan.add_argument(
        "--katana-dom-wait",
        type=_bounded_int(0, 120),
        default=5,
        metavar="N",
        help=help_texts["katana_dom_wait"],
    )
    scan.add_argument(
        "--no-auto-headless",
        action="store_true",
        help=help_texts["no_auto_headless"],
    )
    scan.add_argument(
        "--browser-resource-domain",
        action="append",
        type=validate_browser_resource_domain,
        default=[],
        metavar="HOST",
        help="Разрешить браузеру JS/CSS/изображения/шрифты с указанного хоста; можно повторять",
    )
    scan.add_argument(
        "--subfinder-executable",
        default="subfinder",
        help=help_texts["subfinder_executable"],
    )
    scan.add_argument(
        "--subfinder-timeout",
        type=_positive_int,
        default=120,
        help=help_texts["subfinder_timeout"],
    )
    scan.add_argument(
        "--subfinder-rate-limit",
        type=_positive_int,
        help=help_texts["subfinder_rate_limit"],
    )
    scan.add_argument(
        "--subfinder-max-results",
        type=_bounded_int(1, 5000),
        default=100,
        help=help_texts["subfinder_max_results"],
    )
    scan.add_argument(
        "--subfinder-all",
        action="store_true",
        help=help_texts["subfinder_all"],
    )
    scan.add_argument(
        "--user-agent",
        type=_user_agent,
        default=DEFAULT_USER_AGENT,
        help=help_texts["user_agent"],
    )
    scan.add_argument(
        "--proxy",
        type=_proxy_url,
        default="",
        metavar="HTTP_URL",
        help=help_texts["proxy"],
    )
    scan.add_argument(
        "--ca-cert",
        type=Path,
        help=help_texts["ca_cert"],
    )
    scan.add_argument(
        "--paths-timeout",
        dest="http_timeout",
        metavar="SECONDS",
        type=_positive_int,
        default=10,
        help=help_texts["http_timeout"],
    )
    scan.add_argument(
        "--paths-concurrency",
        dest="http_concurrency",
        metavar="N",
        type=_bounded_int(1, 100),
        help=help_texts["http_concurrency"],
    )
    scan.add_argument(
        "--http-timeout",
        dest="http_timeout",
        type=_positive_int,
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "--http-concurrency",
        dest="http_concurrency",
        type=_bounded_int(1, 100),
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "--paths-file",
        type=Path,
        help=help_texts["paths_file"],
    )
    scan.add_argument(
        "--standard-paths",
        action="store_true",
        help=help_texts["standard_paths"],
    )
    scan.add_argument(
        "--no-standard-paths",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    scan.add_argument("--no-nmap", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--no-katana", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--no-subfinder", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument(
        "--no-http-probe",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
    except (OSError, ValueError) as exc:
        print(f"[ERROR] Не удалось загрузить cli_help.txt: {exc}", file=sys.stderr)
        return 2
    args = parser.parse_args(argv)
    if args.schema:
        schema = files("authpoints").joinpath("report.schema.json")
        print(schema.read_text(encoding="utf-8"), end="")
        return 0
    if args.doctor:
        status = check_environment(
            args.nmap_executable,
            args.katana_executable,
            str(args.nmap_versiondb) if args.nmap_versiondb else "",
            args.subfinder_executable,
        )
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0 if status["ready"] else 1

    try:
        load_login_templates.cache_clear()
        selected_templates = parse_template_selection(args.login_template)
        if args.list_templates:
            for template in load_login_templates():
                print(f"{template.id:12} {template.label}")
            return 0
        goal_targets, goal_urls = _split_goals([*args.goals, *_expand_url_inputs(args.explicit_goals)])
        targets = [
            *goal_targets,
            *args.target,
            *_read_line_files(args.targets_file),
        ]
        urls = list(dict.fromkeys([*goal_urls, *args.url, *_read_line_files(args.urls_file)]))
        if not targets and not urls:
            parser.error("укажите -u URL или -u FILE со списком HTTP(S) URL")
        implicit_web = bool(
            not args.page_only and not args.tools
            and not args.paths_file and not args.standard_paths
        )
        if implicit_web:
            if targets:
                parser.error("для веб-поиска укажите полный http(s) URL; сетевые цели требуют явного -t")
            args.tools = frozenset({"katana"})
            args.standard_paths = not args.no_standard_paths
        if args.page_only:
            if args.standard_paths or args.paths_file or "katana" in args.tools:
                parser.error("--page-only нельзя сочетать с Katana или стандартными путями")
            if args.no_http_probe:
                parser.error("--page-only требует HTTP-проверку; уберите --no-http-probe")
        speed = _SPEED_PRESETS[args.speed]
        nmap_enabled = "nmap" in args.tools and not args.no_nmap
        katana_enabled = "katana" in args.tools and not args.no_katana
        subfinder_enabled = "subfinder" in args.tools and not args.no_subfinder
        if (args.katana_headless or args.no_auto_headless) and not katana_enabled:
            parser.error("Katana rendering options require --tools katana")
        if args.browser_resource_domain and not (katana_enabled or args.page_only):
            parser.error("--browser-resource-domain требует --tools katana или --page-only")
        if nmap_enabled:
            targets = list(dict.fromkeys([*targets, *_nmap_targets_from_urls(urls)]))
        if katana_enabled and not nmap_enabled and not subfinder_enabled and not urls:
            parser.error("Katana without Nmap requires a full http(s) URL")
        if not args.tools and targets and not urls and not args.page_only:
            parser.error("without -t, provide a full http(s) URL")
        standard_paths = []
        if not args.no_standard_paths and (args.paths_file is not None or args.standard_paths):
            if args.paths_file is not None:
                standard_paths = load_standard_paths(args.paths_file)
            elif selected_templates:
                standard_paths = template_paths(selected_templates)
            else:
                standard_paths = list(dict.fromkeys([*load_standard_paths(None), *template_paths(())]))
        if implicit_web and not any((nmap_enabled, katana_enabled, subfinder_enabled, standard_paths, args.page_only)):
            parser.error("все способы поиска отключены; выберите Katana, пути или --page-only")
        config = ScanConfig(
            speed_profile=args.speed,
            include_subdomains=args.include_subdomains or subfinder_enabled,
            page_only=args.page_only,
            standard_paths=standard_paths,
            login_templates=selected_templates,
            nmap=NmapConfig(
                executable=args.nmap_executable,
                version_db=(
                    str(args.nmap_versiondb) if args.nmap_versiondb else ""
                ),
                enabled=nmap_enabled,
                timeout_seconds=args.nmap_timeout,
                top_ports=args.top_ports,
                all_ports=args.nmap_all_ports,
                timing_template=_override(
                    args.nmap_timing,
                    speed["nmap_timing"],
                ),
                udp_enabled=args.nmap_udp,
            ),
            subfinder=SubfinderConfig(
                executable=args.subfinder_executable,
                enabled=subfinder_enabled,
                timeout_seconds=args.subfinder_timeout,
                rate_limit_per_second=_override(
                    args.subfinder_rate_limit,
                    speed["subfinder_rate_limit"],
                ),
                max_results=args.subfinder_max_results,
                all_sources=args.subfinder_all,
                proxy=args.proxy,
            ),
            katana=KatanaConfig(
                executable=args.katana_executable,
                chrome_executable=(
                    str(args.katana_chrome) if args.katana_chrome else ""
                ),
                enabled=katana_enabled,
                timeout_seconds=args.katana_timeout,
                depth=max(1, args.katana_depth),
                request_timeout_seconds=args.katana_request_timeout,
                concurrency=_override(
                    args.katana_concurrency,
                    speed["katana_concurrency"],
                ),
                parallelism=_override(
                    args.katana_parallelism,
                    speed["katana_parallelism"],
                ),
                rate_limit_per_second=_override(
                    args.katana_rate_limit,
                    speed["katana_rate_limit"],
                ),
                max_domain_pages=args.katana_max_pages,
                max_total_pages=args.katana_max_total_pages,
                max_dom_bytes=args.katana_max_dom_mb * 1024 * 1024,
                js_crawl=args.katana_js,
                headless=args.katana_headless,
                auto_headless=(
                    katana_enabled
                    and not args.katana_headless
                    and not args.no_auto_headless
                ),
                auto_headless_timeout_seconds=args.katana_headless_timeout,
                page_load_strategy=args.katana_page_load_strategy,
                dom_wait_seconds=args.katana_dom_wait,
                user_agent=args.user_agent,
                proxy=args.proxy,
                ca_cert=str(args.ca_cert.expanduser().resolve()) if args.ca_cert else "",
                browser_resource_domains=tuple(dict.fromkeys(args.browser_resource_domain)),
                browser_diagnostics_dir=str(
                    args.output.expanduser().resolve().parent / "discovery-debug"
                ),
            ),
            http=HttpConfig(
                enabled=(bool(standard_paths) or args.page_only) and not args.no_http_probe,
                timeout_seconds=args.http_timeout,
                concurrency=_override(
                    args.http_concurrency,
                    int(speed["http_concurrency"]),
                ),
                request_delay_seconds=float(speed["http_request_delay"]),
                user_agent=args.user_agent,
                proxy=args.proxy,
                ca_cert=str(args.ca_cert.expanduser().resolve()) if args.ca_cert else "",
            ),
        )
        report = run_active_scan(
            targets,
            urls,
            config,
            allow_large_networks=args.allow_large_networks,
            on_finding=_print_finding,
            on_progress=_print_progress,
        )
        diagnostics_dir = Path(config.katana.browser_diagnostics_dir)
        if diagnostics_dir.is_dir():
            _print_progress(f"[DEBUG] DOM и диагностика браузера: {diagnostics_dir}")
        links_output = args.links_output or _default_links_output(args.output)
        if links_output.expanduser().resolve() == args.output.expanduser().resolve():
            raise ValueError("JSON report and links output must be different files")
        if not args.no_json:
            _print_progress(f"[OUTPUT] Запись JSON: {args.output.resolve()}")
            write_json_report(report, args.output)
        _print_progress(f"[OUTPUT] Запись ссылок: {links_output.resolve()}")
        write_links_report(report, links_output)
    except KeyboardInterrupt:
        print(
            "\n[ОСТАНОВЛЕНО] Поиск точек входа прерван пользователем. "
            "Уже созданные файлы сохранены.",
            file=sys.stderr,
            flush=True,
        )
        return 130
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr, flush=True)
        return 2

    print(
        f"Готово: найдено {len(report.findings)} точек, "
        f"сервисов {len(report.services)}, ошибок/предупреждений {len(report.issues)}. "
        + (f"JSON: {args.output.resolve()}. " if not args.no_json else "")
        + f"Ссылки: {links_output.resolve()}"
    )
    return 3 if report.partial else 0


def _add_inputs(
    parser: argparse.ArgumentParser,
    help_texts: dict[str, str],
) -> None:
    # Explicit -u goals and positional goals use the same URL/host routing.
    parser.add_argument(
        "-u",
        dest="explicit_goals",
        action="append",
        default=[],
        metavar="URL|FILE",
        help=help_texts["goals"],
    )
    # Legacy aliases are still accepted so existing scripts do not break.
    parser.add_argument("--target", action="append", default=[], help=argparse.SUPPRESS)
    parser.add_argument(
        "--targets-file",
        type=Path,
        action="append",
        default=[],
        help=help_texts["targets_file"],
    )
    parser.add_argument("--url", action="append", default=[], help=argparse.SUPPRESS)
    parser.add_argument(
        "--urls-file",
        type=Path,
        action="append",
        default=[],
        help=help_texts["urls_file"],
    )


def _default_links_output(json_output: Path) -> Path:
    if json_output.suffix.lower() == ".txt":
        return json_output.with_name(json_output.stem + ".links.txt")
    return json_output.with_suffix(".txt")


def _print_finding(finding: Finding) -> None:
    template = finding.metadata.get("login_template")
    tag = f" [{template}]" if template else ""
    print(f"[FOUND]{tag} {finding.auth_type} {finding.endpoint}", flush=True)


def _print_progress(message: str) -> None:
    print(message, flush=True)


def _add_scope_options(
    parser: argparse.ArgumentParser,
    help_texts: dict[str, str],
) -> None:
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help=help_texts["include_subdomains"],
    )
    parser.add_argument(
        "--allow-large-networks",
        action="store_true",
        help=help_texts["allow_large_networks"],
    )


class _EditableHelpParser(argparse.ArgumentParser):
    def __init__(self, *args: object, editable_help: str, **kwargs: object) -> None:
        self._editable_help = editable_help
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        return self._editable_help.rstrip() + "\n"


def _load_cli_help() -> str:
    resource = files("authpoints").joinpath("data/cli_help.txt")
    text = resource.read_text(encoding="utf-8-sig")
    if not text.strip():
        raise ValueError("cli_help.txt is empty")
    return text


def _split_goals(values: list[str]) -> tuple[list[str], list[str]]:
    targets: list[str] = []
    urls: list[str] = []
    for value in values:
        if value.lower().startswith(("http://", "https://")):
            urls.append(value)
        else:
            targets.append(value)
    return targets, urls


def _expand_url_inputs(values: list[str]) -> list[str]:
    expanded: list[str] = []
    for value in values:
        if value.lower().startswith(("http://", "https://")):
            expanded.append(normalize_url(value, redact_query=False))
            continue
        path = Path(value).expanduser()
        if path.exists():
            if not path.is_file():
                raise ValueError(f"-u: ожидается файл со списком URL, а не каталог: {path}")
            lines = _read_line_files([path])
            if not lines:
                raise ValueError(f"-u: файл не содержит URL: {path}")
            for line in lines:
                if not line.lower().startswith(("http://", "https://")):
                    raise ValueError(f"{path}: нужен полный HTTP(S) URL, получено {line!r}")
                expanded.append(normalize_url(line, redact_query=False))
        elif path.suffix.lower() in {".txt", ".list", ".csv"} or value.startswith(("/", "./", "../", "~")):
            raise ValueError(f"-u: файл не найден: {path}")
        else:
            # Preserve legacy host/IP/CIDR input for explicitly selected tools.
            expanded.append(value)
    return expanded


def _nmap_targets_from_urls(urls: list[str]) -> list[str]:
    targets: list[str] = []
    for url in urls:
        normalized = normalize_url(url, redact_query=False)
        host = urlsplit(normalized).hostname
        if host:
            targets.append(host)
    return list(dict.fromkeys(targets))


def _parse_tools(value: str) -> frozenset[str]:
    tools = {item.strip().lower() for item in value.split(",") if item.strip()}
    unknown = tools - _TOOLS
    if not tools or unknown:
        detail = ", ".join(sorted(unknown)) if unknown else "empty list"
        raise argparse.ArgumentTypeError(f"invalid tools: {detail}")
    return frozenset(tools)


def _user_agent(value: str) -> str:
    try:
        return validate_user_agent(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _proxy_url(value: str) -> str:
    try:
        return validate_proxy_url(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _read_line_files(paths: list[Path]) -> list[str]:
    result: list[str] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                result.append(value)
    return result


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _bounded_int(minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        parsed = int(value)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"value must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def _override(value: int | None, default: int) -> int:
    return default if value is None else value
