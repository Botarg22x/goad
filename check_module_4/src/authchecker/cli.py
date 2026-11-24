from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from threading import Lock
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .adapters import (
    AdapterRegistry,
    HttpBasicAdapter,
    ProxyHttpClient,
    TargetScope,
    validate_live_job,
)
from .audit import JsonlAuditWriter
from .adapters.http import validate_target_url
from .browser import BrowserCheckConfig, run_browser_check
from .browser_adapter import BrowserAdapter, TemplateFormAdapter
from .template_profile import profile_from_metadata
from .browser_http import AdaptiveBrowserChecker, BrowserHttpChecker
from .defaults import DEFAULT_USER_AGENT
from .discovery import discover_login_pages, discover_login_url
from .importer import PointFinderReport, ReportValidationError, load_report
from .jobs import DEFAULT_SUPPORTED_AUTH_TYPES, build_jobs
from .loaders import count_candidates, iter_credentials, load_logins, load_passwords
from .models import (
    AuthJob,
    Credential,
    Outcome,
    OutcomeStatus,
    outcome_attempted_count,
)
from .planning import build_dry_run_plan
from .policy import AttemptPolicy
from .scheduler import ScheduleResult, Scheduler


LIVE_HTTP_AUTH_TYPES = frozenset({"http_basic", "password_form"})
SLOW_INTERVAL_SECONDS = 15.0
SLOW_RATE_PER_SECOND = 1.0 / SLOW_INTERVAL_SECONDS


def _attempt_budget(
    job_count: int, login_count: int, password_count: int,
    max_per_account: int, max_total: int | None,
) -> int:
    """Upper bound; a success, lockout or unsupported form can stop earlier."""
    potential = job_count * login_count * min(password_count, max_per_account)
    return min(potential, max_total) if max_total is not None else potential


class _AttemptProgress:
    """Render one in-place progress line and announce confirmed successes."""

    def __init__(
        self, budget: int, *, per_login_budget: int | None = None,
        stream=None, success_stream=None,
    ) -> None:
        self.budget = budget
        self.per_login_budget = per_login_budget
        self.stream = sys.stderr if stream is None else stream
        self.success_stream = success_stream
        self.enabled = self.stream.isatty()
        self.checked = 0
        self.attempted = 0
        self.current_login: str | None = None
        self.login_attempts: Counter[str] = Counter()
        self._lock = Lock()

    def start(self) -> None:
        with self._lock:
            self._render()

    def record(self, attempt, attempted_count: int) -> None:
        with self._lock:
            self.checked += 1
            self.attempted = attempted_count
            if self.per_login_budget is not None:
                self.current_login = attempt.credential.username
                self.login_attempts[self.current_login] += outcome_attempted_count(attempt.outcome)
            if self.success_stream is not None and attempt.outcome.status is OutcomeStatus.SUCCESS:
                if self.enabled:
                    self.stream.write("\r\x1b[2K")
                    self.stream.flush()
                self.success_stream.write(
                    f"[УСПЕШНО] {_terminal_value(attempt.job.endpoint)} — "
                    f"логин: {_terminal_value(attempt.credential.username)} — "
                    f"пароль: {_terminal_value(attempt.credential.password)}\n"
                )
                self.success_stream.flush()
            if attempt is not None and attempt.outcome.status is OutcomeStatus.AMBIGUOUS:
                if self.enabled:
                    self.stream.write("\r\x1b[2K")
                    self.stream.flush()
                notice_stream = self.success_stream if self.success_stream is not None else self.stream
                detail = attempt.outcome.detail or "Признаков для подтверждения входа недостаточно"
                if attempt.credential.password:
                    detail = detail.replace(attempt.credential.password, "<redacted>")
                evidence = attempt.outcome.evidence
                statuses = []
                for key, label in (("post_status", "POST"), ("http_status", "итоговый HTTP")):
                    status = evidence.get(key)
                    if type(status) is int:
                        statuses.append(f"{label} {status}")
                credentials = (
                    f"логин: {_terminal_value(attempt.credential.username)} — "
                    f"пароль: {_terminal_value(attempt.credential.password)}"
                    if outcome_attempted_count(attempt.outcome)
                    else f"логин: {_terminal_value(attempt.credential.username)}; пароль не отправлялся"
                )
                diagnostics = "; ".join([*statuses, _terminal_value(detail)])
                notice_stream.write(
                    f"[РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН] {_terminal_value(attempt.job.endpoint)} — "
                    f"{credentials}; {diagnostics}; проверьте ответ вручную\n"
                )
                notice_stream.flush()
            self._render()

    def note(self, message: str) -> None:
        with self._lock:
            if self.enabled:
                self.stream.write("\r\x1b[2K")
            self.stream.write(f"[BROWSER] {_terminal_value(message)}\n")
            self.stream.flush()
            self._render()

    def finish(self) -> None:
        with self._lock:
            if self.enabled:
                self.stream.write(
                    f"\r\x1b[2K[ПОПЫТКИ] Завершено: отправлено {self.attempted}; "
                    f"проверено {self.checked}\n"
                )
                self.stream.flush()

    def _render(self) -> None:
        if not self.enabled:
            return
        if self.per_login_budget is not None:
            if self.current_login is None:
                login, count = "ожидание", 0
            else:
                login = f"«{_terminal_value(self.current_login)}»"
                count = self.login_attempts[self.current_login]
            self.stream.write(
                f"\r\x1b[2K[ПОПЫТКИ] Логин из файла: {login} — "
                f"{count}/{self.per_login_budget}; всего: {self.attempted}/{self.budget}"
            )
            self.stream.flush()
            return
        remaining = max(0, self.budget - self.attempted)
        self.stream.write(
            f"\r\x1b[2K[ПОПЫТКИ] Отправлено: {self.attempted}/{self.budget}; "
            f"осталось не более {remaining}; проверено: {self.checked}"
        )
        self.stream.flush()


class RussianArgumentParser(argparse.ArgumentParser):
    """Keep argparse behaviour while localizing its fixed help labels."""

    def format_usage(self) -> str:
        return super().format_usage().replace("usage: ", "Использование: ", 1)

    def format_help(self) -> str:
        resource = getattr(self, "_help_resource", None)
        if resource is not None:
            try:
                content = files("authchecker").joinpath("data", resource).read_text(encoding="utf-8-sig")
                if content.strip():
                    return content.rstrip() + "\n"
            except (FileNotFoundError, OSError, UnicodeError):
                pass
        return super().format_help().replace("usage: ", "Использование: ", 1)


def _localize_help(parser: argparse.ArgumentParser) -> None:
    parser._positionals.title = "Позиционные аргументы"
    parser._optionals.title = "Параметры"
    for action in parser._actions:
        if action.dest == "help":
            action.help = "показать эту справку и выйти"


def _existing_input_file(value: str) -> Path:
    """Return an existing regular file or report a CLI-friendly error."""

    path = Path(value).expanduser()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"файл не найден: {path}")
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"ожидался файл, но указан каталог: {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = RussianArgumentParser(
        prog="goad check",
        description=(
            "Модуль 4: проверить найденные страницы входа или отчёт PointFinder, "
            "показать план или выполнить ограниченные попытки авторизации. Для внешней цели "
            "область проверки ограничивается указанным доменом и его поддоменами."
        ),
        epilog=(
            "Короткий запуск по найденным страницам (JSON не нужен):\n"
            "  goad check -u auth-links.txt -l admin -p password123 --max-per-account 1 --rate 1\n"
            "  goad check -u auth-links.txt -l admin -p passwords.txt --max-per-account 5 --slow\n"
            "  goad check -u https://site.example/bitrix/admin/ -t bitrix -l admin -p password123 --max-per-account 1 --rate 1\n\n"
            "Запуск по готовому отчёту (реальные попытки):\n"
            "  goad check -r report.json -l student -p password123 --max-per-account 1 --rate 1\n"
            "  goad check -r report.json -l logins.txt -p passwords.txt --max-per-account 3 --slow\n\n"
            "Порядок работы с подробными настройками:\n"
            "  1. goad check validate report.json\n"
            "  2. goad check plan --report report.json --logins logins.txt "
            "--passwords passwords.txt\n"
            "  3. goad check run --dry-run --report report.json "
            "--logins logins.txt --passwords passwords.txt\n"
            "  4. goad check run --live --report report.json "
            "--logins logins.txt --passwords passwords.txt --audit audit.jsonl "
            "--max-per-account 3 --rate 1\n\n"
            "Подробные параметры запуска: goad check run -h"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser(
        "validate",
        help="проверить структуру отчёта PointFinder",
        description="Проверить report.json без сетевых запросов.",
    )
    validate.add_argument(
        "report",
        type=_existing_input_file,
        metavar="REPORT.json",
        help="проверяемый JSON-отчёт PointFinder",
    )

    plan = subparsers.add_parser(
        "plan",
        help="показать план без сетевых запросов",
        description=(
            "Проверить входные файлы и посчитать будущие задания без обращения "
            "к целевому сайту."
        ),
        epilog=(
            "Пример:\n"
            "  goad check plan --report report.json "
            "--logins logins.txt --passwords passwords.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_plan_arguments(plan)

    run = subparsers.add_parser(
        "run",
        help="построить план или выполнить ограниченные HTTP-проверки",
        description=(
            "Проверить готовый report.json, точную страницу или файл URL. "
            "Для плана без сети используйте --dry-run с отчётом; для -u нужен --live, "
            "поскольку сначала выполняется анализ страницы. --live запускает "
            "реальных запросов к разрешённой цели."
        ),
        epilog=(
            "Примеры:\n"
            "  goad check run --dry-run --report report.json "
            "--login student --password password123\n\n"
            "  goad check run --live -u https://site.example/login -t bitrix "
            "--login student --passwords passwords.txt --audit audit.jsonl "
            "--max-total 3 --max-per-account 3 --rate 1 --threads 1"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_plan_arguments(run, allow_url=True)
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="не отправлять сетевые запросы",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="выполнить ограниченные HTTP(S)-проверки",
    )
    run.add_argument(
        "--audit",
        type=Path,
        help="записывать события без паролей в JSONL; в коротком запуске создаётся рядом с файлом URL или в текущем каталоге",
    )
    run.add_argument(
        "--proxy",
        help="необязательный HTTP-прокси, например Burp, ZAP или mitmproxy",
    )
    run.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent поиска и авторизации (по умолчанию Chrome/Linux)",
    )
    run.add_argument(
        "--scope-domain",
        help="разрешённый домен цели; для одного хоста определяется автоматически",
    )
    run.add_argument(
        "--allow-subdomains",
        action="store_true",
        help="разрешить поддомены значения --scope-domain",
    )
    run.add_argument(
        "--ca-cert",
        type=_existing_input_file,
        metavar="FILE",
        help="проверять HTTPS через прокси с этим CA; без него при --proxy проверка отключена",
    )
    run.add_argument(
        "--save-report",
        type=Path,
        metavar="REPORT.json",
        help="с -u/--url: сохранить отчёт PointFinder для диагностики (необязательно)",
    )
    run.add_argument("--rate", type=float, default=1.0, help="попыток в секунду; по умолчанию 1, максимум 10")
    run.add_argument(
        "--threads",
        type=int,
        default=1,
        help="параллельных потоков авторизации; по умолчанию 1, максимум 10",
    )
    run.add_argument(
        "--slow",
        action="store_true",
        help="щадящий режим: одна попытка в 15 секунд и один поток",
    )
    run.add_argument(
        "--compact",
        action="store_true",
        help="печатать короткую строку по каждой точке вместо JSON",
    )
    run.add_argument(
        "--auto-login-candidates",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    run.add_argument("--max-total", type=int, help="общий лимит попыток; без флага не задан, максимум 1000")
    run.add_argument(
        "--max-per-account",
        type=int,
        default=100000000000000,
        help="лимит на одну точку и логин; без флага явный предел не задан",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="таймаут запроса в секундах; максимум 60",
    )
    browser_mode = run.add_mutually_exclusive_group()
    browser_mode.add_argument("--browser", action="store_true", help="проверять пары в изолированных браузерных сессиях")
    browser_mode.add_argument("--browser-http", action="store_true", help="получить запрос и cookies в браузере, затем проверять через HTTP")
    browser_mode.add_argument("--auto-browser", action="store_true", help="начать с HTTP и подключить браузер при таймауте, 403, JavaScript или session/CSRF")
    run.add_argument("--headless", action="store_true", help="не показывать окно браузера")
    run.add_argument("--browser-timeout", type=float, help="ожидать страницу или форму 1–300 секунд; по умолчанию 60")
    run.add_argument("--success-selector", help="CSS-селектор, подтверждающий успешный вход")
    run.add_argument("--failure-selector", help="CSS-селектор, подтверждающий неудачный вход")
    for command_parser in (parser, validate, plan, run):
        _localize_help(command_parser)
    parser._help_resource = "cli_help.txt"
    validate._help_resource = "validate_help.txt"
    plan._help_resource = "plan_help.txt"
    run._help_resource = "run_help.txt"
    return parser


def _add_plan_arguments(
    parser: argparse.ArgumentParser,
    *,
    allow_url: bool = False,
) -> None:
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument(
        "-r", "--report",
        type=_existing_input_file,
        metavar="REPORT.json",
        help="готовый JSON-отчёт PointFinder",
    )
    if allow_url:
        sources.add_argument(
            "-u", "--pages",
            dest="pages_source",
            metavar="URL|FILE",
            help="готовая страница входа или TXT-файл URL; проверяются только эти страницы",
        )
        sources.add_argument(
            "--url",
            metavar="HTTP_URL",
            help="старый вариант для одной страницы; для списка и шаблона используйте -u",
        )
        parser.add_argument(
            "-t", "--template",
            dest="login_template",
            metavar="ID",
            help="шаблон продукта, например bitrix; совпадение проверяется перед отправкой пароля",
        )
    logins = parser.add_mutually_exclusive_group(required=True)
    logins.add_argument(
        "--logins",
        dest="logins_path",
        type=_existing_input_file,
        metavar="LOGINS.txt",
        help="файл логинов",
    )
    logins.add_argument(
        "-l",
        dest="smart_logins",
        action="append",
        metavar="VALUE|FILE",
        help="один логин или существующий файл; значения можно повторять, файл — нет",
    )
    logins.add_argument(
        "--login",
        dest="login_values",
        action="append",
        metavar="VALUE",
        help="один логин без распознавания файла; флаг можно повторять",
    )
    passwords = parser.add_mutually_exclusive_group(required=True)
    passwords.add_argument(
        "--passwords",
        type=_existing_input_file,
        metavar="PASSWORDS.txt",
        help="файл паролей; предпочтительно для чувствительных значений",
    )
    passwords.add_argument(
        "-p",
        dest="smart_passwords",
        action="append",
        metavar="VALUE|FILE",
        help="один пароль или существующий файл; значения можно повторять, файл — нет",
    )
    passwords.add_argument(
        "--password",
        dest="password_values",
        action="append",
        metavar="VALUE",
        help="один пароль без распознавания файла; флаг можно повторять",
    )
    parser.add_argument(
        "--password-encoding", default="utf-8", metavar="ENCODING",
        help="кодировка файла паролей; по умолчанию utf-8",
    )
    parser.add_argument(
        "--auth-type",
        action="append",
        dest="auth_types",
        metavar="TYPE",
        help=(
            "разрешить тип авторизации; можно повторять; по умолчанию: "
            + ", ".join(sorted(DEFAULT_SUPPORTED_AUTH_TYPES))
        ),
    )


def _short_run_arguments(argv: list[str]) -> tuple[list[str], bool]:
    """A leading option means the explicit module-4 command is the action."""
    if not argv or argv[0] in {"-h", "--help"} or not argv[0].startswith("-"):
        return argv, False
    mode = [] if any(token in {"--live", "--dry-run"} for token in argv) else ["--live"]
    return ["run", *mode, *argv], True


def _has_option(argv: list[str], name: str) -> bool:
    return any(token == name or token.startswith(name + "=") for token in argv)


def _resolve_smart_passwords(args: argparse.Namespace) -> None:
    """Keep file-backed -p streaming; preserve repeated inline -p values."""
    values = args.smart_passwords
    if not values:
        return
    files: list[Path] = []
    for value in values:
        path = Path(value).expanduser()
        if path.is_file():
            files.append(path)
        elif path.exists():
            raise ValueError(f"-p: ожидался файл, но указан каталог: {path}")
        elif "/" in value or "\\" in value or value.lower().endswith((".txt", ".lst", ".csv")):
            raise ValueError(f"-p: файл паролей не найден: {path}; для буквального пароля используйте --password")
    if files:
        if len(values) != 1:
            raise ValueError("-p: файл нельзя смешивать с отдельными паролями; используйте один файл или повторяйте -p со значениями")
        args.passwords = files[0]
    else:
        args.password_values = values


def _resolve_smart_logins(args: argparse.Namespace) -> None:
    """Keep file-backed -l streaming; preserve repeated inline -l values."""
    values = args.smart_logins
    if not values:
        return
    files: list[Path] = []
    for value in values:
        path = Path(value).expanduser()
        if path.is_file():
            files.append(path)
        elif path.exists():
            raise ValueError(f"-l: ожидался файл, но указан каталог: {path}")
        elif "/" in value or "\\" in value or value.lower().endswith((".txt", ".lst", ".csv")):
            raise ValueError(f"-l: файл логинов не найден: {path}; для буквального логина используйте --login")
    if files:
        if len(values) != 1:
            raise ValueError("-l: файл нельзя смешивать с отдельными логинами; используйте один файл или повторяйте -l со значениями")
        args.logins_path = files[0]
    else:
        args.login_values = values


def _page_urls(source: str) -> list[str]:
    if source.startswith(("http://", "https://")):
        urls = [source]
    else:
        try:
            path = _existing_input_file(source)
        except argparse.ArgumentTypeError as exc:
            raise ValueError(str(exc)) from exc
        urls = [
            line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not urls:
        raise ValueError("файл страниц входа пуст")
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError(f"ожидался полный HTTP(S) URL, получено: {url}")
    return list(dict.fromkeys(urls))


def _scope_for_pages(args: argparse.Namespace, urls: list[str]) -> TargetScope:
    hosts = {urlsplit(url).hostname.lower().rstrip(".") for url in urls}
    if args.scope_domain is None:
        if len(hosts) != 1:
            raise ValueError(
                "в файле несколько хостов; укажите --scope-domain ДОМЕН "
                "--allow-subdomains либо разделите список по хостам"
            )
        args.scope_domain = next(iter(hosts))
    scope = TargetScope.from_domain(
        args.scope_domain, include_subdomains=args.allow_subdomains,
    )
    assert scope is not None
    for url in urls:
        validate_target_url(url, scope)
    return scope


def _prepare_short_live(
    args: argparse.Namespace,
    original: list[str],
    *,
    report_override: PointFinderReport | None = None,
) -> None:
    """Fill only safe, unambiguous defaults for the concise report workflow."""
    if args.url is not None:
        raise ValueError("для короткого запуска по URL используйте -u URL")
    report = report_override or load_report(args.report)
    auth_types = frozenset(args.auth_types) if args.auth_types else LIVE_HTTP_AUTH_TYPES
    jobs = build_jobs(report, supported_auth_types=auth_types & LIVE_HTTP_AUTH_TYPES)
    if not jobs:
        raise ValueError("в отчёте нет поддерживаемых точек входа; сначала проверьте результат discover")
    if args.scope_domain is None:
        hosts = {job.host for job in jobs}
        if len(hosts) != 1:
            raise ValueError(
                "в отчёте несколько хостов; для одного домена с поддоменами "
                "укажите --scope-domain ДОМЕН --allow-subdomains; разные домены "
                "проверяйте отдельными отчётами"
            )
        args.scope_domain = next(iter(hosts))
    if args.audit is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        source_path = (
            Path(args.pages_source).expanduser()
            if args.pages_source and not args.pages_source.startswith(("http://", "https://"))
            else args.report if args.report else Path.cwd() / "auth-pages.txt"
        )
        args.audit = source_path.with_name(
            f"{source_path.stem}-auth-{stamp}-{uuid4().hex[:8]}.jsonl"
        )
    args.compact = True




def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    original = list(sys.argv[1:] if argv is None else argv)
    arguments, short_run = _short_run_arguments(original)
    args = parser.parse_args(arguments)
    try:
        if args.command in {"plan", "run"}:
            _resolve_smart_logins(args)
            _resolve_smart_passwords(args)
        report_override = None
        if args.command == "run" and args.login_template and not args.pages_source:
            raise ValueError("-t/--template используется вместе с -u URL|FILE")
        if args.command == "run" and args.pages_source:
            if not args.live:
                raise ValueError("-u требует --live: анализ страниц выполняет HTTP GET")
            _validate_live_limits(args)
            _validated_inline_logins(args.login_values)
            _validated_inline_passwords(args.password_values)
            if any((args.browser, args.browser_http, args.auto_browser)):
                raise ValueError(
                    "-u уже включает браузерный анализ страницы при необходимости; "
                    "не добавляйте отдельный режим браузерной авторизации"
                )
            if (
                args.save_report is not None
                and not args.pages_source.startswith(("http://", "https://"))
                and args.save_report.expanduser().resolve()
                == Path(args.pages_source).expanduser().resolve()
            ):
                raise ValueError("--save-report не должен перезаписывать входной файл URL")
            urls = _page_urls(args.pages_source)
            scope = _scope_for_pages(args, urls)
            report_override = discover_login_pages(
                urls,
                template=args.login_template,
                proxy=args.proxy,
                timeout_seconds=args.timeout,
                user_agent=args.user_agent,
                target_scope=scope,
                ca_cert=args.ca_cert,
                save_report=args.save_report,
            )
            if not build_jobs(report_override, supported_auth_types=LIVE_HTTP_AUTH_TYPES):
                raise ValueError(
                    "на указанных страницах не найдена форма пароля или HTTP Basic"
                    + (f" по шаблону {args.login_template}" if args.login_template else "")
                    + "; попытки авторизации не выполнялись"
                )
        if short_run and args.command == "run" and args.live:
            _prepare_short_live(args, original, report_override=report_override)
        if args.command == "validate":
            report = load_report(args.report)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "schema_version": report.schema_version,
                        "run_id": report.run_id,
                        "partial": report.partial,
                        "findings": len(report.findings),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        login_values = _validated_inline_logins(args.login_values)
        password_values = _validated_inline_passwords(args.password_values)
        if args.command == "run":
            if args.live and args.slow:
                # Validate explicit values before narrowing them, so --slow does
                # not silently accept otherwise invalid limits.
                _validate_live_limits(args)
                args.rate = min(args.rate, SLOW_RATE_PER_SECOND)
                args.threads = 1
            browser_requested = args.browser or args.browser_http or args.auto_browser
            if not browser_requested and any((args.headless, args.browser_timeout is not None, args.success_selector is not None, args.failure_selector is not None)):
                raise ValueError("--headless/--browser-timeout/--success-selector/--failure-selector require a browser mode")
            if args.auto_browser:
                return _run_auto_browser(args, login_values, password_values)
            if args.browser or args.browser_http:
                return _run_browser(args, login_values, password_values)
        if args.command == "run" and args.url and not args.live:
            raise ValueError("--url requires --live because discovery performs an HTTP GET")
        if args.command == "run" and args.save_report is not None and not (args.url or args.pages_source):
            raise ValueError("--save-report используется только с -u или --url")
        if args.command == "run" and args.live:
            auth_types = (
                frozenset(args.auth_types) if args.auth_types else LIVE_HTTP_AUTH_TYPES
            )
            code = _run_live(
                args, auth_types, login_values, password_values,
                report_override=report_override,
            )
            if short_run and code == 0:
                print(f"[ФАЙЛ] Журнал авторизации: {args.audit}")
            return code

        auth_types = (
            frozenset(args.auth_types) if args.auth_types
            else LIVE_HTTP_AUTH_TYPES if short_run
            else DEFAULT_SUPPORTED_AUTH_TYPES
        )
        plan = build_dry_run_plan(
            args.report,
            args.logins_path,
            args.passwords,
            password_encoding=args.password_encoding,
            supported_auth_types=auth_types,
            login_values=login_values,
            password_values=password_values,
        )
        payload = plan.as_dict()
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        if args.command == "run" and args.audit:
            with JsonlAuditWriter(args.audit) as writer:
                writer.write_event(
                    {
                        "event": "dry_run_plan",
                        "report_run_id": plan.report_run_id,
                        "job_count": plan.job_count,
                        "login_count": plan.login_count,
                        "password_count": plan.password_count,
                        "potential_attempt_count": plan.potential_attempt_count,
                    }
                )
        return 0
    except (ReportValidationError, OSError, LookupError, UnicodeError, ValueError) as exc:
        print(f"authchecker: {exc}", file=sys.stderr)
        return 2


def _validate_browser_inputs(
    args: argparse.Namespace,
    login_values: tuple[str, ...],
    password_values: tuple[str, ...],
) -> tuple[int, int]:
    """Validate streams without retaining password lists or expanding pairs."""
    sources = (
        ("login", load_logins(args.logins_path) if args.logins_path else login_values),
        ("password", load_passwords(args.passwords, encoding=args.password_encoding) if args.passwords else password_values),
    )
    counts: list[int] = []
    for label, values in sources:
        count = 0
        for value in values:
            if not value.strip() or any(character in value for character in ("\r", "\n", "\x00")):
                raise ValueError(f"browser mode {label} must be non-empty and contain no CR, LF or NUL")
            count += 1
        if not count:
            raise ValueError(f"browser mode {label} source is empty")
        counts.append(count)
    return counts[0], counts[1]


def _browser_safe_url(value: str) -> str:
    parts = urlsplit(value)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def _browser_result_record(outcome: Outcome, credential: Credential) -> dict[str, object]:
    def safe(value: str) -> str:
        return value.replace(credential.password, "<redacted>")

    evidence = outcome.evidence
    return {
        "username": safe(credential.username),
        "outcome": outcome.status.value,
        "detail": safe(outcome.detail),
        "attempted_count": int(bool(evidence.get("browser_attempted_count", 0))),
        "final_url": safe(_browser_safe_url(str(evidence.get("final_url") or ""))),
        "fields": [safe(str(value)) for value in evidence.get("fields", [])],
        "reason": safe(str(evidence["reason"])) if evidence.get("reason") else None,
        "http_status": evidence.get("http_status"),
        **{
            name: safe(evidence[name]) if isinstance(evidence.get(name), str) else None
            for name in ("blocked_origin", "blocked_method", "blocked_request_type")
        },
    }


class _BrowserAuditSink:
    """Keep failed discovery checks distinct from submitted authentication."""

    def __init__(self, audit: JsonlAuditWriter) -> None:
        self.audit = audit

    def record_attempt(self, job: AuthJob, credential: Credential, outcome: Outcome) -> None:
        endpoint = _browser_safe_url(job.endpoint).replace(credential.password, "<redacted>")
        if outcome.evidence.get("browser_attempted_count", 0):
            self.audit.record_attempt(replace(job, endpoint=endpoint), credential, outcome)
        else:
            self.audit.write_event({
                "event": "browser_check", "report_run_id": job.report_run_id,
                "endpoint": endpoint, **_browser_result_record(outcome, credential),
            })


def _browser_summary(result: ScheduleResult) -> tuple[OutcomeStatus, dict[str, object]]:
    priorities = (
        OutcomeStatus.SUCCESS, OutcomeStatus.RATE_LIMITED, OutcomeStatus.LOCKED_OUT,
        OutcomeStatus.MFA_REQUIRED, OutcomeStatus.ERROR, OutcomeStatus.NETWORK_ERROR,
        OutcomeStatus.UNSUPPORTED, OutcomeStatus.AMBIGUOUS, OutcomeStatus.SKIPPED,
        OutcomeStatus.FAILURE,
    )
    for status in priorities:
        for attempt in result.attempts:
            if attempt.outcome.status is status:
                return status, _browser_result_record(attempt.outcome, attempt.credential)
    return OutcomeStatus.SKIPPED, {
        "outcome": OutcomeStatus.SKIPPED.value, "detail": "Проверки не запускались",
        "final_url": "", "fields": [], "reason": None, "http_status": None,
    }


def _captcha_issue(report: PointFinderReport) -> str | None:
    for issue in report.issues:
        message = str(issue.get("message") or "")
        lowered = message.casefold()
        if "captcha" in lowered or "challenge" in lowered:
            return message
    return None


def _auto_browser_reason(
    report: PointFinderReport,
    jobs: Iterable[AuthJob],
) -> str | None:
    """Return a safe reason for one browser fallback, or None for plain HTTP."""

    prepared_jobs = tuple(jobs)
    for issue in report.issues:
        message = str(issue.get("message") or "").casefold()
        if "http 403" in message:
            return "HTTP 403 не позволил проанализировать страницу"
        if any(marker in message for marker in (
            "timed out", "timeout", "read operation timed out",
            "истекло время", "превышено время ожидания",
        )):
            return "HTTP-анализ завершился по таймауту"

    for job in prepared_jobs:
        if job.auth_type != "password_form":
            continue
        if profile_from_metadata(job.metadata) is not None:
            # The portable template adapter handles fresh HTTP sessions and,
            # if allowed, its own pre-submission browser fallback.
            continue
        method = str(job.metadata.get("form_method") or "POST").upper()
        fields = job.metadata.get("fields")
        hidden = isinstance(fields, list) and any(
            isinstance(field, Mapping)
            and (
                bool(field.get("hidden"))
                or str(field.get("type") or "").casefold() == "hidden"
            )
            for field in fields
        )
        if method != "POST" or hidden:
            return "форма требует browser session/CSRF"

    if prepared_jobs:
        return None
    if any(finding.auth_type == "js_login" for finding in report.findings):
        return "форма входа создаётся JavaScript"
    if not report.findings and not report.issues:
        return "HTTP-анализ не нашёл форму входа"
    return None


def _finish_detected_protection(
    args: argparse.Namespace,
    report: PointFinderReport,
    *,
    login_count: int,
    password_count: int,
) -> int:
    endpoint = _browser_safe_url(args.url)
    detail = (
        "Обнаружена CAPTCHA/защитная страница; считаем её активной защитой. "
        "Логин и пароль не отправлялись, проверки этого хоста остановлены."
    )
    issue = _captcha_issue(report) or ""
    payload = {
        "schema": "adaptive-check/1",
        "mode": "auto_browser",
        "transport": "http",
        "report_run_id": report.run_id,
        "endpoint": endpoint,
        "outcome": "protected",
        "detail": detail,
        "reason": "challenge",
        "protection_detected": True,
        "protection": "captcha",
        "http_status": 403 if "http 403" in issue.casefold() else None,
        "attempted_count": 0,
        "checked_count": 0,
        "halt_reason": "protected:captcha",
        "login_count": login_count,
        "password_count": password_count,
        "outcomes": {"protected": 1},
    }
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    with JsonlAuditWriter(args.audit) as audit:
        audit.write_event({"event": "protection_detected", **payload})
    if args.save_report:
        args.save_report.parent.mkdir(parents=True, exist_ok=True)
        args.save_report.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.compact:
        print(f"[ЗАЩИТА ОБНАРУЖЕНА] {endpoint} — {detail}")
    else:
        print(
            json.dumps(
                {**payload, "audit": str(args.audit)},
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
    return 0


def _run_auto_browser(
    args: argparse.Namespace,
    login_values: tuple[str, ...],
    password_values: tuple[str, ...],
) -> int:
    if not args.live or not args.url or args.report is not None:
        raise ValueError(
            "--auto-browser requires --live and an exact --url; --report is unsupported"
        )
    if args.audit is None:
        raise ValueError("--audit is required with --live")
    if args.auth_types:
        raise ValueError("--auth-type is not used with --auto-browser")
    _validate_live_limits(args)
    if args.allow_subdomains and not args.scope_domain:
        raise ValueError("--allow-subdomains requires --scope-domain")
    browser_timeout = args.browser_timeout if args.browser_timeout is not None else 60.0
    if not 1 <= browser_timeout <= 300:
        raise ValueError("--browser-timeout must be between 1 and 300 seconds")
    login_count, password_count = _validate_browser_inputs(
        args, login_values, password_values
    )
    target_scope = TargetScope.from_domain(
        args.scope_domain,
        include_subdomains=args.allow_subdomains,
    )
    report = discover_login_url(
        args.url,
        proxy=args.proxy,
        timeout_seconds=args.timeout,
        user_agent=args.user_agent,
        target_scope=target_scope,
        ca_cert=args.ca_cert,
        save_report=args.save_report,
        browser_fallback=False,
    )
    if _captcha_issue(report) is not None:
        return _finish_detected_protection(
            args,
            report,
            login_count=login_count,
            password_count=password_count,
        )

    jobs = build_jobs(report, supported_auth_types=LIVE_HTTP_AUTH_TYPES)
    fallback_reason = (
        "заданы CSS-признаки результата входа"
        if args.success_selector or args.failure_selector
        else _auto_browser_reason(report, jobs)
    )
    if fallback_reason is None:
        direct_args = argparse.Namespace(**vars(args))
        direct_args._auto_browser_active = True
        return _run_live(
            direct_args,
            LIVE_HTTP_AUTH_TYPES,
            login_values,
            password_values,
            report_override=report,
        )

    print(
        f"[AUTO] {_browser_safe_url(args.url)} — {fallback_reason}; "
        "запускаю один browser fallback",
        file=sys.stderr,
        flush=True,
    )
    browser_args = argparse.Namespace(**vars(args))
    browser_args.auto_browser = False
    browser_args.browser = False
    browser_args.browser_http = True
    browser_args.threads = 1
    browser_args._auto_browser_active = True
    return _run_browser(browser_args, login_values, password_values)


def _run_browser(
    args: argparse.Namespace,
    login_values: tuple[str, ...],
    password_values: tuple[str, ...],
) -> int:
    automatic = bool(getattr(args, "_auto_browser_active", False))
    mode = "auto_browser" if automatic else "browser_http" if args.browser_http else "browser"
    mode_flag = "--browser-http" if args.browser_http else "--browser"
    transport = "http" if args.browser_http else "browser"
    if not args.live or not args.url or args.report is not None:
        raise ValueError(f"{mode_flag} requires --live and an exact --url; --report is unsupported")
    if args.audit is None:
        raise ValueError("--audit is required with --live")
    if args.auth_types:
        raise ValueError(f"--auth-type is not used with {mode_flag}")
    _validate_live_limits(args)
    browser_timeout = args.browser_timeout if args.browser_timeout is not None else 60.0
    if not 1 <= browser_timeout <= 300:
        raise ValueError("--browser-timeout must be between 1 and 300 seconds")
    if args.allow_subdomains and not args.scope_domain:
        raise ValueError("--allow-subdomains requires --scope-domain")
    login_count, password_count = _validate_browser_inputs(args, login_values, password_values)
    target_scope = TargetScope.from_domain(args.scope_domain, include_subdomains=args.allow_subdomains)
    parts = validate_target_url(args.url, target_scope)
    config = BrowserCheckConfig(
        headless=args.headless,
        timeout_seconds=browser_timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        ca_cert=args.ca_cert,
        success_selector=args.success_selector,
        failure_selector=args.failure_selector,
        stop_on_challenge=automatic,
    )
    run_id = str(uuid4())
    digest = hashlib.sha256(args.url.encode("utf-8")).hexdigest()
    endpoint = _browser_safe_url(args.url)
    job = AuthJob(
        job_key=f"browser-{digest[:24]}", report_run_id=run_id,
        finding_id=f"browser-{digest[:16]}", kind="web_login_page",
        auth_type="password_form", endpoint=args.url,
        host=parts.hostname or "", port=parts.port or (443 if parts.scheme == "https" else 80),
        protocol=parts.scheme,
    )

    attempt_progress = _AttemptProgress(
        _attempt_budget(1, login_count, password_count, args.max_per_account, args.max_total),
        per_login_budget=(
            _attempt_budget(1, 1, password_count, args.max_per_account, args.max_total)
            if args.logins_path else None
        ),
        success_stream=sys.stdout if args.compact else sys.stderr,
    )

    def progress(message: str) -> None:
        attempt_progress.note(message)

    registry = AdapterRegistry()
    checker = (
        AdaptiveBrowserChecker(timeout_seconds=args.timeout)
        if automatic and args.browser_http
        else BrowserHttpChecker(timeout_seconds=args.timeout)
        if args.browser_http
        else run_browser_check
    )
    adapter = BrowserAdapter(
        config, target_scope=target_scope, on_progress=progress,
        rate_per_second=args.rate, checker=checker,
    )
    registry.register(adapter)
    policy = AttemptPolicy(
        rate_per_second=args.rate, max_total_attempts=args.max_total,
        max_attempts_per_account=args.max_per_account,
    )

    def attempts() -> Iterable[tuple[AuthJob, Credential]]:
        for pair in _attempts(
            [job], logins_path=args.logins_path, login_values=login_values,
            passwords_path=args.passwords, password_encoding=args.password_encoding,
            password_values=password_values,
            filter_login_candidates=args.auto_login_candidates,
        ):
            if adapter.interrupted:
                return
            yield pair

    args.audit.parent.mkdir(parents=True, exist_ok=True)
    with JsonlAuditWriter(args.audit) as audit:
        audit.write_event({
            "event": "browser_started", "report_run_id": run_id, "endpoint": endpoint,
            "mode": mode, "transport": transport,
            "headless": args.headless, "rate_per_second": args.rate, "threads": args.threads,
            "max_total_attempts": args.max_total, "max_attempts_per_account": args.max_per_account,
        })
        attempt_progress.start()
        try:
            result = Scheduler(
                registry, policy, audit_sink=_BrowserAuditSink(audit),
                on_attempt=attempt_progress.record, max_workers=args.threads,
            ).run(attempts())
        finally:
            attempt_progress.finish()
        records = [_browser_result_record(attempt.outcome, attempt.credential) for attempt in result.attempts]
        status, summary = _browser_summary(result)
        submitted_count = sum(record["attempted_count"] for record in records)
        halt_reason = "interrupted" if adapter.interrupted else result.halt_reason
        protection_detected = summary["reason"] == "challenge"
        if protection_detected:
            halt_reason = "protected:captcha"
        if halt_reason is None:
            unsupported = next((record for record in records if record["outcome"] == OutcomeStatus.UNSUPPORTED.value), None)
            if unsupported is not None:
                halt_reason = "unsupported" + (f":{unsupported['reason']}" if unsupported["reason"] else "")
        payload = {
            "schema": "browser-check/1", "mode": mode, "transport": transport, "report_run_id": run_id,
            "endpoint": endpoint,
            "outcome": "protected" if protection_detected else status.value,
            "detail": summary["detail"], "attempted_count": submitted_count,
            "checked_count": len(result.attempts), "halt_reason": halt_reason,
            "final_url": summary["final_url"], "fields": summary["fields"],
            "reason": summary["reason"], "http_status": summary["http_status"],
            "protection_detected": protection_detected,
            "protection": "captcha" if protection_detected else None,
            **{name: summary.get(name) for name in ("blocked_origin", "blocked_method", "blocked_request_type")},
            "results": records, "outcomes": dict(Counter(record["outcome"] for record in records)),
            "login_count": login_count, "password_count": password_count,
            "rate_per_second": args.rate, "threads": args.threads,
            "max_total_attempts": args.max_total, "max_attempts_per_account": args.max_per_account,
        }
        audit.write_event({"event": "browser_finished", **payload})
    if args.save_report:
        args.save_report.parent.mkdir(parents=True, exist_ok=True)
        args.save_report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    output = {**payload, "audit": str(args.audit)}
    output["successes"] = [
        {"endpoint": endpoint, "username": attempt.credential.username, "password": attempt.credential.password}
        for attempt in result.attempts if attempt.outcome.status is OutcomeStatus.SUCCESS
    ]
    output["mfa_candidates"] = [
        {"endpoint": endpoint, "username": attempt.credential.username, "password": attempt.credential.password}
        for attempt in result.attempts
        if attempt.outcome.status is OutcomeStatus.MFA_REQUIRED
        and outcome_attempted_count(attempt.outcome)
    ]
    if args.compact:
        labels = {
            OutcomeStatus.SUCCESS: "УСПЕШНО", OutcomeStatus.FAILURE: "НЕУСПЕШНО",
            OutcomeStatus.MFA_REQUIRED: "ТРЕБУЕТСЯ MFA", OutcomeStatus.AMBIGUOUS: "РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН",
            OutcomeStatus.UNSUPPORTED: "НЕ ПРОВЕРЕНО", OutcomeStatus.SKIPPED: "НЕ ПРОВЕРЕНО",
            OutcomeStatus.RATE_LIMITED: "ЛИМИТ ЗАПРОСОВ", OutcomeStatus.LOCKED_OUT: "АККАУНТ ЗАБЛОКИРОВАН",
            OutcomeStatus.ERROR: "ОШИБКА", OutcomeStatus.NETWORK_ERROR: "ОШИБКА СЕТИ",
        }
        label = labels[status]
        if summary["reason"] == "challenge":
            label = "ЗАЩИТА ОБНАРУЖЕНА"
        elif summary["reason"] == "http_403":
            label = "HTTP 403"
        detail = f"попыток: {submitted_count}; проверок: {result.attempted_count}; {_terminal_value(str(summary['detail']))}"
        blocked = " ".join(str(summary[name]) for name in ("blocked_method", "blocked_origin") if summary.get(name))
        if blocked:
            detail += f"; заблокирован запрос: {_terminal_value(blocked)}"
            if summary.get("blocked_request_type"):
                detail += f" ({_terminal_value(str(summary['blocked_request_type']))})"
        if halt_reason:
            detail += f"; остановка: {_terminal_value(halt_reason)}"
        if output["successes"]:
            detail += f"; найдено пар: {len(output['successes'])}"
        for candidate in output["mfa_candidates"]:
            detail += (
                f"; пара вызвала запрос кода: логин: {_terminal_value(candidate['username'])}"
                f" — пароль: {_terminal_value(candidate['password'])}; вход не завершён"
            )
        print(f"[{label}] {_terminal_value(endpoint)} — {detail}")
    else:
        print(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def _run_live(
    args: argparse.Namespace,
    auth_types: frozenset[str],
    login_values: tuple[str, ...],
    password_values: tuple[str, ...],
    *,
    report_override: PointFinderReport | None = None,
) -> int:
    if args.audit is None:
        raise ValueError("--audit is required with --live")
    unknown_types = auth_types - LIVE_HTTP_AUTH_TYPES
    if unknown_types:
        raise ValueError(
            "live mode supports only: "
            + ", ".join(sorted(LIVE_HTTP_AUTH_TYPES))
            + "; unsupported requested types: "
            + ", ".join(sorted(unknown_types))
        )
    _validate_live_limits(args)
    if args.allow_subdomains and not args.scope_domain:
        raise ValueError("--allow-subdomains requires --scope-domain")

    target_scope = TargetScope.from_domain(
        args.scope_domain,
        include_subdomains=args.allow_subdomains,
    )

    client = ProxyHttpClient(
        args.proxy,
        timeout_seconds=args.timeout,
        user_agent=args.user_agent,
        target_scope=target_scope,
        ca_cert=args.ca_cert,
    )
    report = report_override or (
        discover_login_url(
            args.url,
            proxy=args.proxy,
            timeout_seconds=args.timeout,
            user_agent=args.user_agent,
            target_scope=target_scope,
            ca_cert=args.ca_cert,
            save_report=args.save_report,
        )
        if args.url
        else load_report(args.report)
    )
    jobs = build_jobs(report, supported_auth_types=auth_types)
    if args.url and not jobs:
        raise ValueError(_unsupported_page_message(report, args.url))
    for job in jobs:
        validate_live_job(job, target_scope)

    registry = AdapterRegistry()
    registry.register(HttpBasicAdapter(client, target_scope))
    registry.register(TemplateFormAdapter(
        client, target_scope,
        BrowserCheckConfig(
            headless=True, timeout_seconds=args.browser_timeout or 60.0,
            proxy=args.proxy, user_agent=args.user_agent, ca_cert=args.ca_cert,
            stop_on_challenge=True,
        ),
        rate_per_second=args.rate,
    ))
    policy = AttemptPolicy(
        rate_per_second=args.rate,
        max_total_attempts=args.max_total,
        max_attempts_per_account=args.max_per_account,
    )
    login_count, password_count = count_candidates(
        args.logins_path, args.passwords,
        password_encoding=args.password_encoding,
        login_values=login_values, password_values=password_values,
    )
    attempt_progress = _AttemptProgress(
        _attempt_budget(len(jobs), login_count, password_count,
                        args.max_per_account, args.max_total),
        per_login_budget=(
            _attempt_budget(len(jobs), 1, password_count,
                            args.max_per_account, args.max_total)
            if args.logins_path else None
        ),
        success_stream=sys.stdout if args.compact else sys.stderr,
    )
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    with JsonlAuditWriter(args.audit) as audit:
        audit.write_event(
            {
                "event": "live_run_started",
                "report_run_id": report.run_id,
                "job_count": len(jobs),
                "proxy": args.proxy,
                "scope_domain": target_scope.domain if target_scope else None,
                "allow_subdomains": bool(
                    target_scope and target_scope.include_subdomains
                ),
                "rate_per_second": args.rate,
                "threads": args.threads,
                "max_total_attempts": args.max_total,
                "max_attempts_per_account": args.max_per_account,
                "discovery_url": args.url or None,
                "discovery_report": str(args.save_report) if args.save_report else None,
            }
        )
        attempt_progress.start()
        try:
            result = Scheduler(
                registry,
                policy,
                audit_sink=audit,
                on_attempt=attempt_progress.record,
                max_workers=args.threads,
            ).run(
                _attempts(
                    jobs,
                    logins_path=args.logins_path,
                    login_values=login_values,
                    passwords_path=args.passwords,
                    password_encoding=args.password_encoding,
                    password_values=password_values,
                    filter_login_candidates=args.auto_login_candidates,
                )
            )
        finally:
            attempt_progress.finish()
        outcome_counts = Counter(
            attempt.outcome.status.value for attempt in result.attempts
        )
        protection_detected = any(
            attempt.outcome.evidence.get("reason") == "challenge"
            for attempt in result.attempts
        )
        audit.write_event(
            {
                "event": "live_run_finished",
                "report_run_id": report.run_id,
                "attempted_count": result.attempted_count,
                "checked_count": len(result.attempts),
                "halt_reason": (
                    "protected:captcha" if protection_detected else result.halt_reason
                ),
                "outcomes": dict(sorted(outcome_counts.items())),
                "rate_per_second": args.rate,
                "threads": args.threads,
                "protection_detected": protection_detected,
            }
        )

    successes = [
        {
            "job_key": attempt.job.job_key,
            "auth_type": attempt.job.auth_type,
            "endpoint": attempt.job.endpoint,
            "username": attempt.credential.username,
            "password": attempt.credential.password,
        }
        for attempt in result.attempts
        if attempt.outcome.status is OutcomeStatus.SUCCESS
    ]
    mfa_candidates = [
        {
            "job_key": attempt.job.job_key,
            "auth_type": attempt.job.auth_type,
            "endpoint": attempt.job.endpoint,
            "username": attempt.credential.username,
            "password": attempt.credential.password,
        }
        for attempt in result.attempts
        if attempt.outcome.status is OutcomeStatus.MFA_REQUIRED
        and outcome_attempted_count(attempt.outcome)
    ]
    protections = [
        attempt.job.endpoint
        for attempt in result.attempts
        if attempt.outcome.evidence.get("reason") == "challenge"
    ]
    effective_halt_reason = "protected:captcha" if protections else result.halt_reason
    if (
        getattr(args, "_auto_browser_active", False)
        and protections
        and args.save_report
    ):
        adaptive_payload = {
            "schema": "adaptive-check/1",
            "mode": "auto_browser",
            "transport": "http",
            "report_run_id": report.run_id,
            "endpoint": _browser_safe_url(args.url or protections[0]),
            "outcome": "protected",
            "detail": (
                "Обнаружена CAPTCHA/защитная страница; проверки этого хоста "
                "остановлены"
            ),
            "reason": "challenge",
            "protection_detected": True,
            "protection": "captcha",
            "attempted_count": result.attempted_count,
            "checked_count": len(result.attempts),
            "halt_reason": "protected:captcha",
            "outcomes": dict(sorted(outcome_counts.items())),
        }
        args.save_report.parent.mkdir(parents=True, exist_ok=True)
        args.save_report.write_text(
            json.dumps(adaptive_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if args.compact:
        print("\n".join(_compact_live_lines(jobs, result, show_success_credentials=False)))
    else:
        print(
            json.dumps(
                {
                    "mode": "live",
                    "report_run_id": report.run_id,
                    "job_count": len(jobs),
                    "attempted_count": result.attempted_count,
                    "checked_count": len(result.attempts),
                    "halt_reason": effective_halt_reason,
                    "outcomes": dict(sorted(outcome_counts.items())),
                    "rate_per_second": args.rate,
                    "successes": successes,
                    "mfa_candidates": mfa_candidates,
                    "protection_detected": bool(protections),
                    "protection": "captcha" if protections else None,
                    "protected_endpoints": sorted(set(protections)),
                    "threads": args.threads,
                    "audit": str(args.audit),
                    "discovery_url": args.url or None,
                    "discovery_report": str(args.save_report) if args.save_report else None,
                },
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
    return 0


def _unsupported_page_message(report: PointFinderReport, url: str) -> str:
    issue_messages = [str(issue.get("message") or "") for issue in report.issues]
    if any(
        "captcha" in message.casefold() or "challenge" in message.casefold()
        for message in issue_messages
    ):
        return (
            f"На {url} получена CAPTCHA/защитная страница. "
            "Форма входа недоступна; логин и пароль не отправлялись. "
            "Проверка хоста остановлена: CAPTCHA учитывается как обнаруженная "
            "активная защита и автоматически не обходится."
        )
    if any("http 403" in message.casefold() for message in issue_messages):
        return (
            f"На {url} сайт вернул HTTP 403: доступ к странице запрещён. "
            "Форма входа не анализировалась; логин и пароль не отправлялись. "
            "Проверьте proxy/User-Agent или повторите запуск с --auto-browser: "
            "браузер подключится только для диагностики этой страницы."
        )
    for finding in report.findings:
        if finding.auth_type != "passwordless_form":
            continue
        action = str(finding.metadata.get("form_action") or "").casefold()
        if any(marker in action for marker in ("otp", "magic", "send_email", "email_code")):
            return (
                f"PointFinder обнаружил на {url} только шаг с email/OTP, без поля пароля. "
                "Отправка идентификатора может вызвать письмо или код; утилита "
                "не выполняла этот шаг и не проверяла пароли."
            )
        return (
            f"PointFinder обнаружил на {url} форму первого шага только с логином/email, "
            "но не нашёл поле пароля. Утилита не отправляла идентификатор и не "
            "проверяла пароли."
        )
    return f"PointFinder не нашёл на {url} форму с паролем или HTTP Basic"


def _compact_live_lines(
    jobs: Iterable[AuthJob],
    result: ScheduleResult,
    *,
    show_success_credentials: bool = True,
) -> tuple[str, ...]:
    endpoints = tuple(dict.fromkeys(job.endpoint for job in jobs))
    if not endpoints:
        return ("[НЕ ПРОВЕРЕНО] поддерживаемые URL не найдены",)

    attempts_by_endpoint = {
        endpoint: tuple(
            attempt
            for attempt in result.attempts
            if attempt.job.endpoint == endpoint
        )
        for endpoint in endpoints
    }
    lines: list[str] = []
    for endpoint, attempts in attempts_by_endpoint.items():
        attempted_count = sum(
            outcome_attempted_count(attempt.outcome) for attempt in attempts
        )
        count_detail = f"попыток: {attempted_count}"
        if len(attempts) != attempted_count:
            count_detail += f"; проверок: {len(attempts)}"
        successful_credentials = sorted(
            {
                (attempt.credential.username, attempt.credential.password)
                for attempt in attempts
                if attempt.outcome.status is OutcomeStatus.SUCCESS
            }
        )
        mfa_credentials = sorted({
            (attempt.credential.username, attempt.credential.password)
            for attempt in attempts
            if attempt.outcome.status is OutcomeStatus.MFA_REQUIRED
            and outcome_attempted_count(attempt.outcome)
        })
        statuses = {attempt.outcome.status for attempt in attempts}
        challenge = next(
            (
                attempt
                for attempt in attempts
                if attempt.outcome.evidence.get("reason") == "challenge"
            ),
            None,
        )
        forbidden = next(
            (
                attempt
                for attempt in attempts
                if attempt.outcome.evidence.get("reason") == "http_403"
            ),
            None,
        )
        diagnostic: str | None = None

        if successful_credentials:
            label = "УСПЕШНО"
            detail = (
                "; ".join(
                    f"логин: {_terminal_value(username)} — "
                    f"пароль: {_terminal_value(password)}"
                    for username, password in successful_credentials
                )
                if show_success_credentials
                else f"{count_detail}; найдено пар: {len(successful_credentials)}"
            )
            if mfa_credentials:
                detail += "; " + "; ".join(
                    f"пара вызвала запрос кода: логин: {_terminal_value(username)} — "
                    f"пароль: {_terminal_value(password)}; вход не завершён"
                    for username, password in mfa_credentials
                )
        elif not attempts:
            label = "НЕ ПРОВЕРЕНО"
            detail = "попыток: 0"
        elif challenge is not None:
            label = "ЗАЩИТА ОБНАРУЖЕНА"
            detail = count_detail
            diagnostic = challenge.outcome.detail
        elif forbidden is not None:
            label = "HTTP 403"
            detail = count_detail
            diagnostic = forbidden.outcome.detail
        elif OutcomeStatus.RATE_LIMITED in statuses:
            label = "ЛИМИТ ЗАПРОСОВ"
            detail = count_detail
        elif OutcomeStatus.LOCKED_OUT in statuses:
            label = "АККАУНТ ЗАБЛОКИРОВАН"
            detail = count_detail
        elif OutcomeStatus.MFA_REQUIRED in statuses:
            label = "ТРЕБУЕТСЯ MFA"
            detail = count_detail
            if mfa_credentials:
                detail += "; " + "; ".join(
                    f"пара вызвала запрос кода: логин: {_terminal_value(username)} — "
                    f"пароль: {_terminal_value(password)}; вход не завершён"
                    for username, password in mfa_credentials
                )
        elif statuses == {OutcomeStatus.FAILURE}:
            label = "НЕУСПЕШНО"
            detail = count_detail
        else:
            labels = {
                OutcomeStatus.ERROR: "ОШИБКА",
                OutcomeStatus.NETWORK_ERROR: "ОШИБКА СЕТИ",
                OutcomeStatus.AMBIGUOUS: "РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН",
                OutcomeStatus.UNSUPPORTED: "НЕ ПРОВЕРЕНО",
                OutcomeStatus.SKIPPED: "НЕ ПРОВЕРЕНО",
            }
            status = next(status for status in labels if status in statuses)
            label = labels[status]
            if (
                status in {OutcomeStatus.UNSUPPORTED, OutcomeStatus.SKIPPED}
                and OutcomeStatus.FAILURE in statuses
            ):
                label = "ПРОВЕРЕНО ЧАСТИЧНО"
            detail = count_detail
            diagnostic = next(
                (
                    attempt.outcome.detail
                    for attempt in attempts
                    if attempt.outcome.status is status and attempt.outcome.detail
                ),
                None,
            )

        if diagnostic:
            passwords = {attempt.credential.password for attempt in attempts}
            for password in sorted(passwords - {""}, key=len, reverse=True):
                diagnostic = diagnostic.replace(password, "<redacted>")
            detail += f"; {_terminal_value(diagnostic)}"

        lines.append(f"[{label}] {_terminal_value(endpoint)} — {detail}")
    return tuple(lines)


def _terminal_value(value: str) -> str:
    """Escape control characters while keeping ordinary credentials readable."""

    return json.dumps(value, ensure_ascii=False)[1:-1]


def _attempts(
    jobs: Iterable[AuthJob],
    *,
    logins_path: Path | None,
    login_values: tuple[str, ...],
    passwords_path: Path | None,
    password_encoding: str,
    password_values: tuple[str, ...],
    filter_login_candidates: bool = False,
) -> Iterable[tuple[AuthJob, Credential]]:
    for job in jobs:
        for credential in iter_credentials(
            logins_path,
            passwords_path,
            password_encoding=password_encoding,
            login_values=login_values,
            password_values=password_values,
        ):
            if filter_login_candidates and not _credential_matches_identifier(
                job, credential
            ):
                continue
            yield job, credential


def _credential_matches_identifier(job: AuthJob, credential: Credential) -> bool:
    kind = job.metadata.get("identifier_kind")
    if kind not in {"email", "username"}:
        return True
    looks_like_email = _looks_like_email(credential.username)
    return looks_like_email if kind == "email" else not looks_like_email


def _looks_like_email(value: str) -> bool:
    if value.count("@") != 1 or any(character.isspace() for character in value):
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local and domain and "." in domain and not domain.startswith("."))


def _validated_inline_logins(values: list[str] | None) -> tuple[str, ...]:
    result = tuple(values or ())
    for value in result:
        if not value or any(character in value for character in ("\r", "\n", "\x00")):
            raise ValueError("--login must be non-empty and contain no CR, LF or NUL")
    return result


def _validated_inline_passwords(values: list[str] | None) -> tuple[str, ...]:
    result = tuple(values or ())
    for value in result:
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise ValueError("--password must contain no CR, LF or NUL")
    return result


def _validate_live_limits(args: argparse.Namespace) -> None:
    if not 0 < args.rate <= 10:
        raise ValueError("--rate must be greater than 0 and at most 10")
    if not 1 <= args.threads <= 10:
        raise ValueError("--threads must be between 1 and 10")
    if args.max_total is not None and not 1 <= args.max_total <= 1000:
        raise ValueError("--max-total must be between 1 and 1000")
    if args.max_per_account < 1:
        raise ValueError("--max-per-account должен быть больше 0")
    if not 0 < args.timeout <= 60:
        raise ValueError("--timeout must be greater than 0 and at most 60")


if __name__ == "__main__":
    raise SystemExit(main())
