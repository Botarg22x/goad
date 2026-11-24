"""Target-oriented orchestration for modules 2, 3 and 4."""

from __future__ import annotations

import argparse
import ipaddress
import io
import json
import math
import os
import re
import shutil
import sys
import time
from collections.abc import Callable, Sequence
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from .components import COMPONENTS
from .delegation import DelegationError, delegate
from .targets import load_target_urls

DEFAULT_PROXY: str | None = None
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)
SLOW_INTERVAL_SECONDS = 15.0
DEFAULT_SEARCH_DELAY_SECONDS = 10.0  # Keep in sync with logingen AutoConfig.
SLOW_AUTH_RATE_PER_SECOND = 1.0 / SLOW_INTERVAL_SECONDS
DEFAULT_RUN_SPEED_PROFILE = "normal"
RUN_SPEED_PROFILES: dict[str, dict[str, float | int | str]] = {
    "slow": {
        "collection_delay": 15.0,
        "discovery_profile": "slow",
        "auth_rate": SLOW_AUTH_RATE_PER_SECOND,
        "auth_threads": 1,
        "target_delay": 15.0,
    },
    "normal": {
        "collection_delay": 3.0,
        "discovery_profile": "normal",
        "auth_rate": 1.0,
        "auth_threads": 1,
        "target_delay": 0.0,
    },
    "fast": {
        "collection_delay": 1.0,
        "discovery_profile": "fast",
        "auth_rate": 5.0,
        "auth_threads": 5,
        "target_delay": 0.0,
    },
}
# Keep these values in sync with authpoints.cli._SPEED_PRESETS: run delegates
# the profile name to module 3, and the plan must show its effective limits.
DISCOVERY_SPEED_PROFILES: dict[str, dict[str, int | float]] = {
    "slow": {
        "katana_rate": 1, "katana_parallelism": 1, "katana_concurrency": 1,
        "subfinder_rate": 1, "http_concurrency": 1, "http_delay": 1.0,
        "nmap_timing": 2,
    },
    "normal": {
        "katana_rate": 10, "katana_parallelism": 2, "katana_concurrency": 5,
        "subfinder_rate": 10, "http_concurrency": 5, "http_delay": 0.0,
        "nmap_timing": 3,
    },
    "fast": {
        "katana_rate": 50, "katana_parallelism": 4, "katana_concurrency": 10,
        "subfinder_rate": 50, "http_concurrency": 10, "http_delay": 0.0,
        "nmap_timing": 4,
    },
}
LIVE_AUTH_TYPES = frozenset({"http_basic", "password_form"})
_DIRECT_OPTIONS = frozenset({
    "-q", "--quick", "-v", "--verbose", "--collect-points", "--page-only", "--subfinder", "--katana", "--standard-path", "--nmap", "--with-nmap", "--katana-depth", "--katana-max-total-pages", "--katana-max-dom-mb", "--no-standard-paths", "-u", "--url", "--target", "--targets-file", "--urls-file", "--login-pages-file", "--discovery-file", "-l", "--login", "--logins",
    "--collect-logins", "--find-logins", "--collect-info", "--collect-only", "--email-source", "--people-source", "--mail-domain", "--company", "--company-name", "--no-documents", "--setka-max-pages",
    "-g", "--generate", "--generate-logins", "--browser-crawl", "--slow", "--normal", "--fast", "-p", "--password", "--passwords", "--proxy",
    "--user-agent", "-s", "--artifacts", "--audit", "--save-report", "--rate",
    "--ca-cert", "--browser-resource-domain",
    "--threads", "--json", "--yes", "--discover-only", "--max-total",
    "--max-per-account", "--timeout",
    "--browser", "--browser-http", "--auto-browser", "--no-auto-browser", "--headless", "--show-browser", "--browser-timeout", "--success-selector", "--failure-selector",
})

Runner = Callable[[list[str]], int]


class _RussianArgumentParser(argparse.ArgumentParser):
    """Localize argparse's built-in help labels without changing parsing."""

    def format_usage(self) -> str:
        return super().format_usage().replace("usage: ", "Использование: ", 1)

    def format_help(self) -> str:
        return super().format_help().replace("usage: ", "Использование: ", 1)


class _EditableRunHelpParser(_RussianArgumentParser):
    """Render ``run -h`` from the same kind of text resource as module 3."""

    def __init__(self, *args: object, editable_help: str, **kwargs: object) -> None:
        self._editable_help = editable_help
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        return self._editable_help.rstrip() + "\n"


def _load_run_help() -> str:
    resource = files("goad").joinpath("run_help.txt")
    with resource.open("r", encoding="utf-8-sig") as stream:
        text = stream.read()
    if not text.strip():
        raise ValueError("run_help.txt is empty")
    return text


class _TeeTextIO:
    """Mirror component diagnostics to the terminal and an in-memory sink."""

    def __init__(self, *streams: TextIO) -> None:
        self._streams = streams

    def write(self, value: str) -> int:
        for stream in self._streams:
            stream.write(value)
        return len(value)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()

    def isatty(self) -> bool:
        return False


class _RunOutput:
    """Write orchestration messages to the terminal and the private run log."""

    def __init__(self, terminal: TextIO, log: TextIO) -> None:
        self.terminal, self.log = terminal, log

    def write(self, value: str) -> int:
        self.log.write(value)
        self.terminal.write(value)
        return len(value)

    def flush(self) -> None:
        self.log.flush()
        self.terminal.flush()

    def isatty(self) -> bool:
        return self.terminal.isatty()


class _ComponentOutput(_RunOutput):
    """Keep every component message in the log, but show only important lines."""

    def __init__(
        self, terminal: TextIO, log: TextIO, *, verbose: bool,
        suppress_terminal_prefixes: tuple[str, ...] = (),
        found_only: bool = False,
    ) -> None:
        super().__init__(terminal, log)
        self.verbose = verbose
        self.found_only = found_only
        self.shown_found_urls: set[str] = set()
        self.suppress_terminal_prefixes = tuple(
            prefix.casefold() for prefix in suppress_terminal_prefixes
        )
        self.pending = ""

    def write(self, value: str) -> int:
        self.log.write(value)
        if self.verbose and not self.suppress_terminal_prefixes and not self.found_only:
            self.terminal.write(value)
        else:
            self.pending += value
            while "\n" in self.pending:
                line, self.pending = self.pending.split("\n", 1)
                visible = self._visible_line(line)
                if visible is not None:
                    self.terminal.write(visible + "\n")
            if self.verbose and not self.found_only and self.pending and not any(
                prefix.startswith(self.pending.casefold())
                or self.pending.casefold().startswith(prefix)
                for prefix in self.suppress_terminal_prefixes
            ):
                self.terminal.write(self.pending)
                self.pending = ""
            if len(self.pending) > 8192:
                self.pending = self.pending[-2048:]
        return len(value)

    def finish(self) -> None:
        if self.pending:
            visible = self._visible_line(self.pending)
            if visible is not None:
                self.terminal.write(visible)
        self.pending = ""
        self.flush()

    def _visible_line(self, line: str) -> str | None:
        if self.found_only:
            prefix = "[FOUND] "
            if not line.startswith(prefix):
                return None
            kind, separator, url = line[len(prefix):].partition(" ")
            if not separator or not url.strip() or kind == "js_login":
                return None
            url = url.strip()
            if url in self.shown_found_urls:
                return None
            self.shown_found_urls.add(url)
            return f"[НАЙДЕНО] {url}"
        if line.strip().casefold().startswith(self.suppress_terminal_prefixes):
            return None
        return line if self.verbose or _important_component_line(line) else None


def _important_component_line(line: str) -> bool:
    lowered = line.strip().casefold()
    return lowered.startswith((
        "[ошибка]", "[error]", "[предупреждение]", "[warning]",
        "warning:", "error:", "authchecker:",
        "[успешно]", "[неуспешно]", "[результат не определён]",
        "[не проверено]", "[проверено частично]", "[ошибка сети]",
        "[защита обнаружена]", "[требуется mfa]", "[лимит запросов]",
        "[аккаунт заблокирован]", "[http 403]",
        "[результат]", "[логины] сохранено:",
    ))


def is_direct_run(argv: Sequence[str]) -> bool:
    """Select the target-oriented ``run`` interface."""
    if not argv or list(argv) in (["-h"], ["--help"]):
        return True
    return any(token.partition("=")[0] in _DIRECT_OPTIONS for token in argv)


def _browser_resource_domain(value: str) -> str:
    """Validate an exact asset hostname before starting any component."""

    message = "укажите имя домена без схемы, порта, пути или маски"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise argparse.ArgumentTypeError(message)
    host = value.strip().rstrip(".")
    if not host or any(character in host for character in "/\\:@?#*"):
        raise argparse.ArgumentTypeError(message)
    try:
        hostname = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise argparse.ArgumentTypeError(message) from exc
    if len(hostname) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label)
        for label in hostname.split(".")
    ):
        raise argparse.ArgumentTypeError(message)
    return hostname


def build_parser() -> argparse.ArgumentParser:
    parser = _EditableRunHelpParser(
        prog="goad run",
        editable_help=_load_run_help(),
        add_help=False,
        description=(
            "Последовательный запуск: собрать открытые данные, найти точки "
            "авторизации, выбрать нужные и проверить логины/пароли."
        ),
        epilog=(
            "Примеры:\n"
            "  goad run -q -u http://127.0.0.1:8080 -p pass.txt\n"
            "  goad run -u http://127.0.0.1:8080 -l student -p password123\n"
            "  goad run -u http://127.0.0.1:8080 -l users.txt -p pass.txt\n"
            "  goad run -u http://127.0.0.1:8080 --find-logins -p pass.txt\n\n"
            "  goad run -q -u https://site.example "
            "--passwords passwords.txt --slow\n\n"
            "  goad run --browser --target http://127.0.0.1:8080/login "
            "--login student --password password123\n\n"
            "  goad run --target http://127.0.0.1:8080/login "
            "--login student --password password123\n\n"
            "  goad run -u https://site.example "
            "--login student --passwords passwords.txt\n\n"
            "  goad run --no-auto-browser --target https://site.example/login "
            "--login student --passwords passwords.txt\n\n"
            "  goad run --browser-http --targets-file targets.txt "
            "--login student --passwords passwords.txt\n\n"
            "Для -l/-p существующий путь считается файлом, остальные значения — "
            "логинами/паролями; список можно разделить запятыми. Для пароля с запятой "
            "используйте --password. Область проверки автоматически ограничивается "
            "доменом из -u/--target и его поддоменами. В --targets-file нужен "
            "один полный URL страницы входа на строку; пустые строки, # комментарии "
            "и повторы пропускаются. Цели обрабатываются последовательно, "
            "лимиты действуют на каждый URL отдельно. --proxy необязателен и "
            "подходит для любого HTTP-прокси."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument(
        "-u", "--url", metavar="URL",
        help="адрес сайта: модуль 3 найдёт точки входа и предложит выбрать",
    )
    targets.add_argument(
        "--target", metavar="URL",
        help="уже известная точная страница входа (без обхода сайта)",
    )
    targets.add_argument(
        "--login-pages-file", "--targets-file", "--urls-file",
        dest="targets_file", type=Path, metavar="FILE",
        help="файл готовых ссылок на страницы входа, по одному HTTP(S) URL на строку; без обхода сайта",
    )
    targets.add_argument(
        "--discovery-file", type=Path, metavar="FILE",
        help="домены, IP, CIDR и HTTP(S) URL для поиска точек входа через модуль 3",
    )
    parser.add_argument(
        "-q", "--quick", action="store_true",
        help=(
            "полный пресет: сбор ФИО/e-mail, Subfinder, Katana, стандартные "
            "пути и автоматический browser fallback модуля 4"
        ),
    )
    parser.add_argument(
        "--collect-points", action="store_true",
        help="запустить поиск и сбор точек входа",
    )
    parser.add_argument(
        "--page-only", action="store_true",
        help="проверить только стартовые URL и корни поддоменов; без обхода ссылок и попыток входа",
    )
    parser.add_argument(
        "--subfinder", action="store_true",
        help="найти поддомены и передать их проверке",
    )
    parser.add_argument(
        "--katana", action="store_true",
        help="обойти страницы сайта через Katana в поисках точек входа",
    )
    standard_paths = parser.add_mutually_exclusive_group()
    standard_paths.add_argument(
        "--standard-path", dest="standard_path", action="store_true",
        help="проверить встроенный список стандартных путей входа",
    )
    standard_paths.add_argument(
        "--no-standard-paths", action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--nmap", action="store_true",
        help="запустить Nmap для поиска веб-служб и точек входа",
    )
    parser.add_argument(
        "--with-nmap",
        action="store_true",
        help=(
            "с -q: дополнительно запустить Nmap по 100 распространённым "
            "TCP-портам и передать найденные веб-сервисы модулю 3"
        ),
    )
    parser.add_argument(
        "--katana-depth",
        type=int,
        metavar="N",
        help=(
            "с -u/--url: глубина обхода Katana от 0 до 10; "
            "по умолчанию модуль 3 использует 2"
        ),
    )
    parser.add_argument(
        "--katana-max-total-pages",
        type=int,
        metavar="N",
        help=(
            "с -u/--url: общий лимит страниц Katana по основному домену "
            "и всем его поддоменам"
        ),
    )
    parser.add_argument(
        "--katana-max-dom-mb",
        type=int,
        metavar="N",
        help=(
            "с -u/--url: максимальный размер отрисованного DOM одной "
            "страницы, 1–32 МиБ; по умолчанию 2"
        ),
    )
    parser.add_argument(
        "--browser-resource-domain",
        action="append",
        type=_browser_resource_domain,
        metavar="DOMAIN",
        help=(
            "с -u/--url или --discovery-file: разрешить браузеру загружать "
            "ресурсы указанного домена; флаг можно повторять, область обхода не расширяется"
        ),
    )
    logins = parser.add_mutually_exclusive_group()
    logins.add_argument(
        "-l", dest="smart_logins", action="append", metavar="VALUE|FILE",
        help="логин, список через запятую или файл; флаг можно повторять",
    )
    logins.add_argument(
        "--find-logins", action="store_true",
        help=(
            "подготовить кандидатов для поля логина: собрать публичные e-mail/ФИО, "
            "предложить выбор и передать выбранные значения модулю 4"
        ),
    )
    logins.add_argument(
        "--login", action="append", dest="login_values", metavar="VALUE",
        help="один логин без автоопределения; можно повторять",
    )
    logins.add_argument("--logins", type=Path, metavar="FILE", help="файл с логинами")
    parser.add_argument(
        "-g", "--generate", "--generate-logins", dest="generate_logins",
        action="store_true",
        help="после сбора выбрать шаблон и формат, затем сгенерировать кандидатов",
    )
    parser.add_argument(
        "--collect-logins", action="store_true",
        help="запустить сбор опубликованных e-mail, логинов и ФИО",
    )
    parser.add_argument(
        "--mail-domain", metavar="DOMAIN",
        help="почтовый домен для поиска и генерации; может отличаться от сайта в -u",
    )
    parser.add_argument(
        "--company", "--company-name", dest="company_name", metavar="НАЗВАНИЕ",
        help="название организации для поиска ФИО в Setka и других внешних источниках",
    )
    parser.add_argument(
        "--collect-info",
        action="store_true",
        help=(
            "собрать открытые e-mail/ФИО для одного сайта из -u/--target; "
            "источники задаются через --email-source/--people-source"
        ),
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="выполнить только сбор e-mail/ФИО и завершить run до модулей 3 и 4",
    )
    parser.add_argument(
        "--email-source",
        action="append",
        metavar="ИСТОЧНИК",
        help="источники e-mail: site,search; можно через запятую или повторять",
    )
    parser.add_argument(
        "--people-source",
        action="append",
        metavar="ИСТОЧНИК",
        help="источники ФИО: site,search,setka,vedomosti; можно через запятую или повторять",
    )
    parser.add_argument(
        "--browser-crawl",
        action="store_true",
        help=(
            "для сбора с сайта модулем 2: выполнять JavaScript в Chromium; "
            "обычно достаточно облегчённого HTTP-обхода"
        ),
    )
    parser.add_argument(
        "--no-documents", action="store_true",
        help="при сборе e-mail/ФИО не скачивать и не обрабатывать PDF",
    )
    parser.add_argument(
        "--setka-max-pages", type=int, metavar="N",
        help="проверить не более N страниц участников Setka",
    )

    passwords = parser.add_mutually_exclusive_group()
    passwords.add_argument(
        "-p", dest="smart_passwords", action="append", metavar="VALUE|FILE",
        help="пароль, список через запятую или файл; флаг можно повторять",
    )
    passwords.add_argument(
        "--password", action="append", dest="password_values", metavar="VALUE",
        help="один пароль без разбора запятых; можно повторять",
    )
    passwords.add_argument(
        "--passwords", type=Path, metavar="FILE",
        help="файл с паролями; предпочтительно для чувствительных значений",
    )

    parser.add_argument(
        "--search-engine", action="append", metavar="ПОИСКОВИК",
        help="yandex,google; можно через запятую или повторять (по умолчанию: yandex)",
    )
    speed_profile = parser.add_mutually_exclusive_group()
    speed_profile.add_argument(
        "--slow", dest="speed_profile", action="store_const", const="slow",
        help="медленный профиль всей цепочки run",
    )
    speed_profile.add_argument(
        "--normal", dest="speed_profile", action="store_const", const="normal",
        help="обычный профиль всей цепочки run (по умолчанию)",
    )
    speed_profile.add_argument(
        "--fast", dest="speed_profile", action="store_const", const="fast",
        help="быстрый профиль всей цепочки run",
    )
    parser.set_defaults(speed_profile=DEFAULT_RUN_SPEED_PROFILE)
    parser.add_argument(
        "--proxy", default=DEFAULT_PROXY,
        help="необязательный HTTP-прокси для всех сетевых этапов",
    )
    parser.add_argument(
        "--user-agent", default=DEFAULT_USER_AGENT,
        help="User-Agent для поиска, обнаружения и проверки (по умолчанию Chrome/Linux)",
    )
    parser.add_argument(
        "--ca-cert", type=Path, metavar="FILE",
        help="CA-сертификат для HTTPS, перехватываемого proxy",
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="не задавать вопросы: использовать все найденные ссылки и логины",
    )
    parser.add_argument(
        "--discover-only", action="store_true",
        help="только показать точки авторизации, не запускать проверку",
    )
    parser.add_argument(
        "-s", "--artifacts", dest="artifacts", type=Path,
        default=Path("artifacts"), metavar="DIR",
        help="папка для результатов; каждый запуск получает свою подпапку (по умолчанию: ./artifacts)",
    )
    parser.add_argument("--audit", type=Path, help="свой путь к audit.jsonl")
    parser.add_argument("--save-report", type=Path, help="путь к отчёту PointFinder, browser-check/1 или сводке файла целей")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный вывод в консоль; полный журнал всегда сохраняется в run.log")
    parser.add_argument("--rate", type=float, help="своя скорость авторизации, попыток/с; максимум 10")
    parser.add_argument("--threads", type=int, help="своё число параллельных попыток; максимум 10")
    parser.add_argument("--json", action="store_true", help="полный JSON вместо коротких строк")
    parser.add_argument("--max-total", type=int, help="общий лимит попыток на URL; без флага не задан")
    parser.add_argument("--max-per-account", type=int, default=3, help="лимит попыток на одну точку и логин; максимум 20")
    parser.add_argument("--timeout", type=float, default=10.0, help="таймаут одного запроса в секундах; максимум 60")
    browser_mode = parser.add_mutually_exclusive_group()
    browser_mode.add_argument("--browser", action="store_true", help="проверять пары логин/пароль в браузере на --target или страницах из --targets-file")
    browser_mode.add_argument("--browser-http", action="store_true", help="один раз получить запрос и cookies из браузера, затем проверять пары через HTTP")
    browser_mode.add_argument("--auto-browser", action="store_true", help="автоматический режим авторизации (по умолчанию): сначала HTTP, затем скрытый браузер при необходимости")
    browser_mode.add_argument("--no-auto-browser", action="store_true", help="отключить браузерный fallback авторизации; поиск точек и сбор данных не меняются")
    browser_window = parser.add_mutually_exclusive_group()
    browser_window.add_argument("--headless", action="store_true", help="скрыть окно в явных режимах --browser/--browser-http; в автоматическом режиме это уже по умолчанию")
    browser_window.add_argument("--show-browser", action="store_true", help="показывать окно Chromium при автоматическом browser fallback")
    parser.add_argument("--browser-timeout", type=float, help="с браузерным режимом: ожидание страницы/формы, 1–300 секунд (по умолчанию 60)")
    parser.add_argument("--success-selector", help="с браузерным режимом: CSS-селектор подтверждённого успешного входа")
    parser.add_argument("--failure-selector", help="с браузерным режимом: CSS-селектор ошибки входа")
    parser._positionals.title = "Позиционные аргументы"
    parser._optionals.title = "Параметры"
    for action in parser._actions:
        if action.dest == "help":
            action.help = "показать эту справку и выйти"
    return parser


def _apply_ca_certificate_default(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> None:
    """Use a CA only when explicitly selected for this run."""

    if args.ca_cert is None:
        return
    certificate = args.ca_cert.expanduser().resolve()
    if not certificate.is_file():
        parser.error(
            f"файл CA не найден: {certificate}; проверьте --ca-cert"
        )
    args.ca_cert = certificate


def _parse_comma_option(
    values: list[str] | None,
    choices: tuple[str, ...],
    option: str,
    parser: argparse.ArgumentParser,
) -> list[str] | None:
    if values is None:
        return None
    selected: list[str] = []
    for raw in values:
        for item in raw.split(","):
            value = item.strip().lower()
            if not value:
                parser.error(f"{option}: пустое значение в списке {raw!r}")
            if value not in choices:
                parser.error(f"{option}: неизвестное значение {value!r}; допустимо: {', '.join(choices)}")
            if value not in selected:
                selected.append(value)
    return selected


def _normalize_run_stages(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> None:
    """Translate the public stage-oriented CLI into the internal pipeline flags."""

    args.email_source = _parse_comma_option(args.email_source, ("site", "search"), "--email-source", parser)
    args.people_source = _parse_comma_option(
        args.people_source, ("site", "search", "setka", "vedomosti"), "--people-source", parser,
    )
    args.search_engine = _parse_comma_option(
        args.search_engine, ("yandex", "google"), "--search-engine", parser,
    )

    explicit_logins = any((args.smart_logins, args.login_values, args.logins))
    explicit_passwords = any(
        (args.smart_passwords, args.password_values, args.passwords)
    )
    point_method_requested = any((
        args.subfinder,
        args.katana,
        args.standard_path,
        args.nmap,
        args.with_nmap,
    ))
    katana_setting_requested = any((
        args.katana_depth is not None,
        args.katana_max_total_pages is not None,
        args.katana_max_dom_mb is not None,
        args.browser_resource_domain,
    ))

    # Compatibility aliases from the previous run interface.
    if args.with_nmap:
        args.nmap = True
        args.katana = True
    if args.find_logins:
        args.collect_logins = True
        args.generate_logins = True
    if args.collect_info or args.collect_only:
        args.collect_logins = True
    if args.generate_logins:
        args.collect_logins = True
    if args.email_source or args.people_source or args.search_engine:
        args.collect_logins = True
    if args.browser_crawl or args.no_documents:
        args.collect_logins = True
    if args.discover_only:
        args.collect_points = True
    if args.page_only:
        args.collect_points = True
    if katana_setting_requested:
        args.katana = True
    if point_method_requested or katana_setting_requested or args.no_standard_paths:
        args.collect_points = True

    if args.quick:
        if not args.url:
            parser.error("-q/--quick требует адрес сайта через -u/--url")
        if any((args.smart_logins, args.login_values, args.logins)):
            parser.error(
                "-q сам собирает логины; для собственного списка уберите -q"
            )
        if args.browser or args.browser_http:
            parser.error(
                "-q использует автоматический режим авторизации; "
                "--browser/--browser-http не поддерживаются"
            )
        args.collect_logins = True
        args.generate_logins = True
        args.collect_points = True
        args.subfinder = True
        args.katana = True
        if not args.no_standard_paths:
            args.standard_path = True
        args.search_engine = ["yandex", "google"]

    if args.page_only:
        if args.quick or args.katana or args.standard_path or katana_setting_requested:
            parser.error("--page-only нельзя сочетать с -q, Katana, стандартными путями или настройками глубины")
        if explicit_logins or explicit_passwords:
            parser.error("--page-only только ищет формы; уберите логины и пароли")
        if args.target or args.targets_file:
            parser.error("--page-only требует -u URL или --discovery-file FILE")
    if args.collect_only and args.collect_points:
        parser.error(
            "--collect-only выполняет только старый режим сбора; "
            "для совместного запуска используйте --collect-logins --collect-points"
        )
    if args.collect_only and args.generate_logins:
        parser.error("--collect-only не выполняет генерацию; уберите -g")

    credentials_supplied = explicit_logins or explicit_passwords
    args.auth_requested = bool(
        credentials_supplied and not args.discover_only and not args.collect_only
        and not args.page_only
    )

    # The old short form `run -u ... -l ... -p ...` still performs discovery.
    args.implicit_points_for_auth = bool(
        args.auth_requested and (args.url or args.discovery_file)
        and not args.collect_points
    )
    if args.auth_requested and (args.url or args.discovery_file):
        args.collect_points = True

    if args.collect_points:
        if not (args.url or args.discovery_file):
            parser.error(
                "--collect-points и способы поиска требуют -u/--url "
                "или --discovery-file"
            )
        selected_methods = any((
            args.subfinder, args.katana, args.standard_path, args.nmap,
        ))
        if not selected_methods and not args.page_only:
            args.katana = True
            if not args.no_standard_paths:
                args.standard_path = True
        # Subfinder only enumerates names. Katana makes "find and check" useful.
        if args.subfinder and not args.page_only and not any((args.katana, args.standard_path)):
            args.katana = True
        if args.no_standard_paths:
            args.standard_path = False

    if args.mail_domain:
        domain = args.mail_domain.strip().lower().rstrip(".")
        if not args.collect_logins:
            parser.error("--mail-domain используется вместе с --collect-logins")
        if not _valid_mail_domain(domain):
            parser.error("--mail-domain ожидает DNS-домен без схемы, пути и порта, например example.ru")
        args.mail_domain = domain
    if args.company_name is not None:
        args.company_name = args.company_name.strip()
        if not args.company_name:
            parser.error("--company требует непустое название организации")
        if not args.collect_logins:
            parser.error("--company используется вместе с --collect-logins")
    if args.setka_max_pages is not None:
        if args.setka_max_pages < 1:
            parser.error("--setka-max-pages должен быть больше нуля")
        if not args.collect_logins or "setka" not in _collection_sources(args)[1]:
            parser.error("--setka-max-pages требует --collect-logins --people-source setka")
    if not any((args.url, args.target, args.targets_file, args.discovery_file)):
        if not args.collect_logins or not args.mail_domain:
            parser.error(
                "укажите цель через -u/--url, --target или файл; "
                "для сбора только из внешних источников можно указать --mail-domain DOMAIN"
            )
        if args.auth_requested:
            parser.error("для проверки входа нужна страница или сайт через -u/--url, --target или файл")
        email_sources, people_sources = _collection_sources(args)
        if "site" in email_sources or "site" in people_sources:
            parser.error(
                "без -u/--url сбор с сайта недоступен; выберите внешние источники "
                "через --email-source search и/или --people-source search,setka"
            )
        if args.browser_crawl:
            parser.error("--browser-crawl требует адрес сайта через -u/--url или --target")
    args.collect_info = bool(args.collect_logins)
    args.use_collected_logins = bool(
        args.collect_logins and not explicit_logins and args.auth_requested
    )
    # Kept for module 4's automatic e-mail/username routing.
    args.find_logins = args.use_collected_logins

    if not any((args.collect_logins, args.collect_points, args.auth_requested)):
        parser.error(
            "выберите этап: --collect-logins, --collect-points или передайте "
            "логин и пароль для авторизации"
        )

    if args.auth_requested and not (explicit_logins or args.use_collected_logins):
        parser.error(
            "укажите логин через -l/--login/--logins или включите --collect-logins"
        )
    if args.auth_requested and not explicit_passwords:
        parser.error("укажите пароль через -p/--password/--passwords")

    if not args.auth_requested and credentials_supplied:
        # --discover-only and --collect-only intentionally ignore credentials,
        # preserving the previous compatible behaviour.
        return

    if args.auth_requested and not (args.browser or args.browser_http or args.no_auto_browser):
        # Module 4 probes every selected page with HTTP first, then uses a
        # browser only for forms that need JavaScript or a live session.
        args.auto_browser = True
    if args.auto_browser and not args.show_browser:
        args.headless = True


def direct_run_main(
    argv: Sequence[str],
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    runner: Runner | None = None,
    discover_runner: Runner | None = None,
    login_runner: Runner | None = None,
    run_id: str | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv))
    args.browser_resource_domain = list(dict.fromkeys(args.browser_resource_domain or ()))
    _normalize_run_stages(args, parser)
    _apply_ca_certificate_default(args, parser)
    if args.rate is not None and (
        not math.isfinite(args.rate) or not 0 < args.rate <= 10
    ):
        parser.error("--rate должен быть больше 0 и не больше 10")
    if args.threads is not None and not 1 <= args.threads <= 10:
        parser.error("--threads должен быть от 1 до 10")
    if args.katana_depth is not None:
        if not 0 <= args.katana_depth <= 10:
            parser.error("--katana-depth должен быть от 0 до 10")
        if not (args.url or args.discovery_file):
            parser.error("--katana-depth используется с -u/--url или --discovery-file")
    if args.katana_max_total_pages is not None:
        if args.katana_max_total_pages < 1:
            parser.error("--katana-max-total-pages должен быть больше нуля")
        if not (args.url or args.discovery_file):
            parser.error("--katana-max-total-pages используется с -u/--url или --discovery-file")
    if args.katana_max_dom_mb is not None:
        if not 1 <= args.katana_max_dom_mb <= 32:
            parser.error("--katana-max-dom-mb должен быть от 1 до 32")
        if not (args.url or args.discovery_file):
            parser.error("--katana-max-dom-mb используется с -u/--url или --discovery-file")
    if args.no_standard_paths and not (args.url or args.discovery_file):
        parser.error("--no-standard-paths используется с -u/--url или --discovery-file")
    if args.browser_resource_domain and not (args.url or args.discovery_file):
        parser.error("--browser-resource-domain используется с -u/--url или --discovery-file")
    if args.targets_file and any((
        args.quick, args.collect_points, args.collect_logins,
        args.discover_only, args.collect_only, args.generate_logins,
        args.search_engine, args.email_source, args.people_source,
    )):
        parser.error("--targets-file содержит готовые страницы входа; сбор данных и поиск точек для него не запускаются")
    browser_requested = args.browser or args.browser_http or args.auto_browser
    if args.no_auto_browser and not args.auth_requested:
        parser.error("--no-auto-browser относится к проверке входа; передайте логин и пароль")
    if not browser_requested and any((args.headless, args.show_browser, args.browser_timeout is not None, args.success_selector is not None, args.failure_selector is not None)):
        parser.error("--headless/--show-browser/--browser-timeout/--success-selector/--failure-selector требуют браузерный режим")
    if browser_requested and not args.auth_requested:
        parser.error(
            "браузерный режим относится к авторизации; передайте логин и пароль"
        )
    if args.browser or args.browser_http:
        if (
            not (args.target or args.targets_file)
            or args.collect_points
        ):
            parser.error(
                "--browser/--browser-http требуют --target или --targets-file "
                "без поиска точек"
            )
    if browser_requested:
        if args.browser_timeout is not None and not 1 <= args.browser_timeout <= 300:
            parser.error("--browser-timeout должен быть от 1 до 300 секунд")
    selected_email_sources, selected_people_sources = _collection_sources(args)
    if args.search_engine and "search" not in selected_email_sources and "search" not in selected_people_sources:
        parser.error("--search-engine указан, но search не выбран в источниках e-mail или ФИО")
    selected_id = run_id or _new_run_id()
    run_dir = args.artifacts.expanduser().resolve() / selected_id
    audit = args.audit.expanduser().resolve() if args.audit else run_dir / "audit.jsonl"
    report = args.save_report.expanduser().resolve() if args.save_report else run_dir / "report.json"
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        log_path, log = _open_private_run_log(run_dir)
    except OSError as exc:
        print(f"goad run: не удалось создать журнал в {run_dir}: {exc}", file=stderr)
        return 2
    terminal_stdout, terminal_stderr = stdout, stderr
    stdout = _RunOutput(terminal_stdout, log)
    stderr = _RunOutput(terminal_stderr, log)
    component_stdout = _ComponentOutput(
        terminal_stdout, log, verbose=args.verbose,
        found_only=args.page_only and not args.verbose,
    )
    component_stderr = _ComponentOutput(
        terminal_stderr, log, verbose=args.verbose,
        found_only=args.page_only and not args.verbose,
    )

    try:
        _print_run_plan(args, run_dir=run_dir, stream=stderr, interactive=stdin.isatty())
        print(f"[ЛОГ] {log_path}", file=stderr, flush=True)
        login_values, logins_path = _credential_source(
            args.smart_logins, args.login_values, args.logins, "логинов"
        )
        password_values, passwords_path = _credential_source(
            args.smart_passwords, args.password_values, args.passwords, "паролей"
        )
        if args.auth_requested:
            saved_passwords = _save_password_candidates(
                run_dir, password_values, passwords_path,
            )
            if saved_passwords is not None:
                print(f"[ФАЙЛ] Копия паролей для проверки: {saved_passwords}", file=stderr, flush=True)
        if args.targets_file:
            return _run_target_file(
                args, run_dir=run_dir, aggregate_report=report,
                login_values=login_values, logins_path=logins_path,
                password_values=password_values, passwords_path=passwords_path,
                runner=runner, stdout=stdout, stderr=stderr,
                component_stderr=component_stderr, sleeper=sleeper,
            )
        discovery_done = False
        discovery_code = 0
        if args.collect_info and args.subfinder:
            discovery_code = _run_discovery_stage(
                args, report, run_dir, discover_runner,
                component_stdout=component_stdout,
                component_stderr=component_stderr,
                stderr=stderr,
            )
            if discovery_code not in {0, 3}:
                return discovery_code
            discovery_done = True
        if args.collect_info:
            print("[МОДУЛЬ 2] Собираю публичные ФИО и e-mail", file=stderr, flush=True)
            collection_output = _ComponentOutput(
                terminal_stdout, log,
                verbose=args.verbose or (stdin.isatty() and not args.yes),
            )
            collection_errors = _ComponentOutput(
                terminal_stderr, log,
                verbose=args.verbose or (stdin.isatty() and not args.yes),
                suppress_terminal_prefixes=("[СБОР] Подробный журнал:",),
            )
            try:
                with redirect_stdout(collection_output), redirect_stderr(collection_errors):
                    collected_values, collected_path = _find_and_select_logins(
                        args, run_dir, stdin, stdout, stderr, login_runner,
                        require_candidates=args.find_logins and args.auth_requested,
                        discovered_subdomains=(
                            _load_discovered_subdomains(report) if discovery_done else ()
                        ),
                    )
            finally:
                collection_output.finish()
                collection_errors.finish()
            if args.find_logins:
                login_values, logins_path = collected_values, collected_path
            if args.collect_only:
                return 0
            if not args.collect_points and not args.auth_requested:
                return 0
        if args.collect_points:
            code = discovery_code if discovery_done else _run_discovery_stage(
                args, report, run_dir, discover_runner,
                component_stdout=component_stdout,
                component_stderr=component_stderr,
                stderr=stderr,
            )
            if code not in {0, 3}:
                return code
            if not args.auth_requested:
                return _print_discovery_result(
                    report,
                    run_dir / "auth-links.txt",
                    stdout=stdout,
                    stderr=stderr,
                    discovery_code=code,
                    page_only=args.page_only,
                    verbose=args.verbose,
                    shown_found_urls=component_stdout.shown_found_urls,
                )
            selected_targets_path = (
                run_dir / "selected-auth-urls.txt" if args.auto_browser else None
            )
            selected_report = _select_auth_points(
                report,
                run_dir / "selected-report.json",
                stdin,
                stdout,
                assume_yes=args.yes,
                browser_candidates=bool(selected_targets_path),
                targets_output=selected_targets_path,
            )
            if selected_report is None:
                return 2
            if args.find_logins and logins_path is not None:
                logins_path = _route_and_select_login_candidates(
                    logins_path,
                    selected_report,
                    stdin=stdin,
                    stdout=stdout,
                    assume_yes=args.yes,
                )
        else:
            selected_report = None
        if not args.auth_requested:
            return 0
        print("[МОДУЛЬ 4] Запускаю ограниченные попытки авторизации", file=stderr, flush=True)
        if args.auto_browser and selected_report is not None:
            if selected_targets_path is None:
                raise ValueError("не удалось подготовить цели для автоматической проверки")
            batch_args = argparse.Namespace(**vars(args))
            batch_args.targets_file = selected_targets_path
            # Keep one password-free audit for the complete run while
            # each endpoint receives its own sanitized discovery report.
            batch_args.audit = audit
            return _run_target_file(
                batch_args,
                run_dir=run_dir,
                aggregate_report=run_dir / "check-summary.json",
                login_values=login_values,
                logins_path=logins_path,
                password_values=password_values,
                passwords_path=passwords_path,
                runner=runner,
                stdout=stdout,
                stderr=stderr,
                component_stderr=component_stderr,
                sleeper=sleeper,
            )
        check_argv = _check_argv(
            args,
            audit=audit,
            report=report,
            selected_report=selected_report,
            login_values=login_values,
            logins_path=logins_path,
            password_values=password_values,
            passwords_path=passwords_path,
        )
        selected_runner = runner or (
            lambda values: delegate(COMPONENTS["check"], values, stderr=stderr)
        )
        check_stdout = (
            _ComponentOutput(terminal_stdout, log, verbose=True)
            if args.json and not args.verbose else component_stdout
        )
        with redirect_stdout(check_stdout), redirect_stderr(component_stderr):
            return selected_runner(check_argv)
    except KeyboardInterrupt:
        print(
            f"\n[ОСТАНОВЛЕНО] Запуск прерван пользователем. "
            f"Уже созданные файлы сохранены: {run_dir}",
            file=stderr,
            flush=True,
        )
        return 130
    except (DelegationError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"goad run: ошибка: {exc}", file=stderr)
        return 2 if not isinstance(exc, DelegationError) else 127
    finally:
        component_stdout.finish()
        component_stderr.finish()
        print(f"[РЕЗУЛЬТАТЫ] Папка запуска: {run_dir}", file=stderr, flush=True)
        log.close()


def _print_run_plan(
    args: argparse.Namespace,
    *,
    run_dir: Path,
    stream: TextIO,
    interactive: bool,
) -> None:
    """Show the effective orchestration before any component is started."""

    collection_enabled = bool(args.collect_logins)
    discovery_enabled = bool(args.collect_points)
    katana_enabled = discovery_enabled and bool(args.katana)
    subfinder_enabled = discovery_enabled and bool(args.subfinder)
    nmap_enabled = discovery_enabled and bool(args.nmap)
    auth_enabled = bool(args.auth_requested)
    browser_requested = bool(args.browser or args.browser_http or args.auto_browser)
    if args.url:
        target = f"сайт {args.url}"
    elif args.discovery_file:
        target = f"файл разведки {args.discovery_file}"
    elif args.target:
        target = f"точная страница {args.target}"
    elif args.targets_file:
        target = f"готовые страницы {args.targets_file}"
    else:
        target = f"почтовый домен {args.mail_domain} (только внешние источники)"

    print("[ПЛАН ЗАПУСКА]", file=stream)
    print(f"  Цель:                  {target}", file=stream)
    print(f"  User-Agent:            {args.user_agent}", file=stream)
    if collection_enabled:
        email_sources, people_sources = _collection_sources(args)
        print(
            "  Сбор e-mail:           "
            + (", ".join(email_sources) if email_sources else "отключён"),
            file=stream,
        )
        print(
            "  Сбор ФИО:              "
            + (", ".join(people_sources) if people_sources else "отключён"),
            file=stream,
        )
        print(
            "  Документы (PDF):       " + ("отключены" if args.no_documents else "включены"),
            file=stream,
        )
        if "search" in email_sources or "search" in people_sources:
            search_delay = max(
                float(RUN_SPEED_PROFILES[_run_speed_profile(args)]["collection_delay"]),
                DEFAULT_SEARCH_DELAY_SECONDS,
            )
            print(
                "  Поисковики:            "
                + ", ".join(args.search_engine or ("yandex",))
                + f"; пауза между дорками {search_delay:g} с",
                file=stream,
            )
        print(
            "  Генерация кандидатов: "
            + (
                "включена, интерактивный выбор шаблона и формата"
                if args.generate_logins and not args.yes and interactive
                and not (args.quick and args.discover_only)
                else "включена, без вопросов" if args.generate_logins else "отключена"
            ),
            file=stream,
        )
        print(
            "  Почтовый домен:       "
            + (args.mail_domain or "из адреса сайта"),
            file=stream,
        )
        print(
            "  Компания для поиска:  "
            + (args.company_name or "определяется из домена; при несовпадении задайте --company"),
            file=stream,
        )
        collection_scope = (
            "только внешние источники" if not (args.url or args.target or args.discovery_file)
            else "исходные хосты и поддомены Subfinder" if args.subfinder
            else "исходные хосты"
        )
        print(f"  Область сбора:         {collection_scope}", file=stream)
        print(
            "  Обход сайта (сбор):    "
            + (
                "отключён (источник site не выбран)"
                if "site" not in email_sources and "site" not in people_sources
                else (
                    "Chromium с JavaScript"
                    if args.browser_crawl else "облегчённый HTTP + JS fallback"
                )
            ),
            file=stream,
        )
    else:
        print("  Сбор ФИО/e-mail:       отключён", file=stream)
    if args.implicit_points_for_auth:
        print(
            "  Поиск точек:           включён автоматически: заданы логин и пароль",
            file=stream,
        )
    katana_depth_label = (
        "только стартовая страница (0)"
        if args.katana_depth == 0
        else f"глубина {args.katana_depth if args.katana_depth is not None else 2}"
    )
    print(
        "  Katana:                "
        + (
            f"включена, {katana_depth_label}, browser fallback автоматически"
            + (
                f", максимум {args.katana_max_total_pages} страниц"
                if args.katana_max_total_pages is not None else ""
            )
            if katana_enabled else "отключена"
        ),
        file=stream,
    )
    if args.page_only:
        print("  Страницы:              только исходные URL и корни поддоменов; HTTP → браузер", file=stream)
    print(
        f"  Subfinder:             {'включён' if subfinder_enabled else 'отключён'}",
        file=stream,
    )
    if args.browser_resource_domain:
        print(
            "  Ресурсы браузера:      " + ", ".join(args.browser_resource_domain),
            file=stream,
        )
    print(
        f"  Nmap:                  {'включён, top-100 портов' if nmap_enabled else 'отключён'}",
        file=stream,
    )
    print(
        "  Стандартные пути:      "
        + ("включены" if discovery_enabled and args.standard_path else "отключены"),
        file=stream,
    )
    browser_mode = (
        "автоматически"
        if args.auto_browser
        else "browser-http"
        if args.browser_http
        else "браузер"
        if args.browser
        else "отключён (--no-auto-browser; только HTTP-авторизация)"
        if args.no_auto_browser
        else "отключён"
    )
    print(f"  Browser авторизации:   {browser_mode}", file=stream)
    if browser_requested:
        print(f"  Окно Chromium:         {'скрыто (headless)' if args.headless else 'видимое'}", file=stream)
    if args.ca_cert is not None:
        print(f"  CA для HTTPS:          {args.ca_cert}", file=stream)
    elif args.proxy:
        print("  Проверка HTTPS:        отключена для прокси", file=stream)
        print(
            "  [ВНИМАНИЕ] Сертификат HTTPS через прокси не проверяется; "
            "не используйте недоверенный прокси.",
            file=stream,
        )
    print(
        f"  Проверка авторизации:  {'включена' if auth_enabled else 'отключена'}",
        file=stream,
    )
    profile_name = _run_speed_profile(args)
    profile = RUN_SPEED_PROFILES[profile_name]
    print(f"  Профиль скорости:      {profile_name}", file=stream)
    collection_speed = (
        f"пауза между открытием страниц/PDF: {float(profile['collection_delay']):g} с; "
        "обход последовательный"
        if collection_enabled else "не используется"
    )
    if discovery_enabled:
        discovery_speed = str(profile["discovery_profile"])
    else:
        discovery_speed = "не используется"
    if auth_enabled:
        auth_rate = _effective_auth_rate(args)
        auth_threads = _effective_threads(args)
        auth_speed = (
            f"попыток/с: {auth_rate:g} "
            f"(интервал не меньше {1 / auth_rate:g} с), потоков: {auth_threads}"
        )
    else:
        auth_speed = "не используется"
    print(f"  Скорость сбора:        {collection_speed}", file=stream)
    if collection_enabled and "setka" in people_sources:
        setka_delay = max(float(profile["collection_delay"]), SLOW_INTERVAL_SECONDS)
        print(
            f"  Setka, лимиты:        не чаще 1 открытия страницы за {setka_delay:g} с; "
            "HTTP 429 останавливает обход"
            + (
                f"; до {args.setka_max_pages} страниц списков групп и "
                f"{args.setka_max_pages} страниц участников"
                if args.setka_max_pages is not None else ""
            ),
            file=stream,
        )
    print(f"  Скорость поиска:       {discovery_speed}", file=stream)
    if discovery_enabled:
        discovery_limits = DISCOVERY_SPEED_PROFILES[profile_name]
        if subfinder_enabled:
            print(
                f"  Subfinder, лимиты:     до {discovery_limits['subfinder_rate']} запрос/с "
                "к источникам; потоки задаёт Subfinder",
                file=stream,
            )
        if katana_enabled:
            print(
                f"  Katana, лимиты:        до {discovery_limits['katana_rate']} запрос/с "
                f"на процесс; процессов: {discovery_limits['katana_parallelism']}; "
                f"потоков/процесс: {discovery_limits['katana_concurrency']}",
                file=stream,
            )
        if args.standard_path or args.page_only:
            print(
                f"  HTTP точек, лимиты:    потоков: {discovery_limits['http_concurrency']}; "
                f"пауза между стартами: {discovery_limits['http_delay']:g} с",
                file=stream,
            )
        if nmap_enabled:
            print(
                f"  Nmap, лимиты:          -T{discovery_limits['nmap_timing']}, "
                "top-100 портов; скорость/потоки выбирает Nmap",
                file=stream,
            )
    print(f"  Скорость авторизации:  {auth_speed}", file=stream)
    if auth_enabled and args.auto_browser:
        print(
            "  Browser fallback:     только при необходимости; 1 поток для "
            "подготовки и HTTP-проверок",
            file=stream,
        )
    target_delay = float(profile["target_delay"])
    if args.targets_file and target_delay > 0:
        print(f"  Пауза между целями:    {target_delay:g} с", file=stream)
    print(f"  Артефакты:             {run_dir}", file=stream, flush=True)


def _open_private_run_log(run_dir: Path) -> tuple[Path, TextIO]:
    for index in range(1, 1001):
        path = run_dir / ("run.log" if index == 1 else f"run-{index}.log")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        return path, os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)
    raise OSError("достигнут предел файлов run-*.log в каталоге запуска")


def _run_target_file(
    args: argparse.Namespace,
    *,
    run_dir: Path,
    aggregate_report: Path,
    login_values: tuple[str, ...],
    logins_path: Path | None,
    password_values: tuple[str, ...],
    passwords_path: Path | None,
    runner: Runner | None,
    stdout: TextIO,
    stderr: TextIO,
    component_stderr: TextIO,
    sleeper: Callable[[float], None],
) -> int:
    urls = load_target_urls(args.targets_file.expanduser())
    # Fail before processing any target when a shared option is invalid.
    auth_rate = _effective_auth_rate(args)
    auth_threads = _effective_threads(args)
    if not math.isfinite(auth_rate) or not 0 < auth_rate <= 10:
        raise ValueError("--rate должен быть больше 0 и не больше 10")
    if not 1 <= auth_threads <= 10 or (args.max_total is not None and not 1 <= args.max_total <= 1000) or not 1 <= args.max_per_account <= 20:
        raise ValueError("допустимо: --threads 1–10, --max-total 1–1000, --max-per-account 1–20")
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        raise ValueError("--timeout должен быть больше 0 и не больше 60 секунд")
    shared_audit = args.audit.expanduser().resolve() if args.audit else None
    children = [run_dir / f"{index:03d}" for index in range(1, len(urls) + 1)]
    reports = [child / "report.json" for child in children]
    audits = [shared_audit or child / "audit.jsonl" for child in children]
    inputs = [args.targets_file, logins_path, passwords_path, args.ca_cert]
    for values in (args.smart_logins, args.smart_passwords):
        inputs.extend(Path(value).expanduser() for value in values or () if Path(value).expanduser().is_file())
    input_keys = set().union(*(_batch_path_keys(path.expanduser()) for path in inputs if path is not None))
    report_keys = [_batch_path_keys(path) for path in reports]
    audit_keys = [_batch_path_keys(path) for path in audits]
    aggregate_keys = _batch_path_keys(aggregate_report)
    all_reports = set().union(*report_keys)
    all_audits = set().union(*audit_keys)
    if input_keys & (aggregate_keys | all_reports | all_audits):
        raise ValueError("файл отчёта или аудита совпадает с входным файлом; выберите другой путь")
    if aggregate_keys & (all_reports | all_audits) or all_reports & all_audits:
        raise ValueError("пути сводного отчёта, отчётов целей и аудита должны различаться")
    for group in (report_keys, [] if shared_audit else audit_keys):
        seen: set[tuple[object, ...]] = set()
        for keys in group:
            if seen & keys:
                raise ValueError("выходные файлы разных целей ссылаются на один файл; выберите другой каталог")
            seen.update(keys)

    selected_runner = runner or (lambda values: delegate(COMPONENTS["check"], values, stderr=stderr))
    rows: list[dict[str, object]] = []
    return_code = 0
    protected_hosts: set[str] = set()
    previous_target_checked = False
    mode = "auto_browser" if args.auto_browser else "browser_http" if args.browser_http else "browser" if args.browser else "live"
    total_limit = f"лимит {args.max_total} попыток на URL" if args.max_total is not None else "общий лимит попыток не задан"
    print(f"[ЦЕЛИ] {len(urls)}; последовательно; {total_limit}", file=stderr, flush=True)
    for index, (target, child, report, audit) in enumerate(zip(urls, children, reports, audits), 1):
        child.mkdir(parents=True, exist_ok=True)
        target_host = (urlsplit(target).hostname or "").casefold()
        safe_target = _batch_safe_url(target)
        if target_host and target_host in protected_hosts:
            protected_result: dict[str, object] = {
                "schema": "adaptive-check/1",
                "mode": "auto_browser",
                "transport": "none",
                "endpoint": safe_target,
                "outcome": "protected",
                "detail": (
                    "Хост уже остановлен после обнаружения CAPTCHA/защитной "
                    "страницы; запросы к этой странице не выполнялись"
                ),
                "reason": "challenge",
                "protection_detected": True,
                "protection": "captcha",
                "attempted_count": 0,
                "checked_count": 0,
                "halt_reason": "protected:captcha",
                "outcomes": {"protected": 1},
            }
            report.write_text(
                json.dumps(protected_result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            audit.parent.mkdir(parents=True, exist_ok=True)
            with audit.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps({"event": "host_protection_skip", **protected_result}, ensure_ascii=False) + "\n")
            rows.append({
                "target": safe_target,
                "return_code": 0,
                "report": str(report),
                "audit": str(audit),
                "result": protected_result,
            })
            if not args.json:
                print(
                    f"[ЗАЩИТА ОБНАРУЖЕНА] {safe_target} — хост {target_host} "
                    "уже остановлен после CAPTCHA; запросы не выполнялись",
                    file=stdout,
                    flush=True,
                )
            continue
        target_delay = float(
            RUN_SPEED_PROFILES[_run_speed_profile(args)]["target_delay"]
        )
        if target_delay > 0 and previous_target_checked:
            delay_label = (
                "[SLOW]" if _run_speed_profile(args) == "slow"
                else f"[СКОРОСТЬ {_run_speed_profile(args)}]"
            )
            print(
                f"{delay_label} Пауза {target_delay:g} с перед следующей целью",
                file=stderr,
                flush=True,
            )
            sleeper(target_delay)
        child_args = argparse.Namespace(**vars(args))
        child_args.target = target
        child_args.targets_file = None
        check_argv = _check_argv(
            child_args, audit=audit, report=report, selected_report=None,
            login_values=login_values, logins_path=logins_path,
            password_values=password_values, passwords_path=passwords_path,
        )
        print(f"[ЦЕЛЬ {index}/{len(urls)}] {safe_target}", file=stderr, flush=True)
        captured = io.StringIO()
        captured_errors = io.StringIO()
        previous_target_checked = True
        try:
            # Components print their result to sys.stdout. Capture it so batch
            # --json emits one document, while progress remains on stderr.
            with redirect_stdout(captured), redirect_stderr(_TeeTextIO(component_stderr, captured_errors)):
                code = selected_runner(check_argv)
        except KeyboardInterrupt:
            code = 130
            captured_errors.write("Проверка прервана пользователем\n")
        except DelegationError:
            print("goad run: не удалось загрузить модуль проверки", file=stderr)
            captured_errors.write("Не удалось загрузить модуль проверки\n")
            code = 127
        except (OSError, ValueError, json.JSONDecodeError):
            print(f"goad run: не удалось выполнить проверку цели {index}", file=stderr)
            captured_errors.write("Не удалось выполнить проверку цели\n")
            code = 2
        text_output = captured.getvalue()
        child_result = _batch_result(text_output, report)
        if code and child_result is None:
            child_result = _batch_error_result(
                code,
                captured_errors.getvalue(),
                target=target,
                secrets=(*login_values, *password_values),
            )
            if not report.exists():
                report.write_text(
                    json.dumps(child_result, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
        if child_result and (
            child_result.get("protection_detected") is True
            or child_result.get("reason") == "challenge"
        ):
            protected_hosts.add(target_host)
        if child_result and (child_result.get("halt_reason") == "interrupted" or child_result.get("reason") == "interrupted"):
            code = 130
        row: dict[str, object] = {
            "target": safe_target, "return_code": code,
            "report": str(report), "audit": str(audit), "result": child_result,
        }
        rows.append(row)
        if not args.json:
            if text_output.strip():
                print(text_output, end="" if text_output.endswith("\n") else "\n", file=stdout, flush=True)
            else:
                detail = child_result.get("detail") if isinstance(child_result, dict) else None
                suffix = str(detail) if isinstance(detail, str) and detail else f"код: {code}"
                print(f"[{'ПРОВЕРКА ЗАВЕРШЕНА' if code == 0 else 'ОШИБКА'}] {safe_target} — {suffix}", file=stdout, flush=True)
        if code:
            return_code = code if code in {127, 130} else return_code or code
        if code in {127, 130}:
            break

    payload = {
        "schema": "targets-run/1", "mode": mode,
        "targets_count": len(urls), "processed_count": len(rows),
        "completed_count": sum(row["return_code"] == 0 for row in rows),
        "failed_count": sum(row["return_code"] != 0 for row in rows),
        "return_code": return_code, "limits_scope": "per_target",
        "max_total_per_target": args.max_total, "max_per_account": args.max_per_account,
        "rate_per_second": _effective_auth_rate(args),
        "threads": _effective_threads(args), "results": rows,
    }
    # A successful password may be printed by the existing CLI contract, but
    # neither it nor a captured request/session is written into the batch file.
    persisted = {**payload, "results": [
        {**row, "result": _batch_safe_result(row["result"])} for row in rows
    ]}
    aggregate_report.parent.mkdir(parents=True, exist_ok=True)
    aggregate_report.write_text(json.dumps(persisted, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2), file=stdout)
    print(f"[ЦЕЛИ] Обработано {len(rows)}/{len(urls)}; сводка: {aggregate_report}", file=stderr, flush=True)
    return return_code


def _batch_safe_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _batch_path_keys(path: Path) -> set[tuple[object, ...]]:
    # resolve handles symlinks, while inode identity also catches hard links.
    keys: set[tuple[object, ...]] = {("path", str(path.resolve()))}
    try:
        metadata = path.stat()
    except OSError:
        pass
    else:
        keys.add(("inode", metadata.st_dev, metadata.st_ino))
    return keys


def _batch_result(output: str, report: Path) -> dict[str, object] | None:
    try:
        value = json.loads(output)
        if isinstance(value, dict):
            return value
    except (ValueError, TypeError):
        pass
    try:
        value = json.loads(report.read_text(encoding="utf-8"))
        if isinstance(value, dict) and value.get("schema") in {
            "browser-check/1",
            "adaptive-check/1",
        }:
            return value
    except (OSError, ValueError):
        pass
    return None


def _batch_error_result(
    code: int,
    diagnostic: str,
    *,
    target: str,
    secrets: Sequence[str],
) -> dict[str, object]:
    lines = [line.strip() for line in diagnostic.splitlines() if line.strip()]
    preferred = [
        line for line in lines
        if line.casefold().startswith(("authchecker:", "goad run:"))
    ]
    detail = (preferred[-1] if preferred else lines[-1] if lines else f"Компонент завершился с кодом {code}")
    detail = detail.replace(target, _batch_safe_url(target))
    for secret in secrets:
        if secret:
            detail = detail.replace(secret, "<redacted>")
    detail = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in detail
    )[:1000]
    lowered = detail.casefold()
    reason = (
        "timeout" if any(marker in lowered for marker in ("timed out", "timeout", "время ожидания"))
        else "interrupted" if code == 130
        else "component_unavailable" if code == 127
        else "component_error"
    )
    return {
        "schema": "target-error/1",
        "mode": "error",
        "transport": "none",
        "endpoint": _batch_safe_url(target),
        "outcome": "error",
        "detail": detail,
        "reason": reason,
        "attempted_count": 0,
        "checked_count": 0,
        "halt_reason": f"error:{reason}",
        "outcomes": {"error": 1},
    }


def _batch_safe_result(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, object] = {}
    for name in (
        "schema",
        "mode",
        "transport",
        "outcome",
        "detail",
        "halt_reason",
        "reason",
        "protection",
    ):
        item = value.get(name)
        if item is None or isinstance(item, str):
            result[name] = item
    for name in ("attempted_count", "checked_count", "http_status", "job_count"):
        item = value.get(name)
        if isinstance(item, int) and not isinstance(item, bool):
            result[name] = item
    outcomes = value.get("outcomes")
    if isinstance(outcomes, dict):
        result["outcomes"] = {key: count for key, count in outcomes.items() if isinstance(key, str) and isinstance(count, int) and not isinstance(count, bool)}
    protection_detected = value.get("protection_detected")
    if isinstance(protection_detected, bool):
        result["protection_detected"] = protection_detected
    return result


def _load_discovery_goals(path: Path, *, with_nmap: bool) -> tuple[str, ...]:
    """Load mixed discovery inputs and give Katana usable HTTP start URLs."""

    source = path.expanduser()
    if not source.is_file():
        raise ValueError(f"файл целей разведки не найден: {source}")
    goals: list[str] = []
    for line_number, raw in enumerate(
        source.read_text(encoding="utf-8-sig").splitlines(), 1
    ):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        lowered = value.casefold()
        if lowered.startswith(("http://", "https://")):
            parsed = urlsplit(value)
            if not parsed.hostname or parsed.username or parsed.password:
                raise ValueError(
                    f"{source}:{line_number}: нужен HTTP(S) URL без логина и пароля"
                )
            goals.append(urlunsplit((parsed.scheme.casefold(), parsed.netloc, parsed.path or "/", parsed.query, "")))
            continue

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None and "/" in value:
            if not with_nmap:
                raise ValueError(
                    f"{source}:{line_number}: CIDR {value} требует --with-nmap; "
                    "Katana принимает веб-адреса, а не диапазоны IP"
                )
            goals.append(value)
            continue

        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address is not None:
            host = f"[{address}]" if address.version == 6 else str(address)
            if with_nmap:
                goals.append(str(address))
            goals.extend((f"https://{host}/", f"http://{host}/"))
            continue

        parsed_host = urlsplit(f"//{value}")
        try:
            port = parsed_host.port
        except ValueError as exc:
            raise ValueError(f"{source}:{line_number}: некорректная цель {value!r}") from exc
        if (
            not parsed_host.hostname
            or parsed_host.path
            or parsed_host.query
            or parsed_host.fragment
            or parsed_host.username
            or parsed_host.password
            or any(character.isspace() for character in value)
        ):
            raise ValueError(
                f"{source}:{line_number}: укажите домен/IP либо полный URL с http:// или https://"
            )
        try:
            parsed_host.hostname.encode("idna")
        except UnicodeError as exc:
            raise ValueError(f"{source}:{line_number}: некорректный домен {value!r}") from exc
        if with_nmap and port is None:
            goals.append(parsed_host.hostname)
        goals.extend((f"https://{value}/", f"http://{value}/"))

    unique = tuple(dict.fromkeys(goals))
    if not unique:
        raise ValueError(f"файл целей разведки пуст: {source}")
    return unique


def _run_discovery_stage(
    args: argparse.Namespace,
    report: Path,
    run_dir: Path,
    discover_runner: Runner | None,
    *,
    component_stdout: TextIO,
    component_stderr: TextIO,
    stderr: TextIO,
) -> int:
    print("[МОДУЛЬ 3] Собираю точки входа", file=stderr, flush=True)
    selected_discover = discover_runner or (
        lambda values: delegate(COMPONENTS["discover"], values, stderr=stderr)
    )
    discovery_goals = (
        _load_discovery_goals(args.discovery_file, with_nmap=args.nmap)
        if args.discovery_file else ()
    )
    with redirect_stdout(component_stdout), redirect_stderr(component_stderr):
        code = selected_discover(_discover_argv(
            args, report, run_dir / "auth-links.txt", discovery_goals=discovery_goals,
        ))
    if args.page_only and not args.verbose and code not in {0, 3}:
        print(
            f"[ПОИСК] Проверка не завершилась; подробности в {run_dir / 'run.log'}",
            file=stderr,
        )
    return code


def _load_discovered_subdomains(report: Path) -> tuple[str, ...]:
    payload = json.loads(report.read_text(encoding="utf-8"))
    config = payload.get("config", {})
    subfinder = config.get("subfinder", {}) if isinstance(config, dict) else {}
    hosts = subfinder.get("discovered_subdomains", []) if isinstance(subfinder, dict) else []
    if not isinstance(hosts, list):
        raise ValueError("в отчёте поиска некорректный список поддоменов Subfinder")
    return tuple(dict.fromkeys(
        host for host in hosts if isinstance(host, str) and host.strip()
    ))


def _discover_argv(
    args: argparse.Namespace,
    report: Path,
    links: Path,
    *,
    discovery_goals: tuple[str, ...] = (),
) -> list[str]:
    tools = ",".join(
        tool for tool, enabled in (
            ("katana", args.katana),
            ("nmap", args.nmap),
            ("subfinder", args.subfinder),
        )
        if enabled
    )
    values = [
        "--include-subdomains",
        "--output", str(report), "--links-output", str(links),
        "--user-agent", args.user_agent,
    ]
    if tools:
        values[0:0] = ["--tools", tools]
    if args.url:
        values.extend(("-u", args.url))
    for goal in discovery_goals:
        values.extend(("-u", goal))
    if args.page_only:
        values.append("--page-only")
    values.append("--standard-paths" if args.standard_path else "--no-standard-paths")
    if args.proxy:
        values.extend(("--proxy", args.proxy))
    values.append(f"--{_run_speed_profile(args)}")
    if args.subfinder:
        values.extend(("--subfinder-max-results", "50"))
    if args.nmap:
        values.extend(("--top-ports", "100"))
    if args.ca_cert:
        values.extend(("--ca-cert", str(args.ca_cert.expanduser().resolve())))
    if args.katana_depth is not None:
        values.extend(("--katana-depth", str(max(1, args.katana_depth))))
    if args.katana_max_total_pages is not None:
        values.extend((
            "--katana-max-total-pages",
            str(args.katana_max_total_pages),
        ))
    if args.katana_max_dom_mb is not None:
        values.extend(("--katana-max-dom-mb", str(args.katana_max_dom_mb)))
    for domain in args.browser_resource_domain or ():
        values.extend(("--browser-resource-domain", domain))
    return values


def _print_discovery_result(
    report: Path,
    links: Path,
    *,
    stdout: TextIO,
    stderr: TextIO,
    discovery_code: int,
    page_only: bool = False,
    verbose: bool = False,
    shown_found_urls: set[str] | None = None,
) -> int:
    """Finish a search without applying module 4's authentication filters."""

    payload = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError(f"в отчёте нет массива findings: {report}")
    findings = payload["findings"]
    for index, item in enumerate(findings, 1):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("endpoint"), str)
            or not item["endpoint"].strip()
            or not isinstance(item.get("auth_type"), str)
            or not item["auth_type"].strip()
        ):
            raise ValueError(f"некорректная точка findings[{index - 1}] в отчёте: {report}")
    issues = payload.get("issues", [])
    if not isinstance(issues, list):
        raise ValueError(f"в отчёте некорректный массив issues: {report}")
    config = payload.get("config", {})
    page_results = config.get("page_only_results", []) if isinstance(config, dict) else []
    if page_only and not verbose:
        confirmed_urls: list[str] = []
        if isinstance(page_results, list):
            for item in page_results:
                if not isinstance(item, dict) or item.get("status") != "found":
                    continue
                url = item.get("final_url") or item.get("url")
                if isinstance(url, str) and url and url not in confirmed_urls:
                    confirmed_urls.append(url)
        if not isinstance(page_results, list) or not page_results:
            for item in findings:
                if item["auth_type"] == "js_login":
                    continue
                url = item["endpoint"]
                if url not in confirmed_urls:
                    confirmed_urls.append(url)
        shown = shown_found_urls or set()
        for url in confirmed_urls:
            if url not in shown:
                print(f"[НАЙДЕНО] {url}", file=stdout)
        print(
            f"[ПОИСК] Проверено страниц: {len(page_results) if isinstance(page_results, list) else 0}; "
            f"с логинкой: {len(confirmed_urls)}; проблем: {len(issues)}. "
            "Попытки входа не выполнялись.",
            file=stdout,
        )
    elif isinstance(page_results, list) and page_results:
        for item in page_results:
            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                continue
            url = item["url"]
            final_url = item.get("final_url")
            display_url = (
                f"{url} → {final_url}"
                if isinstance(final_url, str) and final_url and final_url != url
                else url
            )
            status = item.get("status")
            if status == "found":
                kinds = item.get("auth_types", [])
                label = ", ".join(kinds) if isinstance(kinds, list) else "точка входа"
                print(f"[НАЙДЕНО] {display_url} — {label}", file=stdout)
            elif status == "unverified":
                detail = str(item.get("detail", "ошибка проверки"))[:300]
                print(f"[НЕ ПРОВЕРЕНО] {display_url} — {detail}", file=stdout)
            else:
                print(f"[НЕ НАЙДЕНО] {display_url}", file=stdout)
    elif findings:
        print("Найдены точки авторизации:", file=stdout)
        for index, item in enumerate(findings, 1):
            print(f"  {index}. {item['endpoint']} ({item['auth_type']})", file=stdout)
    else:
        print("[ПОИСК] Точки авторизации не обнаружены.", file=stdout)
    partial = bool(discovery_code == 3 or payload.get("partial") or issues)
    if not (page_only and not verbose):
        status = "завершён частично" if partial else "завершён"
        print(
            f"[ПОИСК] Поиск {status}: найдено точек {len(findings)}, "
            f"проблем {len(issues)}. Попытки авторизации не выполнялись.",
            file=stdout,
        )
        for issue in issues:
            if isinstance(issue, dict) and issue.get("message"):
                target = f" {issue['target']}" if issue.get("target") else ""
                print(f"[ПРЕДУПРЕЖДЕНИЕ]{target}: {issue['message']}", file=stderr)
        print(f"[ФАЙЛ] Отчёт: {report}", file=stdout)
        print(f"[ФАЙЛ] Ссылки: {links}", file=stdout)
    return 3 if partial else 0


def _select_auth_points(
    report: Path,
    selected_report: Path,
    stdin: TextIO,
    stdout: TextIO,
    *,
    assume_yes: bool,
    browser_candidates: bool = False,
    targets_output: Path | None = None,
) -> Path | None:
    payload = json.loads(report.read_text(encoding="utf-8"))
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"в отчёте нет массива findings: {report}")
    selectable = [
        item for item in findings
        if isinstance(item, dict)
        and isinstance(item.get("endpoint"), str)
        and (
            item.get("auth_type") in LIVE_AUTH_TYPES
            or browser_candidates
            and item.get("auth_type") == "js_login"
            and item.get("kind") == "web_login_page"
        )
    ]
    endpoint_types: dict[str, set[str]] = {}
    for item in selectable:
        endpoint_types.setdefault(str(item["endpoint"]), set()).add(
            str(item.get("auth_type") or "browser_candidate")
        )
    if browser_candidates:
        issues = payload.get("issues")
        if isinstance(issues, list):
            for item in issues:
                if not isinstance(item, dict):
                    continue
                target = item.get("target")
                message = str(item.get("message") or "").casefold()
                if (
                    isinstance(target, str)
                    and target.startswith(("http://", "https://"))
                    and any(marker in message for marker in (
                        "403", "captcha", "challenge", "timeout",
                        "timed out", "javascript", "browser",
                    ))
                ):
                    endpoint_types.setdefault(target, set()).add("browser_fallback")
    endpoints = list(endpoint_types)
    if not endpoints:
        issues = payload.get("issues")
        browser_issue = None
        if isinstance(issues, list):
            browser_issue = next(
                (
                    item.get("message")
                    for item in issues
                    if isinstance(item, dict)
                    and item.get("stage") == "katana_headless"
                    and isinstance(item.get("message"), str)
                ),
                None,
            )
        detail = f"; браузер: {browser_issue}" if browser_issue else ""
        raise ValueError("модуль 3 не нашёл форм пароля или HTTP Basic" + detail)

    print("Найдены точки авторизации:", file=stdout)
    for index, endpoint in enumerate(endpoints, 1):
        types = sorted(endpoint_types[endpoint])
        print(f"  {index}. {endpoint} ({', '.join(types)})", file=stdout)
    chosen = endpoints
    if not assume_yes and stdin.isatty():
        print("Выберите номера через запятую; Enter — выбрать все, q — отмена: ", end="", file=stdout, flush=True)
        raw = stdin.readline().strip().lower()
        if raw in {"q", "quit", "exit"}:
            print("Запуск отменён.", file=stdout)
            return None
        chosen = _number_selection(raw, endpoints, "точки авторизации")
    elif not stdin.isatty() and not assume_yes:
        print("Неинтерактивный ввод: выбраны все найденные точки.", file=stdout)

    payload["findings"] = [
        item for item in selectable if item["endpoint"] in chosen
    ]
    selected_report.parent.mkdir(parents=True, exist_ok=True)
    selected_report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if targets_output is not None:
        targets_output.parent.mkdir(parents=True, exist_ok=True)
        targets_output.write_text("\n".join(chosen) + "\n", encoding="utf-8")
    return selected_report


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _find_and_select_logins(
    args: argparse.Namespace,
    run_dir: Path,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    login_runner: Runner | None,
    *,
    require_candidates: bool = True,
    discovered_subdomains: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], Path | None]:
    seed_urls = (
        tuple(goal for goal in _load_discovery_goals(args.discovery_file, with_nmap=args.nmap)
              if goal.startswith(("http://", "https://")))
        if args.discovery_file else tuple(url for url in (args.url or args.target,) if url)
    )
    if not seed_urls and not args.mail_domain:
        raise ValueError("для сбора e-mail нужен HTTP(S) URL или --mail-domain")
    target = next(
        (url for url in seed_urls
         if not _is_ip_host(urlsplit(url).hostname or "")),
        seed_urls[0] if seed_urls else None,
    )
    domain = (urlsplit(target).hostname or "").lower() if target else args.mail_domain
    if not domain:
        raise ValueError("не удалось определить домен для поиска логинов")
    found = run_dir / "found-emails.txt"
    people = run_dir / "fio.txt"
    generated = run_dir / "generated-logins.txt"
    candidates_path = run_dir / "login-candidates.txt"
    collection_log = run_dir / "collection.log"
    generate_usernames = bool(args.find_logins or args.generate_logins)
    email_sources, people_sources = _collection_sources(args)
    site_selected = "site" in email_sources or "site" in people_sources
    search_selected = "search" in email_sources or "search" in people_sources
    if site_selected and not target:
        raise ValueError("для сбора с сайта нужен хотя бы один HTTP(S) URL")
    if search_selected and args.discovery_file and _is_ip_host(domain) and not args.mail_domain:
        raise ValueError(
            "поиск e-mail/ФИО через поисковик требует домен; "
            "для файла только с IP выберите --email-source site и/или --people-source site"
        )
    engines = args.search_engine or (["yandex"] if search_selected else [])
    values = [
        "--domain", args.mail_domain or domain,
        "--company", args.company_name or (args.mail_domain if _is_ip_host(domain) and args.mail_domain else domain).removeprefix("www.").split(".")[0],
        "--output", str(generated), "--found-emails-output", str(found),
        "--emails-output", str(found), "--people-output", str(people),
        "--evidence-output", str(run_dir / "evidence.jsonl"),
        "--save-artifacts",
        "--browser-pages-dir", str(run_dir / "source-pages"),
        "--search-results-dir", str(run_dir / "search-results"),
        "--pdf-files-dir", str(run_dir / "pdf"),
        "--auto-log", str(collection_log),
        "--no-domain-prompt",
        "--no-default-people", "--no-technical-words", "--user-agent", args.user_agent,
    ]
    if site_selected:
        values.extend(("--url", target))
        values.append("--exact-hosts")
        extra_urls = [url for url in seed_urls if url != target]
        if discovered_subdomains:
            scheme = urlsplit(target).scheme
            extra_urls.extend(f"{scheme}://{host}/" for host in discovered_subdomains)
        extra_urls = list(dict.fromkeys(extra_urls))
        for url in extra_urls:
            values.extend(("--extra-url", url))
        allowed_hosts = dict.fromkeys(
            (urlsplit(url).hostname or "").lower()
            for url in (target, *extra_urls)
        )
        for host in allowed_hosts:
            if host:
                values.extend(("--allowed-domain", host))
        if extra_urls:
            values.extend(("--max-pages", str(max(20, 1 + len(extra_urls)))))
    for source in email_sources:
        values.extend(("--email-source", source))
    for source in people_sources:
        values.extend(("--people-source", source))
    if args.setka_max_pages is not None:
        values.extend(("--setka-max-pages", str(args.setka_max_pages)))
    if generate_usernames:
        values.extend((
            "--kind", "login",
            "--person-pattern", "{f}.{lastname}",
            "--person-pattern", "{firstname}.{lastname}",
            "--person-pattern", "{f}{lastname}",
        ))
        if not args.yes and stdin.isatty() and not (args.quick and args.discover_only):
            values.append("--prompt-inferred-patterns")
        else:
            values.append("--no-pattern-prompt")
    else:
        values.append("--collect-only")
    if args.proxy:
        values.extend(("--proxy", args.proxy))
    if args.ca_cert:
        values.extend(("--ca-cert", str(args.ca_cert)))
    if args.browser_crawl:
        values.append("--browser-crawl")
    if args.no_documents:
        values.append("--no-documents")
    if _run_speed_profile(args) == "slow":
        values.append("--slow")
    else:
        collection_delay = RUN_SPEED_PROFILES[_run_speed_profile(args)][
            "collection_delay"
        ]
        values.extend(("--request-delay", str(collection_delay)))
    for engine in engines:
        values.extend(("--search-engine", engine))
    selected_runner = login_runner or (
        lambda argv: delegate(COMPONENTS["logins"], argv, stderr=stderr)
    )
    code = selected_runner(values)
    if code == 130:
        raise KeyboardInterrupt
    if code:
        raise ValueError(f"поиск логинов завершился с кодом {code}")
    emails = _read_values(found) if found.is_file() else ()
    generated_values = _read_values(generated) if generate_usernames and generated.is_file() else ()
    candidates = list(dict.fromkeys((*emails, *generated_values)))
    if not candidates:
        if not require_candidates:
            return (), None
        raise ValueError("не найдено кандидатов логина; укажите -l вручную")
    if not require_candidates:
        return (), None
    chosen = candidates
    defer_selection = bool(args.find_logins and args.url and not args.collect_only)
    if not defer_selection:
        print("Кандидаты логина:", file=stdout)
        for index, candidate in enumerate(candidates, 1):
            print(f"  {index}. {candidate}", file=stdout)
        if not args.yes and stdin.isatty():
            print("Выберите номера через запятую; Enter — использовать все: ", end="", file=stdout, flush=True)
            chosen = _number_selection(stdin.readline().strip(), candidates, "логины")
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.write_text("\n".join(chosen) + "\n", encoding="utf-8")
    print(f"[ФАЙЛ] Логины для модуля 4: {candidates_path}", file=stdout)
    return (), candidates_path


def _valid_mail_domain(value: str) -> bool:
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return False
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        return False
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        return False
    labels = ascii_domain.split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?", label)
        for label in labels
    )


def _route_and_select_login_candidates(
    candidates_path: Path,
    selected_report: Path,
    *,
    stdin: TextIO,
    stdout: TextIO,
    assume_yes: bool,
) -> Path:
    candidates = list(_read_values(candidates_path))
    payload = json.loads(selected_report.read_text(encoding="utf-8"))
    kinds: set[str] = set()
    for finding in payload.get("findings", []):
        if not isinstance(finding, dict):
            continue
        metadata = finding.get("metadata")
        kind = metadata.get("identifier_kind") if isinstance(metadata, dict) else None
        kinds.add(kind if kind in {"email", "username"} else "unknown")
    if kinds == {"email"}:
        routed = [value for value in candidates if _looks_like_email(value)]
        explanation = "форма принимает e-mail — оставлены найденные адреса"
    elif kinds == {"username"}:
        routed = [value for value in candidates if not _looks_like_email(value)]
        explanation = "форма принимает username — оставлены варианты из ФИО"
    else:
        routed = candidates
        explanation = "тип поля неоднозначен или различается — оставлены оба набора"
    if not routed:
        expected = "e-mail" if kinds == {"email"} else "username"
        raise ValueError(
            f"для поля типа {expected} не найдено подходящих кандидатов; "
            "укажите -l/--login вручную"
        )
    print(f"[КАНДИДАТЫ] {explanation}", file=stdout)
    print("Кандидаты логина:", file=stdout)
    for index, candidate in enumerate(routed, 1):
        print(f"  {index}. {candidate}", file=stdout)
    chosen = routed
    if not assume_yes and stdin.isatty():
        print(
            "Выберите номера через запятую; Enter — использовать все: ",
            end="",
            file=stdout,
            flush=True,
        )
        chosen = _number_selection(stdin.readline().strip(), routed, "логины")
    candidates_path.write_text("\n".join(chosen) + "\n", encoding="utf-8")
    return candidates_path


def _looks_like_email(value: str) -> bool:
    if value.count("@") != 1 or any(character.isspace() for character in value):
        return False
    local, domain = value.rsplit("@", 1)
    return bool(local and domain and "." in domain and not domain.startswith("."))


def _collection_sources(args: argparse.Namespace) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve collection defaults without mixing data types between sources."""

    if args.email_source is None and args.people_source is None:
        return ("site", "search"), ("site", "search")
    return (
        tuple(dict.fromkeys(args.email_source or ())),
        tuple(dict.fromkeys(args.people_source or ())),
    )


def _credential_source(
    smart: list[str] | None,
    explicit: list[str] | None,
    path: Path | None,
    label: str,
) -> tuple[tuple[str, ...], Path | None]:
    if path is not None:
        checked = path.expanduser()
        if not checked.is_file():
            raise ValueError(f"файл {label} не найден: {checked}")
        return (), checked
    if explicit:
        return tuple(explicit), None
    if not smart:
        return (), None
    values: list[str] = []
    for raw in smart:
        candidate = Path(raw).expanduser()
        if candidate.is_file():
            values.extend(_read_values(candidate))
            continue
        if _looks_like_file(raw):
            raise ValueError(f"файл {label} не найден: {candidate}")
        values.extend(part.strip() for part in raw.split(",") if part.strip())
    if not values:
        raise ValueError(f"список {label} пуст")
    return tuple(dict.fromkeys(values)), None


def _save_password_candidates(
    run_dir: Path,
    values: tuple[str, ...],
    source_path: Path | None,
) -> Path | None:
    """Save a private, separate snapshot without changing authentication inputs."""

    if not values and source_path is None:
        return None
    if any("\n" in value or "\r" in value for value in values):
        raise ValueError("пароль с переводом строки нельзя сохранить в TXT-файл кандидатов")

    for index in range(1, 1001):
        destination = run_dir / (
            "password-candidates.txt" if index == 1 else f"password-candidates-{index}.txt"
        )
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        try:
            with os.fdopen(descriptor, "wb") as output:
                if source_path is not None:
                    with source_path.open("rb") as source:
                        shutil.copyfileobj(source, output)
                else:
                    output.write(("\n".join(values) + "\n").encode("utf-8"))
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return destination
    raise OSError("достигнут предел файлов password-candidates-*.txt в каталоге запуска")


def _read_values(path: Path) -> tuple[str, ...]:
    return tuple(
        line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _looks_like_file(value: str) -> bool:
    lowered = value.lower()
    return "/" in value or "\\" in value or lowered.endswith((".txt", ".lst", ".csv"))


def _number_selection(raw: str, choices: list[str], label: str) -> list[str]:
    if not raw or raw in {"all", "*", "0"}:
        return choices
    selected: list[str] = []
    for part in raw.replace(";", ",").split(","):
        try:
            index = int(part.strip())
        except ValueError as exc:
            raise ValueError(f"неверный выбор ({label}): {part!r}") from exc
        if not 1 <= index <= len(choices):
            raise ValueError(f"номер вне диапазона ({label}): {index}")
        if choices[index - 1] not in selected:
            selected.append(choices[index - 1])
    return selected


def _check_argv(
    args: argparse.Namespace,
    *,
    audit: Path,
    report: Path,
    selected_report: Path | None,
    login_values: tuple[str, ...],
    logins_path: Path | None,
    password_values: tuple[str, ...],
    passwords_path: Path | None,
) -> list[str]:
    values = ["run", "--live"]
    if selected_report is not None:
        values.extend(("--report", str(selected_report)))
    else:
        values.extend(("--url", args.target))
    if login_values:
        for login in login_values:
            values.extend(("--login", login))
    else:
        values.extend(("--logins", str(logins_path)))
    if password_values:
        for password in password_values:
            values.extend(("--password", password))
    else:
        values.extend(("--passwords", str(passwords_path)))
    values.extend((
        "--user-agent", args.user_agent,
        "--audit", str(audit), "--rate", str(_effective_auth_rate(args)),
        "--threads", str(_effective_threads(args)),
        "--max-per-account", str(args.max_per_account), "--timeout", str(args.timeout),
    ))
    if args.max_total is not None:
        values.extend(("--max-total", str(args.max_total)))
    if args.proxy:
        values.extend(("--proxy", args.proxy))
    if args.find_logins:
        values.append("--auto-login-candidates")
    if _run_speed_profile(args) == "slow":
        values.append("--slow")
    scope_value = args.url or args.target
    scope_domain = urlsplit(scope_value).hostname if scope_value else None
    if scope_domain:
        values.extend(("--scope-domain", scope_domain, "--allow-subdomains"))
    if args.ca_cert:
        values.extend(("--ca-cert", str(args.ca_cert.expanduser().resolve())))
    if args.browser or args.browser_http or args.auto_browser:
        values.append(
            "--auto-browser" if args.auto_browser
            else "--browser-http" if args.browser_http
            else "--browser"
        )
        if args.headless:
            values.append("--headless")
        if args.browser_timeout is not None:
            values.extend(("--browser-timeout", str(args.browser_timeout)))
        for flag, value in (("--success-selector", args.success_selector), ("--failure-selector", args.failure_selector)):
            if value is not None:
                values.extend((flag, value))
    if selected_report is None:
        values.extend(("--save-report", str(report)))
    if not args.json:
        values.append("--compact")
    return values


def _effective_auth_rate(args: argparse.Namespace) -> float:
    profile = _run_speed_profile(args)
    default = float(RUN_SPEED_PROFILES[profile]["auth_rate"])
    if args.rate is None:
        return default
    return min(args.rate, default) if profile == "slow" else args.rate


def _effective_threads(args: argparse.Namespace) -> int:
    profile = _run_speed_profile(args)
    if profile == "slow":
        return 1
    if args.threads is not None:
        return args.threads
    return int(RUN_SPEED_PROFILES[profile]["auth_threads"])


def _run_speed_profile(args: argparse.Namespace) -> str:
    profile = getattr(args, "speed_profile", DEFAULT_RUN_SPEED_PROFILE)
    return profile if profile in RUN_SPEED_PROFILES else DEFAULT_RUN_SPEED_PROFILE


def _new_run_id() -> str:
    now = datetime.now(UTC)
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
