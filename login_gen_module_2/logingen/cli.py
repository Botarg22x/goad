from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import sys
import tempfile
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from .collector import CollectionResult, EmailSourceRecord, PersonSourceRecord, collect_public_data, collect_vedomosti_speakers, normalize_url
from .config import config_from_dict, load_config, write_example_config
from .evidence_tables import write_evidence_tables
from .generator import VALID_OUTPUT_KINDS, generate
from .help_text import load_cli_help
from .inference import PatternInference, infer_person_pattern_candidates
from .masks import required_custom_charsets, unknown_mask_tokens
from .models import AppConfig, AutoConfig, OutputConfig, PatternsConfig, Person
from .patterns import pattern_tokens
from .search_sources import collect_search_source
from .setka import collect_setka_people
from .workflow import configure_collection, prepare_collection_args, print_collection_plan


VARIABLES_TEXT = """Переменные ФИО:
  {firstname}, {lastname}, {patronymic}
  {first}, {name}, {surname}, {secondname}, {middlename}
  {f}, {f2}, {f3}, {l}, {l2}, {l3}, {p}, {p2}, {p3}
  {firstname1}, {firstname2}, {firstname3}
  {lastname1}, {lastname2}, {lastname3}
  {patronymic1}, {patronymic2}, {patronymic3}
  {company}, {separator}, {domain}

Переменные технических слов:
  {word}, {company}, {separator}, {domain}

Переменные конечного формата:
  {login}, {mail}, {email}, {mail_domain}, {domain}
  {ad_domain}, {netbios}, {company}
"""


PERSON_PATTERN_BLOCKS_TEXT = """Шаблон логина:
  {firstname} — имя, {lastname} — фамилия, {patronymic} — отчество
  {f}, {f2}, {f3} — первые 1, 2 или 3 буквы имени
  {l}, {l2}, {l3} — первые 1, 2 или 3 буквы фамилии
  {p}, {p2}, {p3} — первые 1, 2 или 3 буквы отчества
  Разделители указывайте прямо в шаблоне: . _ -
  Например, для Ивана Иванова: {f}.{lastname} → i.ivanov
  Несколько шаблонов можно указать через запятую.
"""


MASK_BLOCKS_TEXT = """Маски дополнительных символов:
  ?d — цифры 0–9, ?l — строчные a–z, ?u — заглавные A–Z
  ?1, ?2, ?3, ?4 — свои наборы символов; утилита спросит их после выбора
  Например: {f}.{lastname}?d → i.ivanov0, i.ivanov1, …, i.ivanov9
"""


CANDIDATE_FORMAT_BLOCKS_TEXT = """Конечный формат кандидата:
  {login} — логин, например i.ivanov
  {mail} или {email} — логин с почтовым доменом: i.ivanov@example.ru
  {mail_domain} или {domain} — выбранный почтовый домен
  {ad_domain} — домен AD; {netbios} — короткое имя домена AD
  {company} — название компании
  Примеры: {login}, {mail}, {netbios}\\{login}, {login}@{ad_domain}
  Несколько форматов можно указать через запятую.
"""


PERSON_PATTERN_TOKENS = frozenset(
    {
        "firstname",
        "lastname",
        "patronymic",
        "first",
        "name",
        "surname",
        "secondname",
        "middlename",
        "f",
        "f1",
        "f2",
        "f3",
        "l",
        "l1",
        "l2",
        "l3",
        "p",
        "p1",
        "p2",
        "p3",
        "firstname1",
        "firstname2",
        "firstname3",
        "lastname1",
        "lastname2",
        "lastname3",
        "patronymic1",
        "patronymic2",
        "patronymic3",
        "company",
        "separator",
        "domain",
    }
)


CANDIDATE_FORMAT_TOKENS = frozenset(
    {"login", "mail", "email", "mail_domain", "domain", "ad_domain", "netbios", "company"}
)

SLOW_REQUEST_DELAY_SECONDS = 15.0

CONFIG_EXCLUSIVE_CLI_OPTIONS = (
    ("generate", "-g"),
    ("output_dir", "--output-dir"),
    ("save_artifacts", "--save-artifacts"),
    ("katana_depth", "--katana-depth"),
    ("document_types", "--document-types"),
    ("max_documents", "--max-documents"),
    ("output", "--output"),
    ("kind", "--kind"),
    ("company", "--company/--name"),
    ("domain", "--domain/--domen"),
    ("auto", "--auto"),
    ("url", "--url"),
    ("extra_url", "--extra-url"),
    ("allowed_domain", "--allowed-domain"),
    ("max_pages", "--max-pages"),
    ("max_depth", "--max-depth"),
    ("timeout", "--timeout"),
    ("slow", "--slow"),
    ("request_delay", "--request-delay"),
    ("search_delay", "--search-delay"),
    ("user_agent", "--user-agent"),
    ("proxy", "--proxy"),
    ("ca_cert", "--ca-cert"),
    ("browser_crawl", "--browser-crawl"),
    ("headed_browser", "--headed-browser"),
    ("browser_channel", "--browser-channel"),
    ("browser_user_data_dir", "--browser-user-data-dir"),
    ("no_browser_manual_access", "--no-browser-manual-access"),
    ("browser_timeout", "--browser-timeout"),
    ("browser_wait", "--browser-wait"),
    ("browser_pages_dir", "--browser-pages-dir"),
    ("auto_log", "--auto-log"),
    ("ignore_robots", "--ignore-robots"),
    ("vedomosti", "--vedomosti"),
    ("setka", "--setka"),
    ("setka_max_pages", "--setka-max-pages"),
    ("search_engine", "-s/--search-engine"),
    ("email_source", "--email-source"),
    ("people_source", "--people-source"),
    ("no_documents", "--no-documents"),
    ("found_emails_output", "--found-emails-output"),
    ("emails_output", "--emails-output"),
    ("people_output", "--people-output"),
    ("evidence_output", "--evidence-output"),
    ("search_results_dir", "--search-results-dir"),
    ("pdf_files_dir", "--pdf-files-dir"),
    ("limit", "--limit"),
    ("per_person_limit", "--per-person-limit"),
    ("person_pattern", "--person-pattern"),
    ("prompt_inferred_patterns", "--prompt-inferred-patterns"),
    ("no_pattern_prompt", "--no-pattern-prompt"),
    ("no_domain_prompt", "--no-domain-prompt"),
    ("technical_pattern", "--technical-pattern"),
    ("no_default_people", "--no-default-people"),
    ("technical_words", "--technical-words/--include-technical-words"),
    ("no_technical_words", "--no-technical-words"),
)


@dataclass(frozen=True)
class DomainInference:
    domain: str
    matched_count: int
    examples: tuple[str, ...]
    source: str = "site"


class ExternalHelpAction(argparse.Action):
    """Print the user-editable Russian help file verbatim."""

    def __init__(
        self,
        option_strings,
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        **kwargs,
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            **kwargs,
        )

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        sys.stdout.write(load_cli_help())
        parser.exit(0)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        prepare_collection_args(args, parser)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    with tempfile.TemporaryDirectory(prefix="logingen-") as temporary:
        return _main(args, parser, Path(temporary))


def _main(args, parser, temporary: Path) -> int:
    if args.setka_max_pages is not None and args.setka_max_pages < 1:
        parser.error("--setka-max-pages должен быть больше нуля")
    config: AppConfig | None = None
    try:
        args.email_source = _parse_collection_sources(
            args.email_source, ("site", "search"), "--email-source",
        )
        args.people_source = _parse_collection_sources(
            args.people_source, ("site", "search", "setka", "vedomosti"), "--people-source",
        )
    except ValueError as error:
        parser.error(str(error))
    if args.setka_max_pages is not None and not (args.setka or "setka" in (args.people_source or ())):
        parser.error("--setka-max-pages требует --setka или --people-source setka")

    if args.show_variables:
        print(VARIABLES_TEXT)
        return 0

    if args.init_config:
        target = Path(args.init_config)
        if target.exists() and not args.force:
            parser.error(f"{target} already exists; use --force to overwrite it")
        write_example_config(target)
        print(f"Example config written to {target}")
        return 0

    try:
        if args.config:
            conflicts = _config_cli_conflicts(args)
            if conflicts:
                parser.error(
                    "--config cannot be mixed with CLI settings: "
                    f"{', '.join(conflicts)}. Use either --config FILE or pure CLI flags."
                )
            config = load_config(Path(args.config))
        else:
            config = apply_overrides(cli_default_config(), args)
        config = apply_auto_artifact_paths(config, args)
        config = configure_collection(config, args, temporary)
        if is_auto_enabled(config):
            print_collection_plan(config, args, sys.stderr)
        if (args.slow or args.request_delay is not None or args.search_delay is not None) and not is_auto_enabled(config):
            parser.error("--slow/--request-delay/--search-delay require a collection source: --url, -s, --vedomosti, or --setka")
        if is_auto_enabled(config) and config.auto.request_delay_seconds > 0:
            print(
                "[СБОР] Скорость: пауза не меньше "
                f"{config.auto.request_delay_seconds:g} с между открытиями страниц "
                "и запросами документов; ресурсы страниц отдельно",
                file=sys.stderr,
            )
        if args.slow and not config.auto.browser_crawl:
            print(
                "[СБОР] Обход сайта: облегчённый HTTP; для пустой JS-страницы "
                "браузер запустится автоматически. --browser-crawl отрисует все страницы",
                file=sys.stderr,
            )
        if args.collect_only and not (
            config.auto.url
            or config.auto.search_enabled
            or config.auto.vedomosti_enabled
            or config.auto.setka_enabled
        ):
            parser.error(
                "--collect-only needs at least one source: --url, "
                "-s/--search-engine, --vedomosti, or --setka"
            )
        selected_sources = set(args.email_source or ()) | set(args.people_source or ())
        if "site" in selected_sources and not config.auto.url:
            parser.error("source 'site' requires --url")
        collection = None
        inferred_patterns: tuple[str, ...] = ()
        if is_auto_enabled(config):
            if args.collect_only:
                pattern_selector = None
            elif args.person_pattern and args.no_pattern_prompt:
                pattern_selector = lambda _candidates: tuple(args.person_pattern)
            elif args.prompt_inferred_patterns:
                pattern_selector = lambda candidates: choose_inferred_patterns_compact(
                    candidates,
                    fallback_patterns=config.patterns.person,
                    mask_templates=config.generation.masks,
                    input_stream=sys.stdin,
                    output_stream=sys.stderr,
                )
            elif args.no_pattern_prompt:
                pattern_selector = None
            else:
                pattern_selector = lambda candidates: choose_inferred_patterns(
                    candidates,
                    mask_templates=config.generation.masks,
                    fallback_patterns=config.patterns.person,
                    input_stream=sys.stdin,
                    output_stream=sys.stderr,
                )
            domain_selector = None if args.no_domain_prompt else (
                lambda candidates: choose_email_domains(candidates, sys.stdin, sys.stderr)
            )
            source_filtering = bool(args.email_source or args.people_source)
            config, collection, inferred_patterns = run_auto_collection(
                config,
                pattern_selector=pattern_selector,
                domain_selector=domain_selector,
                email_sources=(tuple(args.email_source or ()) if source_filtering else None),
                people_sources=(tuple(args.people_source or ()) if source_filtering else None),
            )
            if not args.no_pattern_prompt and not args.collect_only:
                config = ensure_generation_custom_charsets(config, sys.stdin, sys.stderr)
                config = choose_candidate_formats(config, sys.stdin, sys.stderr)
            if config.patterns.person and not args.collect_only:
                _append_auto_log(config.auto.log_path, f"generation patterns selected: {', '.join(config.patterns.person)}")
            if config.generation.candidate_formats and not args.collect_only:
                _append_auto_log(
                    config.auto.log_path,
                    f"candidate formats selected: {', '.join(config.generation.candidate_formats)}",
                )
    except FileNotFoundError as error:
        print(f"Config file not found: {error.filename}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"Config error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[ОСТАНОВЛЕНО] Сбор прерван; уже найденные ФИО и e-mail сохранены.", file=sys.stderr)
        if config is not None:
            for label, path in (
                ("ФИО", config.auto.fio_path),
                ("E-mail", config.auto.found_emails_path),
                ("Источники", config.auto.evidence_path),
            ):
                if path is not None and path.is_file():
                    print(f"[ФАЙЛ] {label}: {path}", file=sys.stderr)
        return 130

    if collection is not None:
        for warning in collection.warnings:
            print(f"[ПРЕДУПРЕЖДЕНИЕ] {warning}", file=sys.stderr)
        if config.auto.log_path:
            print(f"[СБОР] Подробный журнал: {config.auto.log_path}", file=sys.stderr)
        if config.auto.evidence_path and not args.collect_only:
            print(f"[РЕЗУЛЬТАТ] Источники: {config.auto.evidence_path}")
            print(f"[РЕЗУЛЬТАТ] Таблицы Excel: {config.auto.evidence_path.with_suffix('.xlsx')}")
        if config.patterns.person and not args.collect_only:
            print(
                "[ЛОГИНЫ] Шаблоны генерации: "
                + ", ".join(config.patterns.person),
                file=sys.stderr,
            )

    if args.collect_only:
        if collection is None:
            parser.error("--collect-only requires automatic collection to be enabled")
        write_collection_only_result(config, collection, args.emails_output)
        return 0

    # --emails-output is also useful when collection and generation are
    # performed in one invocation (for example by goad run).
    if collection is not None and args.emails_output:
        _write_lines(Path(args.emails_output), collection.emails)

    result = generate(config)

    for warning in result.stats.warnings:
        print(f"[ПРЕДУПРЕЖДЕНИЕ] {warning}", file=sys.stderr)

    found = collection.emails if collection is not None else ()
    candidates = tuple(dict.fromkeys((*found, *result.candidates)))
    if args.dry_run:
        print_stats(result.stats)
        sample_size = max(args.sample, 0)
        for candidate in candidates[:sample_size]:
            print(candidate)
        return 0

    output_path = Path(args.output) if args.output else config.output.path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_lines(output_path, candidates)
    print(f"[ЛОГИНЫ] Сохранено: {len(candidates)} (найдено {len(found)}, "
          f"сгенерировано {len(candidates) - len(found)}); файл: {output_path}")
    if collection is not None:
        print(f"[РЕЗУЛЬТАТ] ФИО: {config.auto.fio_path}")
        print(f"[РЕЗУЛЬТАТ] E-mail: {config.auto.found_emails_path}")
        print(f"[РЕЗУЛЬТАТ] Папка: {output_path.parent}")
    if args.verbose:
        print_stats(result.stats)
    return 0


def cli_default_config() -> AppConfig:
    # CLI-only mode must work from any current directory.  Project-relative
    # dictionary files remain available to explicit YAML configurations, while
    # built-in Python defaults are used when no config was requested.
    config = config_from_dict(
        {
            "technical_words_path": "none",
            "generation": {
                "masks_path": "none",
                "candidate_formats_path": "none",
            },
            "auto": {"search_dorks_path": "none"},
        }
    )
    generation = replace(config.generation, include_technical_words=False)
    return replace(config, generation=generation)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logingen",
        description="Generate login candidates from Russian names and configurable patterns.",
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("-h", "--help", action=ExternalHelpAction, help=argparse.SUPPRESS)
    parser.add_argument("--config", help="Path to YAML config. If omitted, use CLI-only defaults.")
    parser.add_argument("--init-config", metavar="PATH", help="Write an example YAML config and exit.")
    parser.add_argument("--force", action="store_true", help="Overwrite target when used with --init-config.")
    parser.add_argument("--output", help="Output file path.")
    parser.add_argument("-o", "--output-dir", help="Общая папка результатов.")
    parser.add_argument("-g", "--generate", action="store_true", help="После сбора открыть генерацию кандидатов.")
    parser.add_argument("--save-artifacts", action="store_true", help="Сохранить документы, HTML, источники, Excel и журнал.")
    parser.add_argument("--kind", choices=sorted(VALID_OUTPUT_KINDS), help="Generate login, email, or both.")
    parser.add_argument("--company", "--name", dest="company", help="Override company value.")
    parser.add_argument("--domain", "--domen", dest="domain", action="append", help="Override domains. Can be passed multiple times.")
    parser.add_argument("--auto", action="store_true", help="Enable automatic public collection before generation.")
    parser.add_argument("-u", "--url", metavar="URL|FILE", help="Активный сбор Katana: URL или UTF-8 файл адресов.")
    parser.add_argument("--katana-executable", default="katana", help="Путь к Katana.")
    parser.add_argument("--katana-depth", type=int, help="0/1 — стартовые страницы, 2 — также их ссылки.")
    parser.add_argument("--max-documents", type=int, help="Максимум скачиваемых документов.")
    parser.add_argument("--document-types", action="append", help="Форматы документов через запятую.")
    parser.add_argument("--extra-url", action="append", help="Additional in-scope URL for automatic collection.")
    parser.add_argument("--allowed-domain", action="append", help="Allowed domain for automatic collection. Can be passed multiple times.")
    parser.add_argument("--exact-hosts", action="store_true", help="Collect only from listed hosts, not their other subdomains.")
    parser.add_argument("--max-pages", type=int, help="Maximum number of pages to fetch in auto mode.")
    parser.add_argument("--max-depth", type=int, help="Maximum crawl depth in auto mode.")
    parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds for auto mode.")
    parser.add_argument(
        "--slow",
        action="store_true",
        help="Very slow collection: wait at least 15 seconds between top-level requests.",
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        metavar="SECONDS",
        help="Pause between top-level collection requests (0-3600 seconds).",
    )
    parser.add_argument(
        "--search-delay",
        type=float,
        metavar="SECONDS",
        help="Pause between Yandex/Google search queries (0-3600 seconds; default 10).",
    )
    parser.add_argument("--user-agent", help="User-Agent для сайта и поисковиков (по умолчанию Chrome/Linux)")
    parser.add_argument("--proxy", help="HTTP proxy URL for site and search requests.")
    parser.add_argument(
        "--ca-cert",
        type=Path,
        metavar="FILE",
        help="PEM CA для проверки HTTPS через proxy; без него при --proxy проверка отключена.",
    )
    parser.add_argument("--browser-crawl", action="store_true", help="Render company-site pages with Playwright before parsing.")
    parser.add_argument("--headed-browser", action="store_true", help="Show browser window for Playwright browser pages.")
    parser.add_argument("--browser-channel", help="Installed browser channel for Playwright, for example chrome or msedge.")
    parser.add_argument("--browser-user-data-dir", help="Persistent browser profile directory for Playwright cookies and sessions.")
    parser.add_argument("--no-browser-manual-access", action="store_true", help="Do not pause on company-site HTTP 401/403 in a visible browser.")
    parser.add_argument("--browser-timeout", type=int, help="Playwright page timeout in seconds.")
    parser.add_argument("--browser-wait", type=int, help="Extra wait after page load in milliseconds.")
    parser.add_argument("--browser-pages-dir", help="Directory for rendered company-site HTML pages.")
    parser.add_argument("--search-results-dir", help="Directory for saved search result HTML pages.")
    parser.add_argument("--documents-dir", "--pdf-files-dir", dest="pdf_files_dir", help="Каталог скачанных документов.")
    parser.add_argument("--auto-log", help="Path for auto-mode line-by-line log. Use 'none' to disable file logging.")
    parser.add_argument("--ignore-robots", action="store_true", help="Do not check robots.txt in auto mode.")
    parser.add_argument("--vedomosti", action="store_true", help="Collect public speaker names from events.vedomosti.ru search.")
    parser.add_argument("--setka", action="store_true", help="Collect public employee names from setka.ru company networks.")
    parser.add_argument("--setka-max-pages", type=int, metavar="N", help="Проверить не более N страниц участников Setka.")
    parser.add_argument(
        "--no-documents", action="store_true",
        help="Не скачивать и не обрабатывать PDF; продолжить поиск по страницам и выдаче поисковиков.",
    )
    parser.add_argument(
        "--email-source",
        action="append",
        help="Источники e-mail: site,search; через запятую или повторением флага.",
    )
    parser.add_argument(
        "--people-source",
        action="append",
        help="Источники ФИО: site,search,setka,vedomosti; через запятую или повторением флага.",
    )
    parser.add_argument(
        "-s",
        "--search-engine",
        action="append",
        nargs="+",
        metavar="ENGINE",
        help="Search engine to use: yandex, google. Can be repeated, comma-separated, or space-separated.",
    )
    parser.add_argument("--found-emails-output", help="Path for combined emails found in search results. Use 'none' to disable writing.")
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Collect public emails and people, write artifacts, and skip login generation.",
    )
    parser.add_argument("--emails-output", help="Combined email output for --collect-only.")
    parser.add_argument("--people-output", help="Collected people output path.")
    parser.add_argument("--evidence-output", help="JSONL file recording source URLs and saved proof for found people and emails.")
    parser.add_argument("--limit", type=int, help="Override total output limit.")
    parser.add_argument("--per-person-limit", type=int, help="Override local login limit per person.")
    parser.add_argument("--person-pattern", action="append", help="Override person patterns. Can be passed multiple times.")
    parser.add_argument(
        "--prompt-inferred-patterns",
        action="store_true",
        help="Показать краткий выбор шаблонов перед выбором формата результата.",
    )
    parser.add_argument("--no-pattern-prompt", action="store_true", help="Do not prompt when multiple email patterns are inferred; use all inferred patterns.")
    parser.add_argument("--no-domain-prompt", action="store_true", help="Do not prompt when multiple email domains are found; use all inferred domains.")
    parser.add_argument("--technical-pattern", action="append", help="Override technical patterns. Can be passed multiple times.")
    parser.add_argument("--no-default-people", action="store_true", help="Do not use built-in people if config has none.")
    parser.add_argument(
        "--technical-words",
        "--include-technical-words",
        dest="technical_words",
        action="store_true",
        help="Enable technical-word candidates in CLI mode.",
    )
    parser.add_argument("--no-technical-words", action="store_true", help="Disable technical-word candidates.")
    parser.add_argument("--dry-run", action="store_true", help="Print stats and a sample instead of writing a file.")
    parser.add_argument("--sample", type=int, default=20, help="Number of candidates to print in dry-run mode.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed stats after writing.")
    parser.add_argument("--show-variables", action="store_true", help="Show supported pattern variables and exit.")
    return parser


def _config_cli_conflicts(args: argparse.Namespace) -> tuple[str, ...]:
    conflicts: list[str] = []
    for attr, label in CONFIG_EXCLUSIVE_CLI_OPTIONS:
        value = getattr(args, attr, None)
        if value in (None, False, (), []):
            continue
        conflicts.append(label)
    return tuple(conflicts)


def apply_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    output = config.output
    if args.kind:
        output = replace(output, kind=args.kind)
    if args.output:
        output = replace(output, path=Path(args.output))

    limits = config.limits
    if args.limit is not None:
        limits = replace(limits, total=args.limit if args.limit > 0 else None)
    if args.per_person_limit is not None:
        limits = replace(limits, per_person=args.per_person_limit if args.per_person_limit > 0 else None)

    generation = config.generation
    if args.no_default_people:
        generation = replace(generation, use_default_people_when_empty=False)
    if args.technical_words:
        generation = replace(generation, include_technical_words=True)
    if args.no_technical_words:
        generation = replace(generation, include_technical_words=False)

    patterns = config.patterns
    if args.person_pattern:
        patterns = replace(patterns, person=tuple(args.person_pattern))
    if args.technical_pattern:
        patterns = replace(patterns, technical=tuple(args.technical_pattern))

    domains = config.domains
    if args.domain:
        domains = tuple(domain.strip().lower().lstrip("@") for domain in args.domain if domain.strip())

    auto = config.auto
    mode = config.mode
    if args.auto or args.url or args.vedomosti or args.setka or args.search_engine or args.collect_only or args.email_source or args.people_source:
        mode = "auto"
        auto = replace(auto, enabled=True)
    if args.url:
        auto = replace(auto, url=args.url.strip())
    if args.extra_url:
        auto = replace(auto, extra_urls=tuple(args.extra_url))
    if args.allowed_domain:
        auto = replace(auto, allowed_domains=tuple(_normalize_domain_arg(item) for item in args.allowed_domain if item.strip()))
    if args.exact_hosts:
        auto = replace(auto, exact_hosts=True)
    if args.max_pages is not None:
        auto = replace(auto, max_pages=args.max_pages if args.max_pages > 0 else auto.max_pages)
    if args.max_depth is not None:
        auto = replace(auto, max_depth=args.max_depth if args.max_depth >= 0 else auto.max_depth)
    if args.timeout is not None:
        auto = replace(auto, timeout_seconds=args.timeout if args.timeout > 0 else auto.timeout_seconds)
    if args.request_delay is not None:
        if not math.isfinite(args.request_delay) or not 0 <= args.request_delay <= 3600:
            raise ValueError("--request-delay must be between 0 and 3600 seconds")
        auto = replace(auto, request_delay_seconds=args.request_delay)
    if args.search_delay is not None:
        if not math.isfinite(args.search_delay) or not 0 <= args.search_delay <= 3600:
            raise ValueError("--search-delay must be between 0 and 3600 seconds")
        auto = replace(auto, search_delay_seconds=args.search_delay)
    if args.slow:
        auto = replace(
            auto,
            request_delay_seconds=max(
                auto.request_delay_seconds,
                SLOW_REQUEST_DELAY_SECONDS,
            ),
            browser_crawl=False,
        )
    if args.user_agent is not None:
        user_agent = args.user_agent.strip()
        if not user_agent or len(user_agent) > 512 or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in user_agent
        ):
            raise ValueError("--user-agent must contain 1-512 characters without controls")
        auto = replace(auto, user_agent=user_agent)
    if args.proxy is not None:
        proxy = args.proxy.strip()
        parsed_proxy = urllib.parse.urlsplit(proxy)
        if parsed_proxy.scheme != "http" or not parsed_proxy.hostname or parsed_proxy.port is None:
            raise ValueError("--proxy must be an HTTP URL with an explicit port")
        if parsed_proxy.username or parsed_proxy.password or parsed_proxy.path not in {"", "/"}:
            raise ValueError("--proxy must not contain credentials or a path")
        auto = replace(auto, proxy_url=proxy)
    if args.ca_cert is not None:
        certificate = args.ca_cert.expanduser().resolve()
        if not certificate.is_file():
            raise ValueError(f"--ca-cert file not found: {certificate}")
        auto = replace(auto, ca_cert=certificate)
    if args.browser_crawl:
        auto = replace(auto, browser_crawl=True)
    if args.headed_browser:
        auto = replace(auto, browser_headless=False)
    if args.browser_channel is not None:
        auto = replace(auto, browser_channel=args.browser_channel.strip())
    if args.browser_user_data_dir:
        auto = replace(auto, browser_user_data_dir=Path(args.browser_user_data_dir))
    if args.no_browser_manual_access:
        auto = replace(auto, browser_manual_access=False)
    if args.browser_timeout is not None:
        auto = replace(auto, browser_timeout_seconds=args.browser_timeout if args.browser_timeout > 0 else auto.browser_timeout_seconds)
    if args.browser_wait is not None:
        auto = replace(auto, browser_wait_ms=max(args.browser_wait, 0))
    if args.browser_pages_dir:
        auto = replace(auto, browser_pages_dir=Path(args.browser_pages_dir))
    if args.search_results_dir:
        auto = replace(auto, search_results_dir=Path(args.search_results_dir))
    if args.pdf_files_dir:
        auto = replace(auto, pdf_files_dir=Path(args.pdf_files_dir))
    if args.auto_log:
        auto = replace(auto, log_path=None if args.auto_log.lower() in {"none", "null", "off"} else Path(args.auto_log))
    if args.ignore_robots:
        auto = replace(auto, respect_robots_txt=False)
    if args.vedomosti:
        auto = replace(auto, vedomosti_enabled=True)
    if args.setka:
        auto = replace(auto, setka_enabled=True)
    if args.setka_max_pages is not None:
        auto = replace(auto, setka_max_pages=args.setka_max_pages)
    if args.no_documents:
        auto = replace(auto, pdf_enabled=False)
    selected_email_sources = set(args.email_source or ())
    selected_people_sources = set(args.people_source or ())
    if "setka" in selected_people_sources:
        auto = replace(auto, setka_enabled=True)
    if "vedomosti" in selected_people_sources:
        auto = replace(auto, vedomosti_enabled=True)
    if "search" in selected_email_sources or "search" in selected_people_sources:
        auto = replace(auto, search_enabled=True, search_fetch_enabled=True)
    if args.search_engine:
        auto = replace(
            auto,
            search_enabled=True,
            search_fetch_enabled=True,
            search_engines=_parse_search_engine_args(args.search_engine),
        )
    if args.found_emails_output:
        auto = replace(
            auto,
            found_emails_path=None
            if args.found_emails_output.lower() in {"none", "null", "off"}
            else Path(args.found_emails_output),
        )
    if args.people_output:
        auto = replace(auto, fio_path=Path(args.people_output))
    if args.evidence_output:
        auto = replace(auto, evidence_path=Path(args.evidence_output))

    return replace(
        config,
        mode=mode,
        company=args.company.strip() if args.company else config.company,
        domains=domains,
        output=output,
        limits=limits,
        generation=generation,
        patterns=patterns,
        auto=auto,
    )


def apply_auto_artifact_paths(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    if not is_auto_enabled(config):
        return config

    base = _artifact_directory_base(config)
    if not base:
        return config

    output_dir = Path("output") / base
    auto = config.auto
    output = config.output
    default_auto = AutoConfig()
    default_output = OutputConfig()

    if not args.output and output.path == default_output.path:
        output = replace(output, path=output_dir / "logins.txt")
    if not args.auto_log and auto.log_path == default_auto.log_path:
        auto = replace(auto, log_path=output_dir / "log.txt")
    if auto.mail_from_url_path == default_auto.mail_from_url_path:
        auto = replace(auto, mail_from_url_path=output_dir / "mail_from_url.txt")
    if auto.fio_path == default_auto.fio_path:
        auto = replace(auto, fio_path=output_dir / "fio.txt")
    if not args.found_emails_output and auto.found_emails_path == default_auto.found_emails_path:
        auto = replace(auto, found_emails_path=output_dir / "mail_from_search.txt")
    if auto.email_sources_path == default_auto.email_sources_path:
        sources_dir = Path(args.evidence_output).parent if args.evidence_output else output_dir
        auto = replace(auto, email_sources_path=sources_dir / "email_sources.csv")
    if not args.evidence_output and auto.evidence_path == default_auto.evidence_path:
        auto = replace(auto, evidence_path=output_dir / "evidence.jsonl")
    if auto.search_results_dir == default_auto.search_results_dir:
        auto = replace(auto, search_results_dir=output_dir / "search_results")
    if auto.pdf_files_dir == default_auto.pdf_files_dir:
        auto = replace(auto, pdf_files_dir=output_dir / "pdf")
    if auto.browser_pages_dir == default_auto.browser_pages_dir:
        auto = replace(auto, browser_pages_dir=output_dir / "site_pages")

    if _is_placeholder_company(config.company):
        company = _company_from_domain(_domain_from_url(config.auto.url) or (config.domains[0] if config.domains else ""))
        if company:
            config = replace(config, company=company)

    return replace(config, output=output, auto=auto)


def print_stats(stats) -> None:
    print(f"people: {stats.people_count}")
    print(f"technical_words: {stats.technical_words_count}")
    print(f"emitted: {stats.emitted_count}")
    print(f"duplicates_skipped: {stats.duplicate_count}")


def write_collection_only_result(
    config: AppConfig,
    collection: CollectionResult,
    emails_output: str | None = None,
) -> Path:
    emails_path = Path(emails_output) if emails_output else config.auto.found_emails_path or config.output.path.parent / "emails.txt"
    _write_lines(emails_path, collection.emails)
    print(f"[РЕЗУЛЬТАТ] E-mail: {emails_path}")
    if config.auto.fio_path:
        print(f"[РЕЗУЛЬТАТ] ФИО: {config.auto.fio_path}")
    if config.auto.evidence_path:
        print(f"[РЕЗУЛЬТАТ] Источники: {config.auto.evidence_path}")
        print(f"[РЕЗУЛЬТАТ] Таблицы Excel: {config.auto.evidence_path.with_suffix('.xlsx')}")
    print("[РЕЗУЛЬТАТ] Генерация логинов: пропущена (включить: -g)")
    print(f"[РЕЗУЛЬТАТ] Папка: {config.output.path.parent.resolve()}")
    return emails_path


def is_auto_enabled(config: AppConfig) -> bool:
    return config.mode == "auto" or config.auto.enabled


def run_auto_collection(
    config: AppConfig,
    pattern_selector: Callable[[tuple[PatternInference, ...]], tuple[str, ...]] | None = None,
    domain_selector: Callable[[tuple[DomainInference, ...]], tuple[str, ...]] | None = None,
    email_sources: tuple[str, ...] | None = None,
    people_sources: tuple[str, ...] | None = None,
) -> tuple[AppConfig, CollectionResult, tuple[str, ...]]:
    logger = AutoLogger(config.auto.log_path)
    collections: list[CollectionResult] = []
    site_collection = CollectionResult()
    source_filtering = email_sources is not None or people_sources is not None
    selected_email_sources = set(email_sources or ())
    selected_people_sources = set(people_sources or ())

    def source_enabled(name: str) -> bool:
        return not source_filtering or name in selected_email_sources or name in selected_people_sources

    def filtered(collection: CollectionResult, name: str) -> CollectionResult:
        if not source_filtering:
            return collection
        keep_emails = name in selected_email_sources
        keep_people = name in selected_people_sources
        return replace(
            collection,
            emails=collection.emails if keep_emails else (),
            email_sources=collection.email_sources if keep_emails else (),
            person_sources=collection.person_sources if keep_people else (),
            domains=collection.domains if keep_emails else (),
            people=collection.people if keep_people else (),
        )

    def checkpoint(partial: CollectionResult | None = None) -> None:
        snapshot = _merge_collection_results(
            (*collections, partial) if partial is not None else tuple(collections)
        )
        if not snapshot.people and not snapshot.emails:
            return
        _write_people(config.auto.fio_path, snapshot.people)
        _write_lines(config.auto.found_emails_path, snapshot.emails)
        _write_email_sources(config.auto.email_sources_path, snapshot.email_sources)
        _write_evidence(config.auto.evidence_path, snapshot)
        logger(f"checkpoint saved: people={len(snapshot.people)} emails={len(snapshot.emails)}")

    if config.auto.url and source_enabled("site"):
        site_auto = replace(
            config.auto,
            collect_emails=(not source_filtering or "site" in selected_email_sources),
            collect_people=(not source_filtering or "site" in selected_people_sources),
        )
        site_collection = filtered(collect_public_data(
            site_auto, log=logger, on_progress=lambda partial: checkpoint(filtered(partial, "site")),
        ), "site")
        collections.append(site_collection)
        checkpoint()
        _write_lines(config.auto.mail_from_url_path, site_collection.emails)
        if config.auto.mail_from_url_path:
            logger(f"site emails written: {config.auto.mail_from_url_path} ({len(site_collection.emails)})")
    elif config.auto.url:
        logger("site crawl skipped: site is not selected as a collection source")
    elif config.auto.vedomosti_enabled or config.auto.setka_enabled or config.auto.search_enabled:
        logger(
            "site crawl skipped: site is not selected as a collection source"
            if not source_enabled("site") else "site crawl skipped: auto.url is empty"
        )

    if config.auto.vedomosti_enabled and source_enabled("vedomosti"):
        collections.append(filtered(collect_vedomosti_speakers(config.company, config.auto, log=logger), "vedomosti"))
        checkpoint()
    if config.auto.setka_enabled and source_enabled("setka"):
        collections.append(filtered(collect_setka_people(
            config.company, config.auto, log=logger,
            on_progress=lambda partial: checkpoint(filtered(partial, "setka")),
        ), "setka"))
        checkpoint()

    preliminary_collection = _merge_collection_results(tuple(collections))
    url_domain = _domain_from_url(config.auto.url)
    configured_domains = _effective_configured_domains(config.domains, url_domain)
    site_domain_candidates = _infer_email_domain_candidates(preliminary_collection.emails, source="site")
    selected_domains = _select_email_domains(configured_domains, site_domain_candidates, domain_selector)
    preliminary_domains = selected_domains or _merge_values(url_domain)

    if config.auto.search_enabled and source_enabled("search"):
        search_result = collect_search_source(
            config.auto, preliminary_domains, company=config.company, log=logger,
            on_progress=lambda partial: checkpoint(filtered(partial, "search")),
        )
        collections.append(filtered(search_result.collection, "search"))
        checkpoint()

    collection = _merge_collection_results(tuple(collections))
    _write_lines(config.auto.found_emails_path, collection.emails)
    _write_email_sources(config.auto.email_sources_path, collection.email_sources)
    _write_evidence(config.auto.evidence_path, collection)
    if config.auto.email_sources_path:
        logger(f"email sources written: {config.auto.email_sources_path} ({len(collection.email_sources)})")
    _write_people(config.auto.fio_path, collection.people)
    if config.auto.fio_path:
        logger(f"fio written: {config.auto.fio_path} ({len(collection.people)})")

    print_collection_summary(collection, config.auto.fio_path, sys.stderr)
    people = _merge_people(config.people, collection.people)
    if configured_domains or selected_domains:
        domains = configured_domains or selected_domains
    else:
        collected_domain_candidates = _infer_email_domain_candidates(collection.emails, source="collected")
        domains = _select_email_domains((), collected_domain_candidates, domain_selector) or _merge_values(
            collection.domains,
            url_domain,
        )
    config = replace(config, people=people, domains=domains)

    inferred_candidates = infer_person_pattern_candidates(collection.emails, people, config)
    inferred = (
        pattern_selector(inferred_candidates)
        if pattern_selector
        else tuple(candidate.pattern for candidate in inferred_candidates)
    )
    if inferred:
        config = replace(
            config,
            patterns=PatternsConfig(
                person=inferred,
                technical=config.patterns.technical,
            ),
        )
    return config, collection, inferred


def print_collection_summary(
    collection: CollectionResult,
    people_path: Path | None,
    output_stream: TextIO,
) -> None:
    people_file = f"; файл: {people_path}" if people_path else ""
    print(f"[СБОР] Найдено ФИО: {len(collection.people)}{people_file}", file=output_stream)
    print(f"[ПОЧТЫ] Найдено: {len(collection.emails)}", file=output_stream)
    for email in collection.emails:
        print(f"  {email}", file=output_stream)


def choose_email_domains(
    candidates: tuple[DomainInference, ...],
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> tuple[str, ...]:
    if not candidates:
        return ()
    if len(candidates) == 1:
        print(f"[ДОМЕН] Почтовый домен: {candidates[0].domain}", file=output_stream)
        return tuple(candidate.domain for candidate in candidates)

    print("[ДОМЕНЫ] Найдены почтовые домены:", file=output_stream)
    for index, candidate in enumerate(candidates, start=1):
        _print_domain_candidate(index, candidate, output_stream)

    if not input_stream.isatty():
        return tuple(candidate.domain for candidate in candidates)

    print("Номера доменов через запятую; Enter — использовать все:", file=output_stream)
    raw = input_stream.readline().strip().lower()
    if not raw or raw in {"all", "*", "0"}:
        return tuple(candidate.domain for candidate in candidates)

    selected: list[str] = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            index = int(part)
        except ValueError:
            print(f"[ДОМЕНЫ] Некорректный номер {part!r}; использую все домены.", file=output_stream)
            return tuple(candidate.domain for candidate in candidates)
        if not 1 <= index <= len(candidates):
            print(f"[ДОМЕНЫ] Номера {index} нет в списке; использую все домены.", file=output_stream)
            return tuple(candidate.domain for candidate in candidates)
        domain = candidates[index - 1].domain
        if domain not in selected:
            selected.append(domain)

    return tuple(selected) if selected else tuple(candidate.domain for candidate in candidates)


def choose_inferred_patterns(
    candidates: tuple[PatternInference, ...],
    mask_templates: tuple[str, ...] = (),
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
    fallback_patterns: tuple[str, ...] = (),
) -> tuple[str, ...]:
    return choose_inferred_patterns_compact(
        candidates,
        fallback_patterns=fallback_patterns,
        mask_templates=mask_templates,
        input_stream=input_stream,
        output_stream=output_stream,
    )


def choose_inferred_patterns_compact(
    candidates: tuple[PatternInference, ...],
    fallback_patterns: tuple[str, ...] = (),
    mask_templates: tuple[str, ...] = (),
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> tuple[str, ...]:
    """Select inferred login patterns using the compact unified-CLI interface."""
    inferred_patterns = tuple(dict.fromkeys(candidate.pattern for candidate in candidates))
    choices = list(candidates)
    known_patterns = set(inferred_patterns)
    for pattern in fallback_patterns:
        if pattern in known_patterns:
            continue
        choices.append(PatternInference(pattern, 0, (), source="configured"))
        known_patterns.add(pattern)

    selectable = tuple(choices)
    defaults = inferred_patterns or tuple(dict.fromkeys(fallback_patterns))
    if candidates:
        print(
            "[ШАБЛОНЫ] Варианты по найденным почтам:",
            file=output_stream,
        )
    else:
        print(
            "[ШАБЛОНЫ] Шаблон по почтам не определён. Выберите или введите свой:",
            file=output_stream,
        )

    for index, candidate in enumerate(selectable, start=1):
        if candidate.source == "configured":
            detail = "базовый вариант"
        else:
            detail = f"совпадений: {candidate.matched_count}"
        examples = f"; пример: {candidate.examples[0]}" if candidate.examples else ""
        print(f"  {index}. {candidate.pattern} — {detail}{examples}", file=output_stream)

    if not input_stream.isatty():
        return defaults

    default_label = defaults[0] if len(defaults) == 1 else (
        "шаблоны по почтам" if candidates else "все базовые варианты"
    )
    if not defaults:
        default_label = "оставить текущие шаблоны"
    return _prompt_for_pattern_selection(
        f"Номера или шаблоны через запятую (Enter — {default_label}; ? — справка):",
        selectable, defaults, mask_templates, input_stream, output_stream,
    )


def choose_generation_masks(
    config: AppConfig,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> AppConfig:
    current_patterns = config.patterns.person
    mask_templates = config.generation.masks
    print("[МАСКИ] Текущие шаблоны:", file=output_stream)
    for index, pattern in enumerate(current_patterns, start=1):
        print(f"  {index}. {pattern}", file=output_stream)

    if not input_stream.isatty():
        return config

    if mask_templates:
        print("Сохранённые маски:", file=output_stream)
        for index, pattern in enumerate(mask_templates, start=1):
            print(f"  {index}. {pattern}", file=output_stream)

    prompt = "Номера масок или свои шаблоны (Enter — оставить текущие; ? — справка):"
    while True:
        print(prompt, file=output_stream, flush=True)
        raw = input_stream.readline()
        if raw == "":
            return config
        if raw.strip() == "?":
            print(MASK_BLOCKS_TEXT, file=output_stream)
            continue
        selected = _parse_generation_mask_selection(raw.strip(), mask_templates, current_patterns, output_stream)
        if selected is None:
            continue
        if selected == current_patterns:
            return config
        custom_charsets = _prompt_for_missing_custom_charsets(
            selected,
            dict(config.generation.custom_charsets),
            input_stream,
            output_stream,
        )
        if custom_charsets is None:
            continue
        return replace(
            config,
            generation=replace(config.generation, custom_charsets=custom_charsets),
            patterns=PatternsConfig(
                person=selected,
                technical=config.patterns.technical,
            ),
        )


def ensure_generation_custom_charsets(
    config: AppConfig,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> AppConfig:
    if not input_stream.isatty():
        return config
    custom_charsets = _prompt_for_missing_custom_charsets(
        config.patterns.person,
        dict(config.generation.custom_charsets),
        input_stream,
        output_stream,
    )
    if custom_charsets is None:
        return config
    if custom_charsets == config.generation.custom_charsets:
        return config
    return replace(config, generation=replace(config.generation, custom_charsets=custom_charsets))


def choose_candidate_formats(
    config: AppConfig,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stderr,
) -> AppConfig:
    current_formats = config.generation.candidate_formats
    templates = config.generation.candidate_format_templates or ("{login}", "{mail}")
    kind_labels = {"login": "логины", "email": "почты", "both": "логины и почты"}
    current_label = ", ".join(current_formats) or kind_labels.get(config.output.kind, config.output.kind)

    if not input_stream.isatty():
        print(f"[ФОРМАТ] {current_label}", file=output_stream)
        return config

    print("[ФОРМАТ] Что сохранить:", file=output_stream)
    format_labels = {"{login}": "логин", "{mail}": "почта", "{email}": "почта"}
    for index, candidate_format in enumerate(templates, start=1):
        label = format_labels.get(candidate_format, "свой формат")
        print(f"  {index}. {label} — {candidate_format}", file=output_stream)
    prompt = f"Выберите номера или введите свой шаблон результата (Enter — {current_label}; ? — справка):"
    while True:
        print(prompt, file=output_stream, flush=True)
        raw = input_stream.readline()
        if raw == "":
            return config
        if raw.strip() == "?":
            print(CANDIDATE_FORMAT_BLOCKS_TEXT, file=output_stream)
            continue
        selected = _parse_candidate_format_selection(raw.strip(), templates, current_formats, output_stream)
        if selected is None:
            continue
        if selected == current_formats:
            return config
        generation = _prompt_for_candidate_format_values(selected, config, input_stream, output_stream)
        if generation is None:
            continue
        return replace(config, generation=replace(generation, candidate_formats=selected))


def _prompt_for_pattern_selection(
    prompt: str,
    candidates: tuple[PatternInference, ...],
    default_patterns: tuple[str, ...],
    mask_templates: tuple[str, ...],
    input_stream: TextIO,
    output_stream: TextIO,
) -> tuple[str, ...]:
    print("Пример: {f}.{lastname} → i.ivanov (Иван Иванов).", file=output_stream)
    if mask_templates:
        print("Сохранённые маски:", file=output_stream)
        for index, pattern in enumerate(mask_templates, start=1):
            print(f"  m{index}. {pattern}", file=output_stream)
    while True:
        print(prompt, file=output_stream, flush=True)
        raw = input_stream.readline()
        if raw == "":
            return default_patterns
        if raw.strip() == "?":
            print(PERSON_PATTERN_BLOCKS_TEXT, file=output_stream)
            print(MASK_BLOCKS_TEXT, file=output_stream)
            continue
        selected = _parse_pattern_selection(raw.strip(), candidates, default_patterns, mask_templates, output_stream)
        if selected is not None:
            return selected


def _parse_pattern_selection(
    raw: str,
    candidates: tuple[PatternInference, ...],
    default_patterns: tuple[str, ...],
    mask_templates: tuple[str, ...],
    output_stream: TextIO,
) -> tuple[str, ...] | None:
    command = raw.lower()
    if not raw or command in {"all", "*", "0"}:
        return default_patterns

    selected: list[str] = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdecimal():
            index = int(part)
            if not candidates:
                print("[ШАБЛОНЫ] Вариантов с номерами нет; введите свой шаблон.", file=output_stream)
                return None
            if not 1 <= index <= len(candidates):
                print(f"[ШАБЛОНЫ] Номера {index} нет в списке.", file=output_stream)
                return None
            pattern = candidates[index - 1].pattern
        elif part.lower().startswith("m") and part[1:].isdecimal():
            index = int(part[1:])
            if not 1 <= index <= len(mask_templates):
                print(f"[ШАБЛОНЫ] Маски {part!r} нет в списке.", file=output_stream)
                return None
            pattern = mask_templates[index - 1]
            error = _person_pattern_error(pattern) or _mask_pattern_error(pattern)
            if error:
                print(f"[ШАБЛОНЫ] Ошибка в маске {part!r}: {error}", file=output_stream)
                return None
        else:
            error = _person_pattern_error(part) or _mask_pattern_error(part)
            if error:
                print(f"[ШАБЛОНЫ] Ошибка в шаблоне {part!r}: {error}", file=output_stream)
                return None
            pattern = part
        if pattern not in selected:
            selected.append(pattern)

    return tuple(selected) if selected else default_patterns


def _parse_generation_mask_selection(
    raw: str,
    mask_templates: tuple[str, ...],
    current_patterns: tuple[str, ...],
    output_stream: TextIO,
) -> tuple[str, ...] | None:
    command = raw.lower()
    if not raw or command in {"keep", "current", "default"}:
        return current_patterns

    selected: list[str] = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdecimal():
            index = int(part)
            if not 1 <= index <= len(mask_templates):
                print(f"[МАСКИ] Номера {index} нет в списке.", file=output_stream)
                return None
            pattern = mask_templates[index - 1]
        else:
            pattern = part

        error = _person_pattern_error(pattern) or _mask_pattern_error(pattern)
        if error:
            print(f"[МАСКИ] Ошибка в шаблоне {pattern!r}: {error}", file=output_stream)
            return None
        if pattern not in selected:
            selected.append(pattern)

    return tuple(selected) if selected else current_patterns


def _parse_candidate_format_selection(
    raw: str,
    templates: tuple[str, ...],
    current_formats: tuple[str, ...],
    output_stream: TextIO,
) -> tuple[str, ...] | None:
    command = raw.lower()
    if not raw or command in {"keep", "current", "default"}:
        return current_formats

    selected: list[str] = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdecimal():
            index = int(part)
            if not 1 <= index <= len(templates):
                print(f"[ФОРМАТ] Номера {index} нет в списке.", file=output_stream)
                return None
            candidate_format = templates[index - 1]
        else:
            candidate_format = part

        error = _candidate_format_error(candidate_format)
        if error:
            print(f"[ФОРМАТ] Ошибка в формате {candidate_format!r}: {error}", file=output_stream)
            return None
        if candidate_format not in selected:
            selected.append(candidate_format)

    return tuple(selected) if selected else current_formats


def _candidate_format_error(candidate_format: str) -> str | None:
    if not candidate_format:
        return "формат пуст"
    tokens = pattern_tokens(candidate_format)
    if error := _template_braces_error(candidate_format, tokens):
        return error
    if not tokens:
        return "добавьте переменную, например {login} или {mail}"
    unknown = tuple(token for token in tokens if token not in CANDIDATE_FORMAT_TOKENS)
    if unknown:
        return f"неизвестная переменная {{{unknown[0]}}}; введите ? для справки"
    return None


def _prompt_for_candidate_format_values(
    candidate_formats: tuple[str, ...],
    config: AppConfig,
    input_stream: TextIO,
    output_stream: TextIO,
):
    tokens = set()
    for candidate_format in candidate_formats:
        tokens.update(pattern_tokens(candidate_format))

    generation = config.generation
    if "ad_domain" in tokens and not generation.ad_domain:
        print("Домен AD для {ad_domain}, например corp.example.ru или example.local:", file=output_stream)
        raw = input_stream.readline()
        if raw == "":
            return None
        ad_domain = _normalize_domain_arg(raw.strip())
        if not ad_domain:
            print("[ФОРМАТ] Домен AD не указан.", file=output_stream)
            return None
        generation = replace(generation, ad_domain=ad_domain)

    if "netbios" in tokens and not generation.netbios:
        default_netbios = _default_netbios(config)
        if default_netbios:
            print(f"Имя домена NetBIOS для {{netbios}} (Enter — {default_netbios}):", file=output_stream)
        else:
            print("Имя домена NetBIOS для {netbios}, например EXAMPLE:", file=output_stream)
        raw = input_stream.readline()
        if raw == "":
            return None
        netbios = raw.strip().upper() or default_netbios
        if not netbios:
            print("[ФОРМАТ] Имя домена NetBIOS не указано.", file=output_stream)
            return None
        generation = replace(generation, netbios=netbios)

    return generation


def _default_netbios(config: AppConfig) -> str:
    company = config.company.strip() or _company_from_domain(config.domains[0] if config.domains else "")
    safe = "".join(char for char in company.upper() if char.isalnum())
    return safe[:15]


def _mask_pattern_error(pattern: str) -> str | None:
    unknown = unknown_mask_tokens(pattern)
    if unknown:
        return f"неизвестная маска ?{unknown[0]}; введите ? для справки"
    return None


def _prompt_for_missing_custom_charsets(
    patterns: tuple[str, ...],
    custom_charsets: dict[str, str],
    input_stream: TextIO,
    output_stream: TextIO,
) -> dict[str, str] | None:
    missing = tuple(token for token in required_custom_charsets(patterns) if not custom_charsets.get(token))
    for token in missing:
        print(f"Символы для собственного набора ?{token}:", file=output_stream)
        raw = input_stream.readline()
        if raw == "":
            return None
        value = raw.rstrip("\r\n")
        if not value:
            print(f"[МАСКИ] Набор ?{token} пуст.", file=output_stream)
            return None
        custom_charsets[token] = value
    return custom_charsets


def _person_pattern_error(pattern: str) -> str | None:
    if not pattern:
        return "шаблон пуст"
    if "@" in pattern:
        return "укажите часть до @; почтовый домен выбирается отдельно"
    tokens = pattern_tokens(pattern)
    if error := _template_braces_error(pattern, tokens):
        return error
    if not tokens:
        return "добавьте переменную, например {f2}.{lastname}"
    unknown = tuple(token for token in tokens if token not in PERSON_PATTERN_TOKENS)
    if unknown:
        return f"неизвестная переменная {{{unknown[0]}}}; введите ? для справки"
    return None


def _template_braces_error(value: str, tokens: tuple[str, ...]) -> str | None:
    for token in tokens:
        value = value.replace("{" + token + "}", "")
    if "{" in value or "}" in value:
        return "незакрытая или лишняя фигурная скобка"
    return None


def _print_domain_candidate(index: int, candidate: DomainInference, output_stream: TextIO) -> None:
    print(
        f"  {index}. {candidate.domain} — почт: {candidate.matched_count}",
        file=output_stream,
    )
    for email in candidate.examples:
        print(f"     - {email}", file=output_stream)


def _select_email_domains(
    configured_domains: tuple[str, ...],
    candidates: tuple[DomainInference, ...],
    domain_selector: Callable[[tuple[DomainInference, ...]], tuple[str, ...]] | None,
) -> tuple[str, ...]:
    if configured_domains:
        return configured_domains
    if not candidates:
        return ()
    selected = domain_selector(candidates) if domain_selector else tuple(candidate.domain for candidate in candidates)
    return _merge_values(selected)


def _infer_email_domain_candidates(emails: tuple[str, ...], source: str) -> tuple[DomainInference, ...]:
    examples_by_domain: dict[str, list[str]] = {}
    for email in emails:
        domain = _email_domain(email)
        if not domain or not _is_probable_email_domain(domain):
            continue
        examples_by_domain.setdefault(domain, [])
        if email not in examples_by_domain[domain]:
            examples_by_domain[domain].append(email)

    return tuple(
        DomainInference(
            domain=domain,
            matched_count=len(examples),
            examples=tuple(examples),
            source=source,
        )
        for domain, examples in sorted(
            examples_by_domain.items(),
            key=lambda item: (-len(item[1]), _domain_depth(item[0]), item[0]),
        )
    )


def _email_domain(email: str) -> str:
    if "@" not in email:
        return ""
    return _normalize_domain_arg(email.rsplit("@", 1)[1])


def _is_probable_email_domain(domain: str) -> bool:
    if "." not in domain:
        return False
    labels = domain.split(".")
    if any(not label for label in labels):
        return False
    suffix = labels[-1]
    if suffix in {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar"}:
        return False
    return suffix.isalpha() and 2 <= len(suffix) <= 24


def _domain_depth(domain: str) -> int:
    return domain.count(".")


def _write_lines(path: Path | None, lines: tuple[str, ...]) -> None:
    if path is None:
        return
    _write_text_atomic(path, "\n".join(lines) + ("\n" if lines else ""))


def _write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=f".{path.name}.",
            suffix=".tmp", dir=path.parent, delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(value)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_people(path: Path | None, people: tuple[Person, ...]) -> None:
    lines: list[str] = []
    for person in people:
        line = " ".join(part for part in (person.lastname, person.firstname, person.patronymic) if part).strip()
        if line and line not in lines:
            lines.append(line)
    _write_lines(path, tuple(lines))


def _write_email_sources(path: Path | None, sources: tuple[EmailSourceRecord, ...]) -> None:
    if path is None:
        return
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=("email", "source_type", "engine", "query", "url", "query_url", "file"),
    )
    writer.writeheader()
    for source in sources:
        writer.writerow(
            {
                "email": source.email,
                "source_type": source.source_type,
                "engine": source.engine,
                "query": source.query,
                "url": source.found_url or source.url,
                "query_url": source.query_url,
                "file": source.source_path,
            }
        )
    _write_text_atomic(path, buffer.getvalue())


def _write_evidence(path: Path | None, collection: CollectionResult) -> None:
    """Keep source claims separate from generated login candidates."""
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    collected_at = datetime.now(timezone.utc).isoformat()
    fingerprints: dict[Path, str] = {}

    def proof(source_path: str) -> tuple[str, str]:
        if not source_path:
            return "not_saved", ""
        artifact = Path(source_path)
        if not artifact.is_file():
            return "missing", ""
        if artifact not in fingerprints:
            digest = hashlib.sha256()
            with artifact.open("rb") as source_file:
                for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
                    digest.update(chunk)
            fingerprints[artifact] = digest.hexdigest()
        return "saved", fingerprints[artifact]

    records: list[dict[str, str]] = []
    for source in collection.person_sources:
        status, digest = proof(source.source_path)
        full_name = " ".join(
            part for part in (source.person.lastname, source.person.firstname, source.person.patronymic) if part
        )
        records.append({
            "kind": "person", "value": full_name, "source_type": source.source_type,
            "source_url": source.url, "query_url": source.query_url,
            "artifact_path": source.source_path, "proof_status": status,
            "sha256": digest, "collected_at": collected_at,
        })
    for source in collection.email_sources:
        status, digest = proof(source.source_path)
        records.append({
            "kind": "email", "value": source.email, "source_type": source.source_type,
            "source_url": source.query_url if source.source_type == "search" else (source.found_url or source.url),
            "linked_url": source.found_url if source.source_type == "search" else "",
            "query_url": source.query_url, "artifact_path": source.source_path,
            "proof_status": status, "sha256": digest, "collected_at": collected_at,
        })
    sourced_people = {record["value"].casefold() for record in records if record["kind"] == "person"}
    sourced_emails = {record["value"].casefold() for record in records if record["kind"] == "email"}
    for person in collection.people:
        full_name = " ".join(part for part in (person.lastname, person.firstname, person.patronymic) if part)
        if full_name.casefold() not in sourced_people:
            records.append({"kind": "person", "value": full_name, "source_type": "unknown",
                            "proof_status": "not_saved", "collected_at": collected_at})
    for email in collection.emails:
        if email.casefold() not in sourced_emails:
            records.append({"kind": "email", "value": email, "source_type": "unknown",
                            "proof_status": "not_saved", "collected_at": collected_at})
    _write_text_atomic(
        path,
        "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
    )
    write_evidence_tables(path, records)


def _artifact_directory_base(config: AppConfig) -> str:
    domain_source = config.domains[0] if config.domains else ""
    if not config.auto.url and domain_source == "example.ru" and not _is_placeholder_company(config.company):
        domain_source = ""
    source = config.auto.url or domain_source or config.company or "run"
    if config.auto.url:
        parsed = urllib.parse.urlparse(normalize_url(config.auto.url))
        host = parsed.hostname or parsed.netloc or source
        source = host
    safe = re.sub(r"[^\w._-]+", "-", source.strip().lower(), flags=re.UNICODE).strip("-")
    safe = safe.strip(".")
    return safe[:120] or "run"


def _is_placeholder_company(company: str) -> bool:
    return not company.strip() or company.strip().lower() == "example"


def _company_from_domain(domain: str) -> str:
    labels = [label for label in _normalize_domain_arg(domain).split(".") if label]
    if labels and labels[0] == "www":
        labels = labels[1:]
    if len(labels) > 1:
        labels = labels[:-1]
    return ".".join(labels)


class AutoLogger:
    def __init__(self, path: Path | None) -> None:
        self._path = path
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text("", encoding="utf-8")

    def __call__(self, message: str) -> None:
        line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
        if self._path:
            with self._path.open("a", encoding="utf-8") as file:
                file.write(line + "\n")
        console_line = _format_auto_console_message(message)
        if console_line:
            print(console_line, file=sys.stderr, flush=True)


def _format_auto_console_message(message: str) -> str | None:
    """Keep the terminal readable while the file log retains every detail."""

    if message.startswith("сбор с сайта начат;"):
        return "[САЙТ] Обход начат; " + message.removeprefix("сбор с сайта начат; ")
    match = re.match(r"fetch depth=(\d+):\s+(.+)", message)
    if match:
        return f"[САЙТ] Страница, глубина {match.group(1)}: {match.group(2)}"
    if message.startswith("site crawl skipped:"):
        reasons = {
            "site is not selected as a collection source": "сбор с сайта не выбран",
            "auto.url is empty": "URL сайта для сбора не задан",
        }
        reason = message.partition(":")[2].strip()
        return f"[САЙТ] Обход отключён: {reasons.get(reason, reason)}"
    if message.startswith("robots.txt disallowed:"):
        return "[САЙТ] Запрещено robots.txt: " + message.partition(":")[2].strip()
    if message.startswith("search queries built:"):
        return "[ПОИСК] Подготовлено запросов: " + message.partition(":")[2].strip()
    match = re.match(r"(yandex|google) fetch (\d+)/(\d+):", message, re.IGNORECASE)
    if match:
        return f"[ПОИСК] {match.group(1).title()}: запрос {match.group(2)}/{match.group(3)}"
    match = re.match(r"(?:pdf|document) fetch (\d+)/(\d+):\s+(.+)", message)
    if match:
        host = urllib.parse.urlsplit(match.group(3)).hostname or "документ"
        return f"[ДОКУМЕНТЫ] Документ {match.group(1)}/{match.group(2)}: {host}"
    if message.startswith("setka search started:"):
        return "[SETKA] Поиск сотрудников начат"
    match = re.match(r"setka request delay: ([\d.]+) seconds", message)
    if match:
        return f"[SETKA] Скорость: не чаще одного открытия страницы за {match.group(1)} с"
    match = re.match(r"setka search results parsed: company_pages=(\d+)", message)
    if match:
        return f"[SETKA] Поиск завершён; найдено страниц компаний: {match.group(1)}"
    match = re.match(r"setka company groups page: url=(\S+)", message)
    if match:
        return f"[SETKA] Страница со всеми группами: {match.group(1)}"
    match = re.match(r"setka networks parsed: .* networks=(\d+)", message)
    if match:
        return f"[SETKA] Найдено разделов: {match.group(1)}; проверяю страницы сотрудников"
    if message.startswith("setka rate limited:"):
        return "[SETKA] HTTP 429: обход остановлен; уже найденные ФИО будут сохранены"
    match = re.match(r"setka listing page limit reached: (\d+)", message)
    if match:
        return f"[SETKA] Лимит страниц списка групп достигнут: {match.group(1)}"
    match = re.match(r"setka member page limit reached: (\d+)", message)
    if match:
        return f"[SETKA] Лимит страниц участников достигнут: {match.group(1)}"
    match = re.match(r"setka members parsed: index=(\d+)/(\d+) .* people=(\d+)", message)
    if match:
        current, total = int(match.group(1)), int(match.group(2))
        if current == 1 or current % 5 == 0 or current == total:
            return f"[SETKA] Раздел {current}/{total}; ФИО на странице: {match.group(3)}"
    match = re.match(
        r"setka search finished; pages=(\d+), people=(\d+), skipped=(\d+)",
        message,
    )
    if match:
        return (
            f"[SETKA] Завершено: страниц {match.group(1)}, "
            f"ФИО {match.group(2)}, пропущено {match.group(3)}"
        )
    if message.startswith("vedomosti search started:"):
        return "[ВЕДОМОСТИ] Поиск спикеров начат"
    match = re.match(
        r"vedomosti search finished; pages=(\d+), people=(\d+), skipped=(\d+)",
        message,
    )
    if match:
        return (
            f"[ВЕДОМОСТИ] Завершено: страниц {match.group(1)}, "
            f"ФИО {match.group(2)}, пропущено {match.group(3)}"
        )
    if "HTTP 429" in message or "captcha" in message.casefold():
        return f"[ПРЕДУПРЕЖДЕНИЕ] {message}"
    return None


def _append_auto_log(path: Path | None, message: str) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
    with path.open("a", encoding="utf-8") as file:
        file.write(line + "\n")


def _merge_people(first: tuple[Person, ...], second: tuple[Person, ...]) -> tuple[Person, ...]:
    merged: list[Person] = []
    seen: set[tuple[str, str, str]] = set()
    for person in (*first, *second):
        key = _person_key(person)
        if person.firstname and person.lastname and key not in seen:
            merged.append(person)
            seen.add(key)
    return tuple(merged)


def _person_key(person: Person) -> tuple[str, str, str]:
    return (person.firstname.lower(), person.lastname.lower(), person.patronymic.lower())


def _merge_collection_results(collections: tuple[CollectionResult, ...]) -> CollectionResult:
    people: list[Person] = []
    emails: list[str] = []
    email_sources: list[EmailSourceRecord] = []
    person_sources: list[PersonSourceRecord] = []
    domains: list[str] = []
    visited_urls: list[str] = []
    skipped_urls: list[str] = []
    warnings: list[str] = []

    for collection in collections:
        for person in collection.people:
            if _person_key(person) not in {_person_key(item) for item in people}:
                people.append(person)
        for value, target in (
            (collection.emails, emails),
            (collection.email_sources, email_sources),
            (collection.person_sources, person_sources),
            (collection.domains, domains),
            (collection.visited_urls, visited_urls),
            (collection.skipped_urls, skipped_urls),
            (collection.warnings, warnings),
        ):
            for item in value:
                if item not in target:
                    target.append(item)

    return CollectionResult(
        people=tuple(people),
        emails=tuple(emails),
        email_sources=tuple(email_sources),
        person_sources=tuple(person_sources),
        domains=tuple(domains),
        visited_urls=tuple(visited_urls),
        skipped_urls=tuple(skipped_urls),
        warnings=tuple(warnings),
    )


def _merge_values(*groups: tuple[str, ...] | str) -> tuple[str, ...]:
    merged: list[str] = []
    for group in groups:
        values = (group,) if isinstance(group, str) else group
        for value in values:
            normalized = _normalize_domain_arg(value)
            if normalized and normalized not in merged:
                merged.append(normalized)
    return tuple(merged)


def _effective_configured_domains(domains: tuple[str, ...], url_domain: str) -> tuple[str, ...]:
    if domains == ("example.ru",) and url_domain and url_domain != "example.ru":
        return ()
    return domains


def _prepend_unique(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for value in (*first, *second):
        if value not in result:
            result.append(value)
    return tuple(result)


def _domain_from_url(url: str) -> str:
    if not url:
        return ""
    normalized = normalize_url(url)
    from urllib.parse import urlparse

    host = (urlparse(normalized).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _normalize_domain_arg(value: str) -> str:
    value = value.strip().lower()
    value = value.removeprefix("http://").removeprefix("https://")
    value = value.split("/", 1)[0]
    return value.lstrip("@")


def _parse_collection_sources(
    values: list[str] | None,
    choices: tuple[str, ...],
    option: str,
) -> list[str] | None:
    if values is None:
        return None
    selected: list[str] = []
    for raw in values:
        for item in raw.split(","):
            value = item.strip().lower()
            if not value:
                raise ValueError(f"{option}: пустое значение в списке {raw!r}")
            if value not in choices:
                raise ValueError(f"{option}: неизвестное значение {value!r}; допустимо: {', '.join(choices)}")
            if value not in selected:
                selected.append(value)
    return selected


def _parse_search_engine_args(values) -> tuple[str, ...]:
    engines: list[str] = []
    supported = {"yandex", "google"}
    for value in _flatten_search_engine_args(values):
        for part in value.replace(";", ",").split(","):
            engine = part.strip().lower()
            if not engine:
                continue
            if engine not in supported:
                supported_text = ", ".join(sorted(supported))
                raise ValueError(f"Unsupported search engine {engine!r}; supported: {supported_text}")
            if engine not in engines:
                engines.append(engine)
    return tuple(engines)


def _flatten_search_engine_args(values) -> tuple[str, ...]:
    flattened: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple)):
            flattened.extend(_flatten_search_engine_args(value))
        else:
            flattened.append(str(value))
    return tuple(flattened)
