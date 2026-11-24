"""CLI collection modes and result retention for the standalone login tool."""
from __future__ import annotations

from dataclasses import replace
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

from .documents import SUPPORTED_DOCUMENT_TYPES
from .models import AppConfig


def prepare_collection_args(args: Namespace, parser: ArgumentParser) -> None:
    if args.config or args.init_config or args.show_variables:
        return
    generation = bool(args.generate or args.kind or args.person_pattern or args.technical_pattern
                      or args.technical_words or args.prompt_inferred_patterns or args.dry_run)
    if args.generate and args.collect_only:
        parser.error("-g и --collect-only несовместимы")
    if args.url:
        urls = read_targets(args.url)
        urls.extend(normalize_target(value) for value in args.extra_url or ())
        urls = list(dict.fromkeys(urls))
        args.url, args.extra_url = urls[0], urls[1:]
        if not args.allowed_domain:
            args.allowed_domain = list(dict.fromkeys(urlsplit(url).hostname for url in urls))
    explicit_sources = args.email_source is not None or args.people_source is not None
    source_flags = bool(args.search_engine or args.setka or args.vedomosti)
    collection = bool(args.url or args.auto or args.collect_only or explicit_sources or source_flags
                      or (args.domain and args.company))
    if not collection:
        if generation:
            return
        parser.error("для пассивного сбора укажите --domain ДОМЕН --company НАЗВАНИЕ; "
                     "для активного — -u URL|FILE")
    if not args.url and not explicit_sources and not source_flags and not (args.domain and args.company):
        parser.error("пассивному сбору нужны --domain ДОМЕН и --company НАЗВАНИЕ")
    if not explicit_sources:
        emails, people = [], []
        passive_defaults = not args.url and bool(args.domain and args.company)
        if args.url:
            emails.append("site")
            people.append("site")
        if args.search_engine or passive_defaults:
            emails.append("search")
            people.append("search")
        if args.setka or passive_defaults:
            people.append("setka")
        if args.vedomosti:
            people.append("vedomosti")
        args.email_source, args.people_source = emails, people
    selected = {part.strip() for value in (*(args.email_source or ()), *(args.people_source or ()))
                for part in value.split(",")}
    if "search" in selected and not args.search_engine:
        args.search_engine = [["yandex", "google"]]
    args.auto = True
    args.collect_only = args.collect_only or not generation
    args.no_default_people = True
    if args.generate and not args.no_pattern_prompt:
        args.prompt_inferred_patterns = True


def normalize_target(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    try:
        parsed.port  # Validate the port before any network operation.
    except ValueError as error:
        raise ValueError(f"неверный адрес: {value}") from error
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or any(c.isspace() for c in value)):
        raise ValueError(f"нужен HTTP(S) URL, домен или IP: {value}")
    return value


def read_targets(value: str) -> list[str]:
    if value.startswith(("http://", "https://")):
        return [normalize_target(value)]
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValueError(f"файл адресов не найден: {path}; для одного сайта укажите полный HTTP(S) URL")
    values = []
    for index, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            values.append(normalize_target(line))
        except ValueError as error:
            raise ValueError(f"{path}, строка {index}: {error}") from error
    if not values:
        raise ValueError(f"файл адресов пуст: {path}")
    return list(dict.fromkeys(values))


def configure_collection(config: AppConfig, args: Namespace, temporary: Path) -> AppConfig:
    if args.config or not config.auto.enabled:
        return config
    if args.max_documents is not None and args.max_documents < 1:
        raise ValueError("--max-documents должен быть больше нуля")
    if args.katana_depth is not None and not 0 <= args.katana_depth <= 10:
        raise ValueError("--katana-depth должен быть от 0 до 10")
    if args.katana_depth is not None and args.max_depth is not None:
        raise ValueError("выберите один параметр глубины: --katana-depth или --max-depth")
    if args.max_pages is not None and args.max_pages < 1:
        raise ValueError("--max-pages должен быть больше нуля")
    types = config.auto.document_types
    if args.document_types:
        types = tuple(dict.fromkeys(part.strip().lower().lstrip(".")
                                   for value in args.document_types for part in value.split(",")))
        unknown = set(types) - set(SUPPORTED_DOCUMENT_TYPES)
        if unknown:
            raise ValueError("неподдерживаемые форматы документов: " + ", ".join(sorted(unknown)))
    root = (Path(args.output_dir).expanduser() if args.output_dir else
            Path(args.output).expanduser().parent if args.output else config.output.path.parent)
    root = root.resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"папка результатов указывает на файл: {root}")
    # Explicit diagnostic paths also request retained artifacts (legacy CLI/run).
    save = bool(args.save_artifacts or args.evidence_output not in (None, "none", "off", "null")
                or args.auto_log not in (None, "none", "off", "null")
                or args.browser_pages_dir or args.search_results_dir or args.pdf_files_dir)
    scratch = root if save else temporary
    def optional(value, default):
        if value and value.lower() in {"none", "off", "null"}:
            return None
        return Path(value).expanduser().resolve() if value else default
    auto = replace(
        config.auto, site_crawler="katana", katana_executable=args.katana_executable,
        save_artifacts=save,
        browser_crawl=bool(args.browser_crawl),
        request_delay_seconds=max(1.0 if config.auto.url else 0.0, config.auto.request_delay_seconds),
        max_depth=(max(args.katana_depth - 1, 0) if args.katana_depth is not None else config.auto.max_depth),
        pdf_max_files=args.max_documents or config.auto.pdf_max_files,
        document_types=types,
        fio_path=optional(args.people_output, root / "fio.txt"),
        found_emails_path=optional(args.emails_output or args.found_emails_output, root / "emails.txt"),
        mail_from_url_path=None,
        email_sources_path=root / "email_sources.csv" if save else None,
        evidence_path=optional(args.evidence_output, root / "evidence.jsonl") if save else None,
        log_path=optional(args.auto_log, root / "collection.log") if save else None,
        browser_pages_dir=Path(args.browser_pages_dir) if args.browser_pages_dir else scratch / "source-pages",
        search_results_dir=Path(args.search_results_dir) if args.search_results_dir else scratch / "search-results",
        pdf_files_dir=Path(args.pdf_files_dir) if args.pdf_files_dir else scratch / "documents",
        browser_user_data_dir=(Path(args.browser_user_data_dir) if args.browser_user_data_dir else
                               scratch / "browser-profile" if save else None),
    )
    output = replace(config.output, path=Path(args.output).expanduser().resolve() if args.output else root / "logins.txt")
    return replace(config, auto=auto, output=output)


def print_collection_plan(config: AppConfig, args: Namespace, stream: TextIO) -> None:
    mode = "активный" if config.auto.url else "пассивный"
    print(f"[ПЛАН] Сбор: {mode}", file=stream)
    if config.auto.url:
        print(f"[ПЛАН] Katana: адресов {1 + len(config.auto.extra_urls)}, "
              f"глубина {config.auto.max_depth + 1}, максимум {config.auto.max_pages} страниц; "
              "одновременно 1 запрос", file=stream)
    selected = set(args.email_source or ()) | set(args.people_source or ())
    print("[ПЛАН] Источники: " + ", ".join(sorted(selected)), file=stream)
    if config.auto.search_enabled:
        print("[ПЛАН] Поисковики: " + ", ".join(config.auto.search_engines)
              + f"; пауза между запросами {max(config.auto.request_delay_seconds, config.auto.search_delay_seconds):g} с",
              file=stream)
    print("[ПЛАН] Документы: " + (", ".join(config.auto.document_types)
          + f"; максимум {config.auto.pdf_max_files}" if config.auto.pdf_enabled else "отключены"), file=stream)
    print(f"[ПЛАН] Генерация: {'отключена' if args.collect_only else 'включена'}; "
          f"подробные файлы: {'сохраняются' if config.auto.save_artifacts else 'не сохраняются'}", file=stream)
    print(f"[ПЛАН] Результаты: {config.output.path.parent}", file=stream)
