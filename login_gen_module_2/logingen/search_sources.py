from __future__ import annotations

import json
import os
import re
import tempfile
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from zipfile import BadZipFile

from .collector import CollectionResult, EmailSourceRecord, PersonSourceRecord, extract_people, extract_standalone_people
from .defaults import DEFAULT_SEARCH_DORKS
from .models import AutoConfig, Person
from .documents import MAX_DOCUMENT_BYTES, detect_document_type, document_type, extract_document_text
from .playwright_fetcher import (
    FetchBinaryResponse,
    FetchResponse,
    PlaywrightFetchError,
    PlaywrightFetchTimeoutError,
    PlaywrightFetchTransport,
    PlaywrightUnavailableError,
)


YANDEX_SEARCH_BASE = "https://yandex.ru/search/"
GOOGLE_SEARCH_BASE = "https://www.google.com/search"
SUPPORTED_SEARCH_ENGINES = frozenset({"yandex", "google"})
SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
QUOTED_HTTP_URL_RE = re.compile(r'"(https?://[^"\s]+)"', re.IGNORECASE)
HTML_ENTITY_RE = re.compile(r"&(?:[a-zA-Z]+|#[0-9]+|#x[0-9a-fA-F]+);")
LOOSE_EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+-])"
    r"([A-Z0-9]+(?:\s*[._%+-]\s*[A-Z0-9]+){0,20})"
    r"\s*@\s*"
    r"([A-Z0-9-]+(?:\s*\.\s*[A-Z0-9-]+)+)"
    r"(?![A-Z0-9._%+-])",
    re.IGNORECASE,
)
EMAIL_CANDIDATE_RE = re.compile(r"^[a-z0-9][a-z0-9._%+-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
FILE_EXTENSION_SUFFIXES = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar"}
SEARCH_NAV_HOST_SUFFIXES = (
    "yandex.ru",
    "ya.ru",
    "yastatic.net",
    "yandex.net",
    "google.com",
    "google.ru",
    "gstatic.com",
    "googleusercontent.com",
    "googleapis.com",
)

SNIPPET_CLASSES = {
    "organic__text",
    "organic__content-wrapper",
    "serp-item__text",
    "serp-item__text-container",
    "text-container",
    "text-container__text",
    "OrganicText",
    "OrganicTextContentSpan",
}


@dataclass(frozen=True)
class SearchQuery:
    term: str
    domain: str
    query: str
    url: str
    engine: str = "yandex"


@dataclass(frozen=True)
class SearchEmailFinding:
    email: str
    source_path: Path
    engine: str = "yandex"
    query: str = ""
    query_url: str = ""
    found_url: str = ""


@dataclass(frozen=True)
class SearchResultEmail:
    email: str
    found_url: str = ""


@dataclass(frozen=True)
class _SearchTextChunk:
    text: str
    found_url: str = ""


@dataclass(frozen=True)
class SearchFetchRecord:
    query: SearchQuery
    path: Path
    status_code: int
    captcha_detected: bool = False


@dataclass(frozen=True)
class PdfSourceCandidate:
    url: str
    engine: str
    query: str
    query_url: str
    source_path: Path


@dataclass(frozen=True)
class PdfFetchRecord:
    source: PdfSourceCandidate
    path: Path
    status_code: int
    content_type: str = ""


@dataclass(frozen=True)
class SearchSourceResult:
    collection: CollectionResult
    queries: tuple[SearchQuery, ...] = field(default_factory=tuple)
    findings: tuple[SearchEmailFinding, ...] = field(default_factory=tuple)
    fetched: tuple[SearchFetchRecord, ...] = field(default_factory=tuple)
    pdfs: tuple[PdfFetchRecord, ...] = field(default_factory=tuple)


class _SnippetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.snippets: list[_SearchTextChunk] = []
        self.result_urls: list[str] = []
        self.visible_text_parts: list[str] = []
        self._capture_depth = 0
        self._snippet_parts: list[str] = []
        self._snippet_url = ""
        self._last_external_url = ""
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return
        attrs_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "a":
            found_url = _normalize_result_href(attrs_map.get("href", ""))
            if found_url:
                self._last_external_url = found_url
                if found_url not in self.result_urls:
                    self.result_urls.append(found_url)
        classes = set(attrs_map.get("class", "").split())
        if classes & SNIPPET_CLASSES:
            self._capture_depth += 1
            if self._capture_depth == 1:
                self._snippet_parts = []
                self._snippet_url = self._last_external_url
        elif self._capture_depth:
            self._capture_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if not self._capture_depth:
            return
        self._capture_depth -= 1
        if self._capture_depth == 0:
            snippet = _normalize_text_for_display(" ".join(self._snippet_parts))
            if snippet:
                self.snippets.append(_SearchTextChunk(snippet, self._snippet_url))
            self._snippet_parts = []
            self._snippet_url = ""

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.visible_text_parts.append(data)
        if self._capture_depth:
            self._snippet_parts.append(data)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.handle_data(f"&#{name};")

    @property
    def visible_text(self) -> str:
        return " ".join(self.visible_text_parts)


def collect_search_source(
    config: AutoConfig,
    domains: tuple[str, ...],
    company: str = "",
    log=None,
    fetcher: PlaywrightFetchTransport | None = None,
    on_progress: Callable[[CollectionResult], None] | None = None,
) -> SearchSourceResult:
    normalized_domains = tuple(_normalize_domain(domain) for domain in domains if _normalize_domain(domain))
    dorks = config.search_dorks or DEFAULT_SEARCH_DORKS
    if config.pdf_enabled and dorks == DEFAULT_SEARCH_DORKS:
        dorks = (*dorks, *(f'site:{{domain}} filetype:{kind}' for kind in config.document_types))
    queries = build_search_queries(
        normalized_domains,
        config.search_terms,
        dorks=dorks,
        engines=config.search_engines,
        company=company,
        site_url=config.url,
    )
    if log:
        log(f"search queries built: {_search_query_counts_text(queries)}")

    excluded_query_emails = _query_emails(queries)
    checkpoint_findings: list[SearchEmailFinding] = []

    def checkpoint_search_page(record: SearchFetchRecord) -> None:
        if record.status_code >= 400 or record.captcha_detected:
            return
        html = record.path.read_text(encoding="utf-8", errors="replace")
        previous_count = len(checkpoint_findings)
        for result_email in parse_search_result_email_findings(html, engine=record.query.engine):
            if result_email.email in excluded_query_emails:
                continue
            finding = SearchEmailFinding(
                email=result_email.email,
                source_path=record.path,
                engine=record.query.engine,
                query=record.query.query,
                query_url=record.query.url,
                found_url=result_email.found_url,
            )
            if finding not in checkpoint_findings:
                checkpoint_findings.append(finding)
        if on_progress and len(checkpoint_findings) > previous_count:
            on_progress(_search_checkpoint(tuple(checkpoint_findings)))

    fetched, fetch_warnings = (
        fetch_search_pages(
            queries, config, log=log, fetcher=fetcher,
            on_saved=checkpoint_search_page if on_progress else None,
        )
        if config.search_fetch_enabled
        else ((), ())
    )

    findings: list[SearchEmailFinding] = []
    pdf_candidates: list[PdfSourceCandidate] = []
    warnings: list[str] = list(fetch_warnings)

    for record in fetched:
        path = record.path
        if log:
            log(f"search parse local html: {path}")
        if not path.exists():
            warnings.append(f"Search result file not found: {path}")
            continue
        html = path.read_text(encoding="utf-8", errors="replace")
        for url in parse_search_result_links(html, engine=record.query.engine):
            if document_type(url) not in config.document_types:
                continue
            candidate = PdfSourceCandidate(
                url=url,
                engine=record.query.engine,
                query=record.query.query,
                query_url=record.query.url,
                source_path=path,
            )
            pdf_candidates.append(candidate)
        result_emails = parse_search_result_email_findings(html, engine=record.query.engine)
        for result_email in result_emails:
            email = result_email.email
            if email in excluded_query_emails:
                continue
            finding = SearchEmailFinding(
                email=email,
                source_path=path,
                engine=record.query.engine,
                query=record.query.query,
                query_url=record.query.url,
                found_url=result_email.found_url,
            )
            if finding not in findings:
                findings.append(finding)
        if log:
            log(f"search parsed: emails={len(result_emails)}")

    def checkpoint_pdf(pdf_partial: CollectionResult) -> None:
        if on_progress:
            search_partial = _search_checkpoint(tuple(findings))
            on_progress(CollectionResult(
                people=pdf_partial.people,
                person_sources=pdf_partial.person_sources,
                emails=tuple(dict.fromkeys((*search_partial.emails, *pdf_partial.emails))),
                email_sources=(*search_partial.email_sources, *pdf_partial.email_sources),
                domains=tuple(dict.fromkeys((*search_partial.domains, *pdf_partial.domains))),
            ))

    pdf_fetches, pdf_collection = collect_pdf_sources(
        tuple(pdf_candidates), config, log=log, fetcher=fetcher,
        on_progress=checkpoint_pdf if on_progress else None,
    )
    warnings.extend(pdf_collection.warnings)

    search_emails = tuple(dict.fromkeys(finding.email for finding in findings))
    emails = tuple(dict.fromkeys((*search_emails, *pdf_collection.emails)))
    if config.found_emails_path:
        _write_found_emails(config.found_emails_path, emails)
        if log:
            log(f"search emails written: {config.found_emails_path} ({len(emails)})")
    if config.found_emails_path and config.save_artifacts:
        output_dir = config.found_emails_path.parent
        for engine in _normalize_search_engines(config.search_engines):
            engine_emails = tuple(dict.fromkeys(finding.email for finding in findings if finding.engine == engine))
            engine_pdf_emails = tuple(
                dict.fromkeys(
                    source.email
                    for source in pdf_collection.email_sources
                    if source.engine == engine
                )
            )
            engine_emails = tuple(dict.fromkeys((*engine_emails, *engine_pdf_emails)))
            engine_path = output_dir / f"mail_from_{engine}.txt"
            _write_found_emails(engine_path, engine_emails)
            if log:
                log(f"{engine} emails written: {engine_path} ({len(engine_emails)})")
        pdf_emails = tuple(dict.fromkeys(source.email for source in pdf_collection.email_sources))
        pdf_path = output_dir / "mail_from_pdf.txt"
        _write_found_emails(pdf_path, pdf_emails)
        if log:
            log(f"pdf emails written: {pdf_path} ({len(pdf_emails)})")

    domains_from_emails = tuple(sorted({_email_domain(email) for email in emails if _email_domain(email)}))
    email_sources = tuple(
        EmailSourceRecord(
            email=finding.email,
            source_type="search",
            engine=finding.engine,
            query=finding.query,
            found_url=finding.found_url,
            query_url=finding.query_url,
            url=finding.found_url or finding.query_url,
            source_path=str(finding.source_path),
        )
        for finding in findings
    )
    return SearchSourceResult(
        collection=CollectionResult(
            people=pdf_collection.people,
            person_sources=pdf_collection.person_sources,
            emails=emails,
            email_sources=(*email_sources, *pdf_collection.email_sources),
            domains=domains_from_emails,
            warnings=tuple(warnings),
        ),
        queries=queries,
        findings=tuple(findings),
        fetched=fetched,
        pdfs=pdf_fetches,
    )


def _search_checkpoint(findings: tuple[SearchEmailFinding, ...]) -> CollectionResult:
    emails = tuple(dict.fromkeys(finding.email for finding in findings))
    sources = tuple(EmailSourceRecord(
        email=finding.email,
        source_type="search",
        engine=finding.engine,
        query=finding.query,
        found_url=finding.found_url,
        query_url=finding.query_url,
        url=finding.found_url or finding.query_url,
        source_path=str(finding.source_path),
    ) for finding in findings)
    return CollectionResult(
        emails=emails,
        email_sources=sources,
        domains=tuple(sorted({_email_domain(email) for email in emails if _email_domain(email)})),
    )


def fetch_search_pages(
    queries: tuple[SearchQuery, ...],
    config: AutoConfig,
    log=None,
    fetcher: PlaywrightFetchTransport | None = None,
    on_saved: Callable[[SearchFetchRecord], None] | None = None,
) -> tuple[tuple[SearchFetchRecord, ...], tuple[str, ...]]:
    config.search_results_dir.mkdir(parents=True, exist_ok=True)
    fetched: list[SearchFetchRecord] = []
    warnings: list[str] = []
    owned_fetcher: PlaywrightFetchTransport | None = None
    if fetcher is None:
        try:
            owned_fetcher = PlaywrightFetchTransport(config)
            fetcher = owned_fetcher
        except PlaywrightUnavailableError as error:
            warning = str(error)
            warnings.append(warning)
            if log:
                log(warning)
            return (), tuple(warnings)

    total = len(queries)
    captcha_blocked_engines: set[str] = set()
    try:
        for index, query in enumerate(queries, start=1):
            if query.engine in captcha_blocked_engines:
                if log:
                    log(f"{query.engine} skipped after captcha: {query.url}")
                continue
            path = _unique_destination(
                config.search_results_dir / query.engine,
                f"{index:03d}-{_safe_filename(query.term)}-{_safe_filename(query.domain)}.html",
            )
            if log:
                log(f"{query.engine} fetch {index}/{total}: {query.url}")
            try:
                response = _fetch_search_response(fetcher, query.url, query.engine)
            except PlaywrightFetchTimeoutError:
                warnings.append(f"Таймаут запроса к поисковику: {query.url}")
                continue
            except PlaywrightFetchError as error:
                warnings.append(f"Ошибка запроса к поисковику {query.url}: {error}")
                continue

            html = _search_response_html(response)
            captcha_detected = is_search_captcha_html(html, engine=query.engine)
            path.write_text(html, encoding="utf-8", errors="replace")
            record = SearchFetchRecord(
                query=query,
                path=path,
                status_code=response.status_code,
                captcha_detected=captcha_detected,
            )
            fetched.append(record)
            if log:
                log(f"search saved html: {path} status={response.status_code}")
            if on_saved:
                on_saved(record)
            if response.status_code == 429:
                warning = (
                    f"{query.engine.title()} вернул HTTP 429; "
                    "оставшиеся запросы к этому поисковику остановлены."
                )
                warnings.append(warning)
                if log:
                    log(warning)
                captcha_blocked_engines.add(query.engine)
                continue
            if captcha_detected:
                warning = (
                    f"{query.engine.title()}: вместо результатов получена CAPTCHA; "
                    + (f"страница сохранена: {path}" if config.save_artifacts
                       else "копия страницы не сохраняется без --save-artifacts")
                )
                warnings.append(warning)
                if log:
                    log(warning)
                captcha_blocked_engines.add(query.engine)
                continue

    finally:
        if owned_fetcher:
            owned_fetcher.close()

    return tuple(fetched), tuple(warnings)


def _fetch_search_response(fetcher: PlaywrightFetchTransport, url: str, engine: str) -> FetchResponse:
    captcha_detector = _captcha_detector_for_engine(engine)
    manual_session_fetch = getattr(fetcher, "fetch_rendered_html_in_manual_session", None)
    if callable(manual_session_fetch):
        return manual_session_fetch(url, captcha_detector)
    manual_captcha_fetch = getattr(fetcher, "fetch_rendered_html_with_manual_captcha", None)
    if callable(manual_captcha_fetch):
        return manual_captcha_fetch(url, captcha_detector)
    return fetcher.fetch_rendered_html(url)


def collect_pdf_sources(
    candidates: tuple[PdfSourceCandidate, ...],
    config: AutoConfig,
    log=None,
    fetcher: PlaywrightFetchTransport | None = None,
    on_progress: Callable[[CollectionResult], None] | None = None,
) -> tuple[tuple[PdfFetchRecord, ...], CollectionResult]:
    if not config.pdf_enabled or not candidates:
        return (), CollectionResult()

    first_candidate_by_url: dict[str, PdfSourceCandidate] = {}
    for candidate in candidates:
        first_candidate_by_url.setdefault(candidate.url, candidate)
    unique_candidates = tuple(first_candidate_by_url.values())
    limited_candidates = unique_candidates[: config.pdf_max_files]
    warnings: list[str] = []
    if len(unique_candidates) > len(limited_candidates):
        warnings.append(
            f"PDF result limit reached: {len(unique_candidates)} found, "
            f"only first {len(limited_candidates)} will be fetched."
        )

    emails: list[str] = []
    email_sources: list[EmailSourceRecord] = []
    people: list[Person] = []
    person_sources: list[PersonSourceRecord] = []

    def parse_saved_pdf(record: PdfFetchRecord) -> None:
        try:
            text = extract_document_text(record.path, pdf_extractor=extract_pdf_text)
        except ModuleNotFoundError:
            warnings.append("PDF parsing requires pdfminer.six. Install dependencies from requirements.txt.")
            return
        except Exception as error:
            warnings.append(f"Не удалось разобрать документ {record.source.url}: {error}")
            return

        pdf_emails = extract_loose_emails(text)
        pdf_people = extract_pdf_people(text)
        for email in pdf_emails:
            if email not in emails:
                emails.append(email)
            source = EmailSourceRecord(
                email=email,
                source_type=record.path.suffix.lstrip("."),
                engine=record.source.engine,
                query=record.source.query,
                found_url=record.source.url,
                query_url=record.source.query_url,
                url=record.source.url,
                source_path=str(record.path),
            )
            if source not in email_sources:
                email_sources.append(source)
        for person in pdf_people:
            person_sources.append(PersonSourceRecord(
                person, record.path.suffix.lstrip("."), record.source.url, str(record.path), record.source.query_url,
            ))
            key = (person.firstname.lower(), person.lastname.lower(), person.patronymic.lower())
            if key not in {
                (item.firstname.lower(), item.lastname.lower(), item.patronymic.lower())
                for item in people
            }:
                people.append(person)
        if log:
            log(f"pdf parsed: {record.path} emails={len(pdf_emails)}, people={len(pdf_people)}")
        if on_progress and (pdf_emails or pdf_people):
            on_progress(CollectionResult(
                people=tuple(people),
                emails=tuple(emails),
                email_sources=tuple(email_sources),
                person_sources=tuple(dict.fromkeys(person_sources)),
                domains=tuple(sorted({_email_domain(email) for email in emails if _email_domain(email)})),
            ))

    fetched, fetch_warnings = fetch_pdf_files(
        tuple(limited_candidates), config, log=log, fetcher=fetcher,
        on_saved=parse_saved_pdf,
    )
    warnings.extend(fetch_warnings)

    domains = tuple(sorted({_email_domain(email) for email in emails if _email_domain(email)}))
    return fetched, CollectionResult(
        people=tuple(people),
        emails=tuple(emails),
        email_sources=tuple(email_sources),
        person_sources=tuple(dict.fromkeys(person_sources)),
        domains=domains,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def extract_pdf_people(text: str) -> tuple[Person, ...]:
    # Keep PDF line boundaries so names from neighbouring columns or a
    # hyphenated line break are not joined into a fictitious person.
    return tuple(dict.fromkeys(
        person
        for line in text.splitlines()
        for person in (*extract_people(line), *extract_standalone_people(line))
    ))


def fetch_pdf_files(
    candidates: tuple[PdfSourceCandidate, ...],
    config: AutoConfig,
    log=None,
    fetcher: PlaywrightFetchTransport | None = None,
    on_saved: Callable[[PdfFetchRecord], None] | None = None,
) -> tuple[tuple[PdfFetchRecord, ...], tuple[str, ...]]:
    if not candidates:
        return (), ()

    config.pdf_files_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    fetched: list[PdfFetchRecord] = []
    owned_fetcher: PlaywrightFetchTransport | None = None
    if fetcher is None:
        try:
            owned_fetcher = PlaywrightFetchTransport(config)
            fetcher = owned_fetcher
        except PlaywrightUnavailableError as error:
            warning = str(error)
            warnings.append(warning)
            if log:
                log(warning)
            return (), tuple(warnings)

    fetch_bytes = getattr(fetcher, "fetch_bytes", None)
    if not callable(fetch_bytes):
        warnings.append("PDF fetching requires a fetcher with fetch_bytes support.")
        if owned_fetcher:
            owned_fetcher.close()
        return (), tuple(warnings)

    try:
        for index, candidate in enumerate(candidates, start=1):
            if log:
                log(f"document fetch {index}/{len(candidates)}: {candidate.url}")
            try:
                response: FetchBinaryResponse = fetch_bytes(
                    candidate.url,
                    timeout_seconds=config.timeout_seconds,
                    headers={"Accept": "*/*"},
                )
            except PlaywrightFetchTimeoutError:
                warnings.append(f"PDF fetch timed out for {candidate.url}")
                continue
            except PlaywrightFetchError as error:
                warnings.append(f"PDF fetch failed for {candidate.url}: {error}")
                continue

            if response.tls_warning:
                warnings.append(response.tls_warning)
                if log:
                    log(response.tls_warning)
            if response.status_code >= 400:
                warnings.append(f"HTTP {response.status_code} while fetching PDF {candidate.url}")
                continue
            if len(response.body) > MAX_DOCUMENT_BYTES:
                warnings.append(f"Документ больше 64 МиБ: {candidate.url}")
                continue
            try:
                kind = detect_document_type(candidate.url, response.body, response.content_type)
            except (ValueError, OSError, BadZipFile) as error:
                warnings.append(f"Повреждённый документ {candidate.url}: {error}")
                continue
            if kind not in config.document_types:
                warnings.append(f"Неподдерживаемый ответ документа {candidate.url}: {response.content_type or 'unknown'}")
                continue
            filename = str(Path(_pdf_filename(candidate.url, index)).with_suffix('.' + kind))
            path = _unique_destination(config.pdf_files_dir, filename)
            path.write_bytes(response.body)
            record = PdfFetchRecord(
                source=candidate,
                path=path,
                status_code=response.status_code,
                content_type=response.content_type,
            )
            fetched.append(record)
            if log:
                log(f"pdf saved: {path} status={response.status_code}")
            if on_saved:
                on_saved(record)
    finally:
        if owned_fetcher:
            owned_fetcher.close()

    return tuple(fetched), tuple(warnings)


def extract_pdf_text(path: Path) -> str:
    from pdfminer.high_level import extract_text  # type: ignore[import-not-found]

    return extract_text(str(path)) or ""


def build_search_queries(
    domains: Iterable[str],
    terms: Iterable[str] = (),
    dorks: Iterable[str] | None = None,
    engines: Iterable[str] = ("yandex",),
    company: str = "",
    site_url: str = "",
) -> tuple[SearchQuery, ...]:
    queries: list[SearchQuery] = []
    normalized_engines = _normalize_search_engines(tuple(engines))
    normalized_terms = tuple(_normalize_term(term) for term in terms if _normalize_term(term))
    templates = tuple(template.strip() for template in (dorks or DEFAULT_SEARCH_DORKS) if template.strip())
    seen: set[tuple[str, str]] = set()
    for domain in domains:
        normalized_domain = _normalize_domain(domain)
        if not normalized_domain:
            continue
        company_value = company.strip().lower() or _company_from_domain(normalized_domain)
        for template in templates:
            template_terms = normalized_terms if "{term}" in template else ("",)
            for normalized_term in template_terms:
                query = _render_dork(
                    template,
                    term=normalized_term,
                    domain=normalized_domain,
                    company=company_value,
                    site_url=site_url,
                )
                if not query:
                    continue
                for engine in normalized_engines:
                    key = (engine, query)
                    if key in seen:
                        continue
                    seen.add(key)
                    queries.append(
                        SearchQuery(
                            term=normalized_term,
                            domain=normalized_domain,
                            query=query,
                            url=build_search_url(engine, query),
                            engine=engine,
                        )
                    )
    return tuple(queries)


def _query_emails(queries: tuple[SearchQuery, ...]) -> frozenset[str]:
    emails: set[str] = set()
    for query in queries:
        if query.term and query.domain:
            emails.add(f"{query.term}@{query.domain}".lower())
        emails.update(extract_loose_emails(query.query))
    return frozenset(emails)


def build_search_url(engine: str, query: str) -> str:
    if engine == "yandex":
        return build_yandex_search_url(query)
    if engine == "google":
        return build_google_search_url(query)
    raise ValueError(f"Unsupported search engine: {engine}")


def build_yandex_search_url(query: str) -> str:
    return YANDEX_SEARCH_BASE + "?" + urllib.parse.urlencode({"text": query})


def build_google_search_url(query: str) -> str:
    return GOOGLE_SEARCH_BASE + "?" + urllib.parse.urlencode({"q": query})


def parse_search_result_emails(html: str, engine: str = "yandex") -> tuple[str, ...]:
    findings = parse_search_result_email_findings(html, engine=engine)
    emails: list[str] = []
    for finding in findings:
        if finding.email not in emails:
            emails.append(finding.email)
    return tuple(emails)


def parse_search_result_email_findings(html: str, engine: str = "yandex") -> tuple[SearchResultEmail, ...]:
    if is_search_captcha_html(html, engine=engine):
        return ()
    parser = _SnippetParser()
    parser.feed(html)
    chunks = parser.snippets or (_SearchTextChunk(parser.visible_text),)
    findings: list[SearchResultEmail] = []
    for chunk in chunks:
        for email in extract_loose_emails(chunk.text):
            _append_search_result_email(findings, email, chunk.found_url)
    if parser.snippets:
        for email in extract_loose_emails(_strip_html_to_text(html, keep_tag_boundaries=False)):
            _append_search_result_email(findings, email, "")
    if engine == "google":
        visible_emails = {finding.email for finding in findings}
        for finding in _google_comment_findings(html):
            if finding.email in visible_emails:
                _append_search_result_email(findings, finding.email, finding.found_url)
    return tuple(findings)


def _google_comment_findings(html: str) -> tuple[SearchResultEmail, ...]:
    """Link an e-mail to its Google result only when one source URL is explicit."""
    findings: list[SearchResultEmail] = []
    for raw_comment in HTML_COMMENT_RE.findall(html):
        if not raw_comment.startswith("TgQPHd|||") or "@" not in raw_comment:
            continue
        comment = unescape(raw_comment)
        emails = extract_loose_emails(comment)
        if not emails:
            continue
        urls = tuple(dict.fromkeys(
            normalized
            for raw_url in QUOTED_HTTP_URL_RE.findall(comment)
            if (normalized := _normalize_result_href(_decode_google_result_url(raw_url)))
        ))
        if len(urls) != 1:
            continue
        for email in emails:
            finding = SearchResultEmail(email=email, found_url=urls[0])
            if finding not in findings:
                findings.append(finding)
    return tuple(findings)


def _decode_google_result_url(raw_url: str) -> str:
    try:
        return json.loads('"' + raw_url + '"')
    except json.JSONDecodeError:
        return raw_url


def parse_search_result_links(html: str, engine: str = "yandex") -> tuple[str, ...]:
    if is_search_captcha_html(html, engine=engine):
        return ()
    parser = _SnippetParser()
    parser.feed(html)
    return tuple(parser.result_urls)


def parse_yandex_result_emails(html: str) -> tuple[str, ...]:
    return parse_search_result_emails(html, engine="yandex")


def parse_google_result_emails(html: str) -> tuple[str, ...]:
    return parse_search_result_emails(html, engine="google")


def _append_search_result_email(findings: list[SearchResultEmail], email: str, found_url: str) -> None:
    if found_url:
        findings[:] = [finding for finding in findings if not (finding.email == email and not finding.found_url)]
    elif any(finding.email == email and finding.found_url for finding in findings):
        return
    finding = SearchResultEmail(email=email, found_url=found_url)
    if finding not in findings:
        findings.append(finding)


def _normalize_result_href(href: str) -> str:
    href = unescape(href or "").strip()
    if not href:
        return ""
    lowered = href.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:")) or lowered.startswith("#"):
        return ""
    if href.startswith("//"):
        href = "https:" + href

    parsed = urllib.parse.urlparse(href)
    host = (parsed.hostname or "").lower()
    if not parsed.scheme or _is_search_navigation_host(host):
        query_values = urllib.parse.parse_qs(parsed.query)
        for key in ("url", "u", "to", "target", "q"):
            for value in query_values.get(key, ()):
                nested = unescape(value).strip()
                if nested.startswith(("http://", "https://")):
                    normalized = _normalize_result_href(nested)
                    if normalized:
                        return normalized

    if not parsed.scheme or parsed.scheme not in {"http", "https"}:
        return ""
    if _is_search_navigation_host(host):
        return ""

    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def _is_search_navigation_host(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in SEARCH_NAV_HOST_SUFFIXES)


def _is_pdf_url(url: str) -> bool:
    return urllib.parse.urlparse(url).path.lower().endswith(".pdf")


def _looks_like_pdf_response(url: str, response: FetchBinaryResponse) -> bool:
    content_type = response.content_type.lower()
    return "pdf" in content_type or response.body.lstrip().startswith(b"%PDF") or _is_pdf_url(url)


def is_search_captcha_html(html: str, engine: str = "yandex") -> bool:
    detector = _captcha_detector_for_engine(engine)
    return detector(html)


def is_yandex_captcha_html(html: str) -> bool:
    normalized = unescape(html).lower()
    return (
        "smartcaptcha" in normalized
        or "checkbox-captcha" in normalized
        or "вы не робот" in normalized
        or "подтвердите, что запросы отправляли вы" in normalized
        or "/checkcaptcha" in normalized
    )


def is_google_captcha_html(html: str) -> bool:
    normalized = unescape(html).lower()
    return (
        "unusual traffic" in normalized
        or "our systems have detected" in normalized
        or "detected unusual traffic" in normalized
        or 'id="captcha-form"' in normalized
        or "g-recaptcha" in normalized
    )


def extract_loose_emails(value: str) -> tuple[str, ...]:
    text = _strip_html_to_text(value, keep_tag_boundaries=False)
    text = HTML_ENTITY_RE.sub(lambda match: unescape(match.group(0)), text)
    text = unescape(text)
    text = _normalize_quoted_email_separators(text)
    found: list[str] = []
    for match in LOOSE_EMAIL_RE.finditer(text):
        local = re.sub(r"\s+", "", match.group(1).lower()).strip("._%+-")
        domain = re.sub(r"\s+", "", match.group(2).lower()).strip(".-")
        email = _strip_email_file_extension(f"{local}@{domain}")
        if EMAIL_CANDIDATE_RE.match(email) and email not in found:
            found.append(email)
    return tuple(found)


def _strip_email_file_extension(email: str) -> str:
    local, _, domain = email.partition("@")
    labels = domain.split(".")
    if len(labels) <= 2 or labels[-1] not in FILE_EXTENSION_SUFFIXES:
        return email
    trimmed_domain = ".".join(labels[:-1])
    trimmed = f"{local}@{trimmed_domain}"
    return trimmed if EMAIL_CANDIDATE_RE.match(trimmed) else email


def _normalize_quoted_email_separators(value: str) -> str:
    return re.sub(r"[\"'`“”«»]\s*([@.])\s*[\"'`“”«»]", r"\1", value)


def _strip_html_to_text(value: str, keep_tag_boundaries: bool) -> str:
    value = SCRIPT_STYLE_RE.sub(" ", value)
    separator = " " if keep_tag_boundaries else ""
    return TAG_RE.sub(separator, value)


def _write_found_emails(path: Path, emails: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=f".{path.name}.",
            suffix=".tmp", dir=path.parent, delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write("\n".join(emails) + ("\n" if emails else ""))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _search_response_html(response: FetchResponse) -> str:
    return response.body


def _unique_destination(directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / filename
    if not destination.exists():
        return destination
    stem = destination.stem
    suffix = destination.suffix
    counter = 2
    while True:
        candidate = directory / f"{stem}-{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return safe or "query"


def _pdf_filename(url: str, index: int) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "pdf"
    stem = Path(urllib.parse.unquote(parsed.path)).stem or "document"
    return f"{index:03d}-{_safe_filename(host)}-{_safe_filename(stem)}.pdf"


def _normalize_text_for_display(value: str) -> str:
    return re.sub(r"\s+", " ", unescape(value)).strip()


def _normalize_domain(value: str) -> str:
    value = value.strip().lower().lstrip("@")
    value = value.removeprefix("http://").removeprefix("https://")
    return value.split("/", 1)[0]


def _normalize_term(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._%+-]+", "", value.strip().lower())


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[1].lower() if "@" in email else ""


def _search_query_counts_text(queries: tuple[SearchQuery, ...]) -> str:
    if not queries:
        return "0"
    counts: dict[str, int] = {}
    for query in queries:
        counts[query.engine] = counts.get(query.engine, 0) + 1
    details = ", ".join(f"{engine}: {count}" for engine, count in sorted(counts.items()))
    return f"{len(queries)} всего ({details})"


def _normalize_search_engines(engines: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for raw in engines:
        for part in str(raw).replace(";", ",").split(","):
            engine = part.strip().lower()
            if not engine:
                continue
            if engine not in SUPPORTED_SEARCH_ENGINES:
                supported = ", ".join(sorted(SUPPORTED_SEARCH_ENGINES))
                raise ValueError(f"Unsupported search engine {engine!r}; supported: {supported}")
            if engine not in result:
                result.append(engine)
    return tuple(result) or ("yandex",)


def _render_dork(template: str, *, term: str, domain: str, company: str, site_url: str) -> str:
    values = _DorkValues(
        {
            "term": term,
            "domain": domain,
            "email_domain": domain,
            "company": company,
            "url": site_url or domain,
        }
    )
    return re.sub(r"\s+", " ", template.format_map(values)).strip()


class _DorkValues(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _company_from_domain(domain: str) -> str:
    labels = [label for label in _normalize_domain(domain).split(".") if label]
    if labels and labels[0] == "www":
        labels = labels[1:]
    if len(labels) > 1:
        labels = labels[:-1]
    return ".".join(labels)


def _captcha_detector_for_engine(engine: str):
    if engine == "google":
        return is_google_captcha_html
    return is_yandex_captcha_html
