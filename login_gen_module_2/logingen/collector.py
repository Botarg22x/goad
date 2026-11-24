from __future__ import annotations

import re
import urllib.parse
import urllib.robotparser
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol

from .defaults import DEFAULT_PEOPLE, popular_firstnames
from .models import AutoConfig, Person
from .documents import document_type
from .playwright_fetcher import (
    FetchResponse,
    PlaywrightFetchError,
    PlaywrightFetchTimeoutError,
    PlaywrightFetchTransport,
    PlaywrightUnavailableError,
)


LogFn = Callable[[str], None]


class FetchTransport(Protocol):
    def fetch_text(
        self,
        url: str,
        *,
        timeout_seconds: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResponse:
        ...

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        ...

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOCUMENT_SUFFIXES = (".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".odt", ".odp", ".ods", ".txt", ".csv")
CYR_WORD = r"[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?"
CYR_TOKEN_RE = re.compile(r"[А-ЯЁа-яё]+(?:-[А-ЯЁа-яё]+)?")
FIO3_RE = re.compile(rf"\b({CYR_WORD})\s+({CYR_WORD})\s+({CYR_WORD})\b")
FIO2_RE = re.compile(rf"\b({CYR_WORD})\s+({CYR_WORD})\b")
STANDALONE_FIO_RE = re.compile(rf"^\s*({CYR_WORD})\s+({CYR_WORD})(?:\s+({CYR_WORD}))?\s*$")
VEDOMOSTI_SEARCH_BASE = "https://events.vedomosti.ru/search"
VEDOMOSTI_ALLOWED_DOMAIN = "events.vedomosti.ru"
_JS_SHELL_RE = re.compile(
    r"(?:id\s*=\s*['\"](?:app|root|__next|__nuxt)['\"]|"
    r"__NEXT_DATA__|__NUXT__|data-reactroot|"
    r"<noscript\b[^>]*>[^<]*(?:javascript|java\s*script))",
    re.IGNORECASE,
)

COMMON_FIRSTNAMES = {
    person.firstname.lower() for person in DEFAULT_PEOPLE
} | {
    firstname.lower() for firstname in popular_firstnames()
} | {
    "александр",
    "алексей",
    "анатолий",
    "андрей",
    "анна",
    "антон",
    "артем",
    "борис",
    "валентин",
    "валентина",
    "валерий",
    "василий",
    "вера",
    "виктор",
    "виктория",
    "виталий",
    "владимир",
    "вячеслав",
    "галина",
    "денис",
    "дмитрий",
    "евгений",
    "евгения",
    "екатерина",
    "елена",
    "иван",
    "игорь",
    "илья",
    "инна",
    "ирина",
    "кирилл",
    "константин",
    "ксения",
    "марина",
    "мария",
    "максим",
    "михаил",
    "наталья",
    "никита",
    "николай",
    "оксана",
    "олег",
    "ольга",
    "павел",
    "петр",
    "роман",
    "светлана",
    "сергей",
    "татьяна",
    "юлия",
    "юрий",
}

PERSON_STOPWORDS = {
    "акции",
    "архив",
    "бизнес",
    "вакансии",
    "главная",
    "группа",
    "директор",
    "документы",
    "команда",
    "компания",
    "контакты",
    "магазин",
    "менеджер",
    "новости",
    "отдел",
    "партнеры",
    "поддержка",
    "политика",
    "пресс",
    "продукты",
    "проект",
    "раздел",
    "россия",
    "служба",
    "сотрудники",
    "страница",
    "услуги",
    "центр",
}


@dataclass(frozen=True)
class EmailSourceRecord:
    email: str
    source_type: str
    engine: str = ""
    query: str = ""
    found_url: str = ""
    query_url: str = ""
    url: str = ""
    source_path: str = ""


@dataclass(frozen=True)
class PersonSourceRecord:
    person: Person
    source_type: str
    url: str
    source_path: str = ""
    query_url: str = ""


@dataclass(frozen=True)
class CollectionResult:
    people: tuple[Person, ...] = field(default_factory=tuple)
    emails: tuple[str, ...] = field(default_factory=tuple)
    email_sources: tuple[EmailSourceRecord, ...] = field(default_factory=tuple)
    person_sources: tuple[PersonSourceRecord, ...] = field(default_factory=tuple)
    domains: tuple[str, ...] = field(default_factory=tuple)
    visited_urls: tuple[str, ...] = field(default_factory=tuple)
    skipped_urls: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.mailto_emails: list[str] = []
        self.source_path: str = ""
        self.raw_html: str = ""
        self.base_url: str = ""
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return
        attrs_map = {name.lower(): value or "" for name, value in attrs}
        href = attrs_map.get("href", "")
        if tag == "base" and href:
            self.base_url = urllib.parse.urljoin(self.base_url, href)
        if tag == "a" and href:
            if href.lower().startswith("mailto:"):
                self.mailto_emails.extend(extract_emails(href))
            else:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.text_parts.append(data)

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)


class _SpeakerNameParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.names: list[str] = []
        self._capture_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {name.lower(): value or "" for name, value in attrs}
        classes = set(attrs_map.get("class", "").split())
        if "b-search-speaker__name" in classes:
            self._capture_depth += 1
            self._parts = []
        elif self._capture_depth:
            self._capture_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if not self._capture_depth:
            return
        self._capture_depth -= 1
        if self._capture_depth == 0:
            name = re.sub(r"\s+", " ", " ".join(self._parts)).strip()
            if name:
                self.names.append(name)
            self._parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_depth:
            self._parts.append(data)


class _RobotsGate:
    def __init__(self, config: AutoConfig, log: LogFn | None, fetcher: FetchTransport) -> None:
        self._config = config
        self._log = log
        self._fetcher = fetcher
        self._cache: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def can_fetch(self, url: str) -> bool:
        if not self._config.respect_robots_txt:
            return True
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._cache:
            self._cache[base] = self._load_parser(base)
        parser = self._cache[base]
        if parser is None:
            return True
        allowed = parser.can_fetch(self._config.user_agent, url)
        if not allowed and self._log:
            self._log(f"robots.txt disallowed: {url}")
        return allowed

    def _load_parser(self, base: str) -> urllib.robotparser.RobotFileParser | None:
        robots_url = urllib.parse.urljoin(base, "/robots.txt")
        parser = urllib.robotparser.RobotFileParser(robots_url)
        try:
            response = self._fetcher.fetch_text(
                robots_url,
                timeout_seconds=self._config.timeout_seconds,
                headers={"Accept": "text/plain,*/*"},
            )
        except PlaywrightFetchTimeoutError:
            if self._log:
                self._log(f"robots.txt unavailable (timeout); continuing: {base}")
            return None
        except PlaywrightFetchError as error:
            if self._log:
                self._log(f"robots.txt unavailable ({error}); continuing: {base}")
            return None

        if response.status_code >= 400:
            if response.status_code == 404:
                parser.parse([])
                return parser
            if response.status_code in {401, 403}:
                if self._config.browser_crawl:
                    if self._log:
                        self._log(
                            f"robots.txt unavailable with HTTP {response.status_code}; "
                            f"continuing with browser crawl: {base}"
                        )
                    return None
                if self._log:
                    self._log(f"robots.txt unavailable with HTTP {response.status_code}; skipping host: {base}")
                return _DenyAllRobotsParser(robots_url)
            if self._log:
                self._log(f"robots.txt unavailable with HTTP {response.status_code}; continuing: {base}")
            return None

        parser.parse(response.body.splitlines())
        return parser


class _DenyAllRobotsParser(urllib.robotparser.RobotFileParser):
    def can_fetch(self, useragent: str, url: str) -> bool:
        return False


class _AutoPageFetcher:
    def __init__(self, config: AutoConfig, log: LogFn | None, fetcher: FetchTransport) -> None:
        self._config = config
        self._log = log
        self._fetcher = fetcher
        self._counter = 0

    def fetch_page(self, url: str, warnings: list[str]) -> _PageParser | None:
        if not self._config.browser_crawl:
            response = _fetch_response(url, self._config, warnings, self._fetcher)
            if response is None:
                return None
            html = response.body
            static_page = _PageParser()
            static_page.base_url = response.url or url
            static_page.feed(html)
            static_page.raw_html = html
            if not _needs_browser_fallback(html, static_page):
                return static_page
            if self._log:
                self._log(f"JS-оболочка без e-mail/ФИО; пробую браузер: {url}")
            try:
                # Automatic fallback stays headless; interactive manual access
                # is reserved for an explicit --browser-crawl run.
                response = self._fetcher.fetch_rendered_html(url)
            except (PlaywrightFetchError, PlaywrightFetchTimeoutError) as error:
                warnings.append(f"Browser fallback failed for {url}: {error}")
                return static_page
            if not _is_usable_html_response(response, url, warnings):
                return static_page
            rendered_page = _PageParser()
            rendered_page.base_url = response.url or url
            rendered_page.feed(response.body)
            rendered_page.links = list(dict.fromkeys((*static_page.links, *rendered_page.links)))
            saved_path = _save_browser_html(
                url, response.body, self._config.browser_pages_dir, self._counter
            )
            self._counter += 1
            rendered_page.source_path = str(saved_path)
            if self._log:
                self._log(f"browser fallback html saved: {saved_path}")
            return rendered_page

        try:
            response = self._fetch_rendered_company_html(url)
        except PlaywrightFetchTimeoutError:
            warnings.append(f"Browser timeout while fetching {url}")
            return None
        except PlaywrightFetchError as error:
            warnings.append(f"Browser error while fetching {url}: {error}")
            return None

        if not _is_usable_html_response(response, url, warnings):
            return None

        saved_path = _save_browser_html(url, response.body, self._config.browser_pages_dir, self._counter)
        self._counter += 1
        if self._log:
            self._log(f"browser html saved: {saved_path}")

        parser = _PageParser()
        parser.base_url = response.url or url
        parser.feed(response.body)
        parser.source_path = str(saved_path)
        return parser

    def _fetch_rendered_company_html(self, url: str) -> FetchResponse:
        if self._config.browser_manual_access:
            manual_fetch = getattr(self._fetcher, "fetch_rendered_html_with_manual_access", None)
            if callable(manual_fetch):
                return manual_fetch(url)
        return self._fetcher.fetch_rendered_html(url)


def collect_public_data(
    config: AutoConfig,
    log: LogFn | None = None,
    fetcher: FetchTransport | None = None,
    on_progress: Callable[[CollectionResult], None] | None = None,
) -> CollectionResult:
    seeds = tuple(url for url in (config.url, *config.extra_urls) if url)
    if not seeds:
        return CollectionResult(warnings=("Auto mode enabled, but no auto.url is configured.",))

    allowed_domains = tuple(config.allowed_domains) or tuple(dict.fromkeys(
        domain for seed in seeds for domain in _default_allowed_domains(seed)))
    queue: deque[tuple[str, int]] = deque((normalize_url(seed), 0) for seed in seeds)
    queued = {item[0] for item in queue}
    visited: list[str] = []
    skipped: list[str] = []
    warnings: list[str] = []
    people: list[Person] = []
    emails: list[str] = []
    email_sources: list[EmailSourceRecord] = []
    person_sources: list[PersonSourceRecord] = []
    owned_fetcher: PlaywrightFetchTransport | None = None

    if fetcher is None:
        try:
            if config.site_crawler == "katana":
                from .katana_fetcher import KatanaFetchTransport
                owned_fetcher = KatanaFetchTransport(config)
            else:
                owned_fetcher = PlaywrightFetchTransport(config)
            fetcher = owned_fetcher
        except PlaywrightUnavailableError as error:
            if log:
                log(str(error))
            return CollectionResult(warnings=(str(error),))

    robots = _RobotsGate(config, log, fetcher)
    page_fetcher = _AutoPageFetcher(config, log, fetcher)
    document_count = 0
    page_count = 0

    def checkpoint():
        if on_progress:
            on_progress(CollectionResult(
                people=tuple(people), emails=tuple(emails), email_sources=tuple(email_sources),
                person_sources=tuple(dict.fromkeys(person_sources)), visited_urls=tuple(visited),
                domains=tuple(_sorted_unique(_email_domain(email) for email in emails)),
                warnings=tuple(warnings),
            ))

    if log:
        log(
            "сбор с сайта начат; разрешённые домены: "
            f"{', '.join(allowed_domains)}; внешние ссылки будут пропущены"
        )

    try:
        while queue:
            url, depth = queue.popleft()
            if not _is_http_url(url) or not is_allowed_url(url, allowed_domains, exact_hosts=config.exact_hosts):
                skipped.append(url)
                if log:
                    log(f"skip out of scope: {url}")
                continue
            if url in visited:
                continue
            kind = document_type(url)
            if '.' + kind in DOCUMENT_SUFFIXES and (not config.pdf_enabled or kind not in config.document_types):
                skipped.append(url)
                if log:
                    log(f"skip document (disabled format): {url}")
                continue
            if not robots.can_fetch(url):
                skipped.append(url)
                continue

            if document_type(url) in config.document_types:
                if not config.pdf_enabled or document_count >= config.pdf_max_files:
                    continue
                from .search_sources import PdfSourceCandidate, collect_pdf_sources
                document_count += 1
                _files, result = collect_pdf_sources(
                    (PdfSourceCandidate(url, "", "", "", Path()),),
                    replace(config, pdf_max_files=1), log=log, fetcher=fetcher,
                )
                visited.append(url)
                if config.collect_people:
                    for person in result.people:
                        if _person_key(person) not in {_person_key(item) for item in people}:
                            people.append(person)
                    person_sources.extend(result.person_sources)
                if config.collect_emails:
                    emails.extend(email for email in result.emails if email not in emails)
                    email_sources.extend(result.email_sources)
                warnings.extend(result.warnings)
                checkpoint()
                continue
            if page_count >= config.max_pages:
                continue
            page_count += 1

            if log:
                log(f"fetch depth={depth}: {url}")
            page = page_fetcher.fetch_page(url, warnings)
            if page is None:
                skipped.append(url)
                continue

            visited.append(url)
            page_emails = extract_emails(page.text) if config.collect_emails else ()
            page_people = extract_people(page.text) if config.collect_people else ()
            if (page_emails or page.mailto_emails or page_people) and not page.source_path and page.raw_html:
                snapshot = _save_browser_html(url, page.raw_html, config.browser_pages_dir / "site", len(visited) - 1)
                page.source_path = str(snapshot)
            for email in (*page.mailto_emails, *page_emails):
                if email not in emails:
                    emails.append(email)
                source = EmailSourceRecord(
                    email=email, source_type="site", found_url=url, url=url,
                    source_path=page.source_path,
                )
                if source not in email_sources:
                    email_sources.append(source)
            for person in page_people:
                if _person_key(person) not in {_person_key(item) for item in people}:
                    people.append(person)
                person_sources.append(PersonSourceRecord(person, "site", url, page.source_path))
            if log:
                log(f"parsed: emails={len(page_emails) + len(page.mailto_emails)}, people={len(page_people)}")
            checkpoint()
            for link in page.links:
                next_url = normalize_url(urllib.parse.urljoin(page.base_url or url, link))
                link_kind = document_type(next_url)
                is_document = '.' + link_kind in DOCUMENT_SUFFIXES
                if depth >= config.max_depth and not is_document:
                    continue
                if is_document and (not config.pdf_enabled or link_kind not in config.document_types):
                    skipped.append(next_url)
                    continue
                if next_url not in queued and is_allowed_url(next_url, allowed_domains, exact_hosts=config.exact_hosts):
                    queue.append((next_url, depth + 1))
                    queued.add(next_url)
    finally:
        if owned_fetcher:
            owned_fetcher.close()

    domains = tuple(_sorted_unique(_email_domain(email) for email in emails if _email_domain(email)))
    if log:
        log(
            "auto collection finished; "
            f"pages={len(visited)}, people={len(people)}, emails={len(emails)}, skipped={len(skipped)}"
        )
    return CollectionResult(
        people=tuple(people),
        emails=tuple(emails),
        email_sources=tuple(email_sources),
        person_sources=tuple(dict.fromkeys(person_sources)),
        domains=domains,
        visited_urls=tuple(visited),
        skipped_urls=tuple(skipped),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def collect_vedomosti_speakers(
    company: str,
    config: AutoConfig,
    log: LogFn | None = None,
    fetcher: FetchTransport | None = None,
) -> CollectionResult:
    if not company.strip():
        return CollectionResult(warnings=("Vedomosti source enabled, but company name is empty.",))

    warnings: list[str] = []
    people: list[Person] = []
    person_sources: list[PersonSourceRecord] = []
    visited: list[str] = []
    skipped: list[str] = []
    owned_fetcher: PlaywrightFetchTransport | None = None
    if fetcher is None:
        try:
            owned_fetcher = PlaywrightFetchTransport(config)
            fetcher = owned_fetcher
        except PlaywrightUnavailableError as error:
            if log:
                log(str(error))
            return CollectionResult(warnings=(str(error),))

    robots = _RobotsGate(config, log, fetcher)

    if log:
        log(f"vedomosti search started: company={company!r}")

    try:
        page_number = 1
        url = build_vedomosti_search_url(company, page=page_number)
        if not robots.can_fetch(url):
            skipped.append(url)
        else:
            if log:
                log(f"vedomosti fetch page={page_number}: {url}")
            html = _fetch_html(url, config, warnings, fetcher)
            if html is None:
                skipped.append(url)
            else:
                visited.append(url)
                page_people = extract_vedomosti_people(html)
                snapshot = _save_browser_html(url, html, config.browser_pages_dir / "vedomosti", 0)
                for person in page_people:
                    if _person_key(person) not in {_person_key(item) for item in people}:
                        people.append(person)
                    person_sources.append(PersonSourceRecord(person, "vedomosti", url, str(snapshot)))
                if log:
                    log(f"vedomosti parsed: people={len(page_people)}")
    finally:
        if owned_fetcher:
            owned_fetcher.close()

    if log:
        log(f"vedomosti search finished; pages={len(visited)}, people={len(people)}, skipped={len(skipped)}")

    return CollectionResult(
        people=tuple(people),
        person_sources=tuple(dict.fromkeys(person_sources)),
        visited_urls=tuple(visited),
        skipped_urls=tuple(skipped),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def build_vedomosti_search_url(company: str, page: int = 1) -> str:
    params = {
        "page": str(max(page, 1)),
        "q": company,
        "sort": "revalance",
        "template": "speakers",
    }
    return VEDOMOSTI_SEARCH_BASE + "?" + urllib.parse.urlencode(params)


def extract_vedomosti_people(html: str) -> tuple[Person, ...]:
    parser = _SpeakerNameParser()
    parser.feed(html)

    people: list[Person] = []
    seen: set[tuple[str, str, str]] = set()
    for raw_name in parser.names:
        person = _person_from_speaker_name(raw_name)
        if person and _person_key(person) not in seen:
            people.append(person)
            seen.add(_person_key(person))
    return tuple(people)


def extract_emails(text: str) -> tuple[str, ...]:
    found = []
    for raw in EMAIL_RE.findall(unescape(text)):
        email = raw.strip().strip(".,;:()[]{}<>\"'").lower()
        if email and email not in found:
            found.append(email)
    return tuple(found)


def extract_people(text: str) -> tuple[Person, ...]:
    normalized = re.sub(r"\s+", " ", unescape(text))
    people: list[Person] = []
    seen: set[tuple[str, str, str]] = set()

    for match in FIO3_RE.finditer(normalized):
        words = match.groups()
        person = _person_from_words(words)
        if person and _person_key(person) not in seen:
            people.append(person)
            seen.add(_person_key(person))

    occupied = set()
    for match in FIO3_RE.finditer(normalized):
        occupied.update(range(match.start(), match.end()))

    for match in FIO2_RE.finditer(normalized):
        if any(index in occupied for index in range(match.start(), match.end())):
            continue
        if normalized[match.end():match.end() + 1] == "-":
            # A PDF line may split a surname ("Подоль-\nская").  The
            # partial token must not become a separate person.
            continue
        words = match.groups()
        person = _person_from_words(words)
        if person and _person_key(person) not in seen:
            people.append(person)
            seen.add(_person_key(person))

    return tuple(people)


def extract_standalone_people(text: str) -> tuple[Person, ...]:
    """Read standalone name lines, including uncommon first names."""
    people: list[Person] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        match = STANDALONE_FIO_RE.fullmatch(line)
        if match is None:
            continue
        words = tuple(word for word in match.groups() if word)
        if any(word.lower() in PERSON_STOPWORDS for word in words):
            continue
        person = _person_from_words(words)
        if person is None:
            if len(words) == 3 and _looks_like_patronymic(words[2]):
                person = Person(firstname=words[0], lastname=words[1], patronymic=words[2])
            elif len(words) == 2:
                person = Person(firstname=words[0], lastname=words[1])
        if person and _person_key(person) not in seen:
            people.append(person)
            seen.add(_person_key(person))
    return tuple(people)


def normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url.strip())
    if not parsed.scheme:
        parsed = urllib.parse.urlparse("https://" + url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    normalized = urllib.parse.urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return normalized


def is_allowed_url(
    url: str, allowed_domains: Iterable[str], *, exact_hosts: bool = False,
) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return any(
        host == domain or (not exact_hosts and host.endswith("." + domain))
        for domain in allowed_domains
    )


def _needs_browser_fallback(html: str, page: _PageParser) -> bool:
    """Render only sparse JS app shells with no useful static people or email data."""
    visible_text = page.text.strip()
    return (
        len(visible_text) <= 300
        and not page.mailto_emails
        and not extract_emails(visible_text)
        and not extract_people(visible_text)
        and bool(_JS_SHELL_RE.search(html))
        and bool(re.search(r"<script\b", html, re.IGNORECASE))
    )


def _fetch_html(
    url: str,
    config: AutoConfig,
    warnings: list[str],
    fetcher: FetchTransport,
) -> str | None:
    response = _fetch_response(url, config, warnings, fetcher)
    return response.body if response is not None else None


def _fetch_response(
    url: str,
    config: AutoConfig,
    warnings: list[str],
    fetcher: FetchTransport,
) -> FetchResponse | None:
    try:
        response = fetcher.fetch_text(url, timeout_seconds=config.timeout_seconds)
    except PlaywrightFetchTimeoutError:
        warnings.append(f"Timeout while fetching {url}")
        return None
    except PlaywrightFetchError as error:
        warnings.append(f"Network error while fetching {url}: {error}")
        return None

    if not _is_usable_html_response(response, url, warnings):
        return None
    return response


def _is_usable_html_response(response: FetchResponse, url: str, warnings: list[str]) -> bool:
    if response.status_code >= 400:
        warnings.append(f"HTTP {response.status_code} while fetching {url}")
        return False
    if not _is_html_content_type(response.content_type):
        warnings.append(f"Skipped non-HTML content at {url}: {response.content_type or 'unknown content type'}")
        return False
    return True


def _is_html_content_type(content_type: str) -> bool:
    if not content_type:
        return True
    normalized = content_type.lower()
    return "text/html" in normalized or "application/xhtml+xml" in normalized


def _person_from_words(words: tuple[str, ...]) -> Person | None:
    lowered = tuple(word.lower() for word in words)
    if any(word in PERSON_STOPWORDS for word in lowered):
        return None

    if len(words) == 3:
        first, second, third = words
        if _looks_like_patronymic(third):
            if first.lower() in COMMON_FIRSTNAMES:
                return Person(firstname=first, lastname=second, patronymic=third)
            if second.lower() in COMMON_FIRSTNAMES:
                return Person(firstname=second, lastname=first, patronymic=third)
        if first.lower() in COMMON_FIRSTNAMES:
            return Person(firstname=first, lastname=second, patronymic=third)
        if second.lower() in COMMON_FIRSTNAMES:
            return Person(firstname=second, lastname=first, patronymic=third)
        return None

    first, second = words
    if first.lower() in COMMON_FIRSTNAMES:
        return Person(firstname=first, lastname=second)
    if second.lower() in COMMON_FIRSTNAMES:
        return Person(firstname=second, lastname=first)
    return None


def _person_from_speaker_name(value: str) -> Person | None:
    words = [word.title() for word in CYR_TOKEN_RE.findall(unescape(value))]
    if len(words) < 2:
        return None
    firstname = words[0]
    lastname = words[1]
    patronymic = words[2] if len(words) >= 3 and _looks_like_patronymic(words[2]) else ""
    return Person(firstname=firstname, lastname=lastname, patronymic=patronymic)


def _looks_like_patronymic(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith(("вич", "ич", "вна", "ична", "инична", "оглы", "кызы"))


def _default_allowed_domains(url: str) -> tuple[str, ...]:
    host = urllib.parse.urlparse(normalize_url(url)).hostname or ""
    host = host.lower()
    if host.startswith("www."):
        return (host[4:],)
    return (host,)


def _is_http_url(url: str) -> bool:
    return urllib.parse.urlparse(url).scheme in {"http", "https"}


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[1].lower() if "@" in email else ""


def _person_key(person: Person) -> tuple[str, str, str]:
    return (person.firstname.lower(), person.lastname.lower(), person.patronymic.lower())


def _sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted(dict.fromkeys(value for value in values if value))


def _save_browser_html(url: str, html: str, directory: Path, index: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "page"
    path = parsed.path.strip("/").replace("/", "-") or "index"
    filename = f"{index + 1:03d}-{_safe_filename(host)}-{_safe_filename(path)}.html"
    destination = _unique_path(directory / filename)
    destination.write_text(html, encoding="utf-8", errors="replace")
    return destination


def _safe_filename(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower()).strip("-")
    return safe or "page"


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 2
    while True:
        candidate = path.with_name(f"{stem}-{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1
