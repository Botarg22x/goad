from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import replace
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol

from .collector import CollectionResult, LogFn, PersonSourceRecord, extract_people, normalize_url
from .models import AutoConfig, Person
from .playwright_fetcher import (
    FetchResponse,
    PlaywrightFetchError,
    PlaywrightFetchTimeoutError,
    PlaywrightFetchTransport,
    PlaywrightUnavailableError,
)
from .search_sources import (
    SUPPORTED_SEARCH_ENGINES,
    SearchQuery,
    build_search_url,
    fetch_search_pages,
    parse_search_result_links,
)


SETKA_HOST = "setka.ru"
SETKA_NETWORK_URL_BASE = "https://setka.ru/networks"
SETKA_MIN_DELAY_SECONDS = 15.0


class _SetkaRateLimited(Exception):
    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.url = url
NETWORK_ID_RE = re.compile(r"(?:https?://setka\.ru)?/networks/([a-zA-Z0-9_-]+)(?=[/?#\"'<>\s]|$)")
NETWORKS_LOAD_MORE_RE = re.compile(r"""hx-get=["']([^"']*/companies/[^"']+/networks/load-more/[^"']*)["']""")
EVENT_LABEL_RE = re.compile(r'"event_label"\s*:\s*"([a-zA-Z0-9_-]+)"')
NAME_TOKEN_RE = re.compile(r"[A-Za-zА-Яа-яЁё]+(?:[-'][A-Za-zА-Яа-яЁё]+)?")
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
COMPANY_STOP_WORDS = frozenset(
    {
        "ooo",
        "ao",
        "pao",
        "zao",
        "ip",
        "llc",
        "ltd",
        "\u043e\u043e\u043e",
        "\u0430\u043e",
        "\u043f\u0430\u043e",
        "\u0437\u0430\u043e",
        "\u0438\u043f",
        "\u043e\u0430\u043e",
        "\u043a\u043e\u043c\u043f\u0430\u043d\u0438\u044f",
        "\u043a\u043e\u043c\u043f\u0430\u043d\u0438\u0438",
        "\u0441\u0435\u0442\u044c",
        "\u0441\u0435\u0442\u0438",
        "\u0433\u0440\u0443\u043f\u043f\u0430",
        "\u0433\u043a",
    }
)


class RenderFetcher(Protocol):
    def fetch_rendered_html(self, url: str) -> FetchResponse:
        ...


class _HxSwapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.working_names: list[str] = []
        self.working_section_seen = False
        self.chunks: list[str] = []
        self.chunk_nodes: list[tuple[str, ...]] = []
        self._working_depth = 0
        self._member_link_depth = 0
        self._member_link_parts: list[str] = []
        self._capture_depth = 0
        self._parts: list[str] = []
        self._nodes: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return

        attrs_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "div" and attrs_map.get("id", "").strip() == "working_now_members" and not self._working_depth:
            self.working_section_seen = True
            self._working_depth = 1
        elif self._working_depth and tag not in VOID_TAGS:
            self._working_depth += 1

        if self._working_depth and tag == "a" and _is_setka_member_link(attrs_map) and not self._member_link_depth:
            self._member_link_depth = 1
            self._member_link_parts = []
        elif self._member_link_depth and tag not in VOID_TAGS:
            self._member_link_depth += 1

        hx_swap = attrs_map.get("hx-swap", "").lower()
        if "innerhtml" in hx_swap and not self._capture_depth:
            self._capture_depth = 1
            self._parts = []
            self._nodes = []
        elif self._capture_depth:
            self._capture_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return

        if self._member_link_depth:
            self._member_link_depth -= 1
            if self._member_link_depth == 0:
                name = re.sub(r"\s+", " ", " ".join(self._member_link_parts)).strip()
                if name:
                    self.working_names.append(name)
                self._member_link_parts = []

        if not self._capture_depth:
            if self._working_depth:
                self._working_depth -= 1
            return
        self._capture_depth -= 1
        if self._capture_depth == 0:
            text = re.sub(r"\s+", " ", " ".join(self._parts)).strip()
            if text:
                self.chunks.append(text)
                self.chunk_nodes.append(tuple(self._nodes))
            self._parts = []
            self._nodes = []
        if self._working_depth:
            self._working_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._member_link_depth and not self._skip_depth:
            self._member_link_parts.append(data)
        if self._capture_depth and not self._skip_depth:
            self._parts.append(data)
            node = re.sub(r"\s+", " ", data).strip()
            if node:
                self._nodes.append(node)


class _SetkaCompanyIdentityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._capture_tag: str | None = None
        self._capture_depth = 0
        self._current_parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return

        attrs_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "meta":
            name = (attrs_map.get("property") or attrs_map.get("name") or "").lower()
            if name in {"og:title", "og:description", "description"} and attrs_map.get("content"):
                self.parts.append(attrs_map["content"])
            return

        if tag in {"title", "h1"} and self._capture_tag is None:
            self._capture_tag = tag
            self._capture_depth = 1
            self._current_parts = []
        elif self._capture_tag and tag not in VOID_TAGS:
            self._capture_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if not self._capture_tag:
            return
        self._capture_depth -= 1
        if self._capture_depth == 0:
            text = re.sub(r"\s+", " ", " ".join(self._current_parts)).strip()
            if text:
                self.parts.append(text)
            self._capture_tag = None
            self._current_parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_tag and not self._skip_depth:
            self._current_parts.append(data)


def build_setka_search_query(company: str) -> str:
    return re.sub(r"\s+", " ", f"{company.strip()} site:setka.ru/companies").strip()


def build_setka_search_queries(company: str, engines: Iterable[str] = ("yandex",)) -> tuple[SearchQuery, ...]:
    query_text = build_setka_search_query(company)
    if not query_text:
        return ()

    return tuple(
        SearchQuery(
            term=company.strip().lower() or "company",
            domain=SETKA_HOST,
            query=query_text,
            url=build_search_url(engine, query_text),
            engine=engine,
        )
        for engine in _normalize_search_engines(engines)
    )


def collect_setka_people(
    company: str,
    config: AutoConfig,
    log: LogFn | None = None,
    fetcher: RenderFetcher | None = None,
    on_progress: Callable[[CollectionResult], None] | None = None,
) -> CollectionResult:
    if not company.strip():
        return CollectionResult(warnings=("Setka source enabled, but company name is empty.",))

    queries = build_setka_search_queries(company, config.search_engines)
    if not queries:
        return CollectionResult(warnings=("Setka source enabled, but no search query could be built.",))

    warnings: list[str] = []
    visited: list[str] = []
    skipped: list[str] = []
    people: list[Person] = []
    person_sources: list[PersonSourceRecord] = []
    member_pages_attempted = 0
    listing_pages_attempted = 0
    max_member_pages = config.setka_max_pages
    owned_fetcher: PlaywrightFetchTransport | None = None
    if fetcher is None:
        try:
            setka_config = replace(
                config,
                request_delay_seconds=max(config.request_delay_seconds, SETKA_MIN_DELAY_SECONDS),
            )
            owned_fetcher = PlaywrightFetchTransport(setka_config)
            fetcher = owned_fetcher
        except PlaywrightUnavailableError as error:
            if log:
                log(str(error))
            return CollectionResult(warnings=(str(error),))

    if log:
        log(f"setka search started: company={company!r}")
        log(f"setka request delay: {max(config.request_delay_seconds, SETKA_MIN_DELAY_SECONDS):g} seconds")

    try:
        fetched, fetch_warnings = fetch_search_pages(queries, config, log=log, fetcher=fetcher)  # type: ignore[arg-type]
        warnings.extend(fetch_warnings)
        company_pages = _company_network_pages_from_search(fetched)
        if log:
            log(f"setka search results parsed: company_pages={len(company_pages)}")
        if not company_pages:
            warnings.append("Setka company networks page was not found in search results.")

        page_counter = 0
        for networks_url in company_pages:
            if max_member_pages is not None and (
                member_pages_attempted >= max_member_pages
                or listing_pages_attempted >= max_member_pages
            ):
                break
            listing_pages_attempted += 1
            html = _fetch_rendered_html(networks_url, config, warnings, fetcher)
            if html is None:
                skipped.append(networks_url)
                continue
            _save_setka_html(networks_url, html, config.browser_pages_dir, page_counter, log)
            page_counter += 1
            if not setka_company_page_matches(company, html):
                identity = extract_setka_company_identity(html) or "unknown"
                warning = (
                    "Skipped Setka company page because it looks like another company: "
                    f"expected {company!r}, page {identity!r}, url {networks_url}"
                )
                warnings.append(warning)
                skipped.append(networks_url)
                if log:
                    log(f"setka company page skipped: url={networks_url} expected={company!r} page={identity!r}")
                continue
            visited.append(networks_url)
            if log:
                log(f"setka company groups page: url={networks_url}")

            network_html_parts = [html]
            load_more_urls = list(extract_setka_network_load_more_urls(html, networks_url))
            loaded_more_urls: set[str] = set()
            remaining = max_member_pages - member_pages_attempted if max_member_pages is not None else None
            while (
                load_more_urls
                and len(loaded_more_urls) < max(config.max_pages, 1)
                and (max_member_pages is None or listing_pages_attempted < max_member_pages)
                and (remaining is None or len(extract_setka_network_ids("\n".join(network_html_parts))) < remaining)
            ):
                load_more_url = load_more_urls.pop(0)
                if load_more_url in loaded_more_urls:
                    continue
                loaded_more_urls.add(load_more_url)
                listing_pages_attempted += 1
                load_more_html = _fetch_rendered_html(load_more_url, config, warnings, fetcher)
                if load_more_html is None:
                    skipped.append(load_more_url)
                    continue
                visited.append(load_more_url)
                _save_setka_html(load_more_url, load_more_html, config.browser_pages_dir, page_counter, log)
                page_counter += 1
                network_html_parts.append(load_more_html)
                if log:
                    log(f"setka networks load-more fetched: url={load_more_url}")
                for next_url in extract_setka_network_load_more_urls(load_more_html, load_more_url):
                    if next_url not in loaded_more_urls and next_url not in load_more_urls:
                        load_more_urls.append(next_url)

            if load_more_urls and (remaining is None or len(extract_setka_network_ids("\n".join(network_html_parts))) < remaining):
                if max_member_pages is not None and listing_pages_attempted >= max_member_pages:
                    if log:
                        log(f"setka listing page limit reached: {max_member_pages}")
                else:
                    warnings.append(f"Stopped Setka network load-more after {len(loaded_more_urls)} pages for {networks_url}")

            network_ids = extract_setka_network_ids("\n".join(network_html_parts))
            if log:
                log(f"setka networks parsed: url={networks_url} networks={len(network_ids)}")
            if not network_ids:
                warnings.append(f"No Setka network identifiers found at {networks_url}")

            for index, network_id in enumerate(network_ids, start=1):
                if max_member_pages is not None and member_pages_attempted >= max_member_pages:
                    break
                members_url = build_setka_members_url(network_id)
                member_pages_attempted += 1
                member_html = _fetch_rendered_html(members_url, config, warnings, fetcher)
                if member_html is None:
                    skipped.append(members_url)
                    continue
                visited.append(members_url)
                saved_page = _save_setka_html(members_url, member_html, config.browser_pages_dir, page_counter, log)
                page_counter += 1

                page_people = extract_setka_people(member_html)
                for person in page_people:
                    person_sources.append(PersonSourceRecord(person, "setka", members_url, str(saved_page)))
                    key = _person_key(person)
                    if key not in {_person_key(item) for item in people}:
                        people.append(person)
                if on_progress and page_people:
                    on_progress(CollectionResult(
                        people=tuple(people),
                        person_sources=tuple(dict.fromkeys(person_sources)),
                    ))
                if log:
                    log(
                        f"setka members parsed: index={index}/{len(network_ids)} "
                        f"url={members_url} people={len(page_people)}"
                    )
    except _SetkaRateLimited as error:
        skipped.append(error.url)
        if log:
            log(f"setka rate limited: url={error.url}; stopping source and keeping collected people")
    finally:
        if owned_fetcher:
            owned_fetcher.close()

    if log:
        if max_member_pages is not None and member_pages_attempted >= max_member_pages:
            log(f"setka member page limit reached: {max_member_pages}")
        log(f"setka search finished; pages={len(visited)}, people={len(people)}, skipped={len(skipped)}")

    return CollectionResult(
        people=tuple(people),
        person_sources=tuple(dict.fromkeys(person_sources)),
        visited_urls=tuple(visited),
        skipped_urls=tuple(skipped),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def is_setka_company_networks_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(normalize_url(url))
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == SETKA_HOST
        and re.fullmatch(r"/companies/[^/]+/networks/?", parsed.path or "") is not None
    )


def extract_setka_company_identity(html: str) -> str:
    parser = _SetkaCompanyIdentityParser()
    parser.feed(html)

    values: list[str] = []
    for part in parser.parts:
        cleaned = re.sub(r"\s+", " ", unescape(part)).strip()
        if cleaned and cleaned not in values:
            values.append(cleaned)
    return " | ".join(values[:4])


def setka_company_page_matches(company: str, html: str) -> bool:
    tokens = _company_tokens(company)
    if not tokens:
        return True

    identity = extract_setka_company_identity(html)
    if not identity:
        return False

    haystack = f" {_normalize_company_text(identity)} "
    return any(f" {token} " in haystack for token in tokens)


def extract_setka_network_ids(html: str) -> tuple[str, ...]:
    normalized_html = unescape(html)
    ids: list[str] = []
    for raw_id in EVENT_LABEL_RE.findall(normalized_html):
        _append_network_id(ids, raw_id, strict=True)
    for raw_id in NETWORK_ID_RE.findall(normalized_html):
        _append_network_id(ids, raw_id, strict=False)
    return tuple(ids)


def extract_setka_network_load_more_urls(html: str, base_url: str) -> tuple[str, ...]:
    normalized_html = unescape(html)
    urls: list[str] = []
    for raw_url in NETWORKS_LOAD_MORE_RE.findall(normalized_html):
        url = urllib.parse.urljoin(base_url, raw_url.strip())
        if not _is_setka_networks_load_more_url(url):
            continue
        if url not in urls:
            urls.append(url)
    return tuple(urls)


def build_setka_members_url(network_id: str) -> str:
    escaped = urllib.parse.quote(network_id.strip(), safe="")
    return f"{SETKA_NETWORK_URL_BASE}/{escaped}/members"


def extract_setka_people(html: str) -> tuple[Person, ...]:
    parser = _HxSwapParser()
    parser.feed(html)

    people: list[Person] = []
    seen: set[tuple[str, str, str]] = set()
    for raw_name in parser.working_names:
        person = _person_from_setka_name(raw_name)
        if person is None:
            continue
        key = _person_key(person)
        if key not in seen:
            people.append(person)
            seen.add(key)
    if people or parser.working_section_seen:
        return tuple(people)

    for index, chunk in enumerate(parser.chunks):
        chunk_people: list[Person] = []
        nodes = parser.chunk_nodes[index] if index < len(parser.chunk_nodes) else ()
        for node in nodes:
            chunk_people.extend(extract_people(node))
        if not chunk_people:
            chunk_people.extend(extract_people(chunk))
        for person in chunk_people:
            key = _person_key(person)
            if key not in seen:
                people.append(person)
                seen.add(key)
    return tuple(people)


def _is_setka_member_link(attrs: dict[str, str]) -> bool:
    href = attrs.get("href", "")
    hx_get = attrs.get("hx-get", "")
    classes = set(attrs.get("class", "").split())
    return (
        "/users/" in href
        or "/users/" in hx_get
        or "subtitle-2-semibold" in classes
    )


def _person_from_setka_name(value: str) -> Person | None:
    words = NAME_TOKEN_RE.findall(unescape(value))
    if len(words) < 2:
        return None
    firstname = words[0].strip()
    lastname = words[1].strip()
    patronymic = words[2].strip() if len(words) >= 3 and _looks_like_patronymic(words[2]) else ""
    if not firstname or not lastname:
        return None
    return Person(firstname=firstname, lastname=lastname, patronymic=patronymic)


def _looks_like_patronymic(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith(("вич", "ич", "вна", "ична", "инична", "оглы", "кызы"))


def _company_tokens(company: str) -> tuple[str, ...]:
    normalized = _normalize_company_text(company)
    tokens: list[str] = []
    for token in normalized.split():
        if len(token) < 2 or token in COMPANY_STOP_WORDS:
            continue
        if token not in tokens:
            tokens.append(token)
    return tuple(tokens)


def _normalize_company_text(value: str) -> str:
    normalized = unescape(value).lower().replace("ё", "е")
    normalized = re.sub(r"[^\w]+", " ", normalized, flags=re.UNICODE)
    return re.sub(r"\s+", " ", normalized).strip()


def _append_network_id(ids: list[str], raw_id: str, *, strict: bool) -> None:
    network_id = raw_id.strip()
    if not network_id:
        return
    if network_id in {"load-more"}:
        return
    if strict and not _looks_like_setka_network_id(network_id):
        return
    if network_id not in ids:
        ids.append(network_id)


def _looks_like_setka_network_id(value: str) -> bool:
    return len(value) >= 16 and re.fullmatch(r"[a-zA-Z0-9_-]+", value) is not None


def _is_setka_networks_load_more_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(normalize_url(url))
    return (
        parsed.scheme == "https"
        and (parsed.hostname or "").lower() == SETKA_HOST
        and re.fullmatch(r"/companies/[^/]+/networks/load-more/[^/]+/?", parsed.path or "") is not None
    )


def _company_network_pages_from_search(fetched) -> tuple[str, ...]:
    urls: list[str] = []
    for record in fetched:
        if record.captcha_detected or not record.path.exists():
            continue
        html = record.path.read_text(encoding="utf-8", errors="replace")
        for url in parse_search_result_links(html, engine=record.query.engine):
            if is_setka_company_networks_url(url) and url not in urls:
                urls.append(url)
    return tuple(urls)


def _fetch_rendered_html(
    url: str,
    config: AutoConfig,
    warnings: list[str],
    fetcher: RenderFetcher,
) -> str | None:
    try:
        response = fetcher.fetch_rendered_html(url)
    except PlaywrightFetchTimeoutError:
        warnings.append(f"Setka fetch timed out for {url}")
        return None
    except PlaywrightFetchError as error:
        warnings.append(f"Setka fetch failed for {url}: {error}")
        return None

    if response.status_code == 429:
        warnings.append(f"HTTP 429 while fetching Setka page {url}")
        raise _SetkaRateLimited(url)
    if response.status_code >= 400:
        warnings.append(f"HTTP {response.status_code} while fetching Setka page {url}")
        return None
    if not _is_html_content_type(response.content_type):
        warnings.append(f"Skipped non-HTML Setka page at {url}: {response.content_type or 'unknown content type'}")
        return None
    return response.body


def _save_setka_html(url: str, html: str, root: Path, index: int, log: LogFn | None) -> Path:
    directory = root / "setka"
    directory.mkdir(parents=True, exist_ok=True)
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.strip("/").replace("/", "-") or "index"
    destination = _unique_path(directory / f"{index + 1:03d}-{_safe_filename(path)}.html")
    destination.write_text(html, encoding="utf-8", errors="replace")
    if log:
        log(f"setka html saved: {destination}")
    return destination


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


def _is_html_content_type(content_type: str) -> bool:
    if not content_type:
        return True
    normalized = content_type.lower()
    return "text/html" in normalized or "application/xhtml+xml" in normalized


def _person_key(person: Person) -> tuple[str, str, str]:
    return (person.firstname.lower(), person.lastname.lower(), person.patronymic.lower())


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
