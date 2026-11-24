from __future__ import annotations

import urllib.error
import urllib.request
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin

from .config import HttpConfig, validate_proxy_url, validate_user_agent
from .models import Issue, Source, WebObservation
from .normalize import (
    is_logout_url, normalize_url,
)
from .parsers.html import parse_html
from .scope import Scope


_SAFE_HEADERS = {
    "content-type",
    "cf-mitigated",
    "location",
    "www-authenticate",
    "proxy-authenticate",
}


@dataclass(slots=True)
class ProbeResult:
    observation: WebObservation | None = None
    issue: Issue | None = None
    requested_url: str = ""


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(
        self, scope: Scope, max_redirects: int,
    ) -> None:
        super().__init__()
        self.scope = scope
        self.max_redirects = max_redirects
        self.redirects: list[str] = []
        self.blocked_redirect = ""

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        target = urljoin(req.full_url, newurl)
        if is_logout_url(target):
            self.blocked_redirect = normalize_url(target)
            return None
        if len(self.redirects) >= self.max_redirects or not self.scope.allows_url(target):
            try:
                self.blocked_redirect = normalize_url(target)
            except ValueError:
                self.blocked_redirect = ""
            return None
        transport_target = normalize_url(target, redact_query=False)
        self.redirects.append(normalize_url(target))
        return super().redirect_request(req, fp, code, msg, headers, transport_target)


def probe_urls(
    urls: list[str],
    scope: Scope,
    config: HttpConfig,
    *,
    on_progress: Callable[[str], None] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> list[ProbeResult]:
    unique = list(dict.fromkeys(urls))
    if not unique:
        return []
    if config.request_delay_seconds < 0:
        raise ValueError("HTTP request delay must not be negative")
    _emit(on_progress, f"[HTTP] Начало проверки: {len(unique)} URL")
    results: list[ProbeResult] = []
    with ThreadPoolExecutor(
        max_workers=config.concurrency,
        thread_name_prefix="authpoints-http",
    ) as pool:
        futures = {}
        for index, url in enumerate(unique):
            if index and config.request_delay_seconds:
                sleeper(config.request_delay_seconds)
            _emit(on_progress, f"[HTTP] GET {_display_url(url)}")
            futures[pool.submit(_probe_one, url, scope, config)] = url
        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # defensive isolation between targets
                result = ProbeResult(
                    issue=Issue(
                        stage="http",
                        target=_display_url(url),
                        message=f"unexpected probe error: {exc}",
                    )
                )
            result.requested_url = url
            results.append(result)
            if result.observation is not None:
                status = result.observation.status_code
                _emit(
                    on_progress,
                    f"[HTTP] Ответ {status if status is not None else '?'} "
                    f"{result.observation.url}",
                )
            if result.issue is not None:
                _emit(
                    on_progress,
                    f"[ERROR] HTTP {result.issue.target or _display_url(url)}: "
                    f"{result.issue.message}",
                )
    _emit(on_progress, f"[HTTP] Проверка завершена: {len(results)} URL")
    return results


def _display_url(url: str) -> str:
    try:
        return normalize_url(url)
    except ValueError:
        return "<некорректный URL>"


def _emit(callback: Callable[[str], None] | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _probe_one(url: str, scope: Scope, config: HttpConfig) -> ProbeResult:
    try:
        transport_url = normalize_url(url, redact_query=False)
        proxy = validate_proxy_url(config.proxy)
    except ValueError as exc:
        return ProbeResult(issue=Issue(stage="http", target=url, message=str(exc)))
    report_url = normalize_url(transport_url)
    if is_logout_url(transport_url):
        return ProbeResult(
            issue=Issue(
                stage="http",
                target=report_url,
                message="request skipped for a logout URL",
            )
        )
    if not scope.allows_url(transport_url):
        return ProbeResult(
            issue=Issue(
                stage="scope",
                target=report_url,
                message="URL is outside the allowed scope",
            )
        )

    redirect_handler = _ScopedRedirectHandler(scope, config.max_redirects)
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    try:
        context = (
            ssl._create_unverified_context()
            if config.proxy and not config.ca_cert
            else ssl.create_default_context(cafile=config.ca_cert or None)
        )
    except (OSError, ssl.SSLError) as exc:
        return ProbeResult(
            issue=Issue(stage="http", target=report_url, message=f"invalid CA certificate: {exc}")
        )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=context),
        redirect_handler,
    )
    request = urllib.request.Request(
        transport_url,
        method="GET",
        headers={
            "User-Agent": validate_user_agent(config.user_agent),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.5,*/*;q=0.1",
        },
    )
    response: object
    try:
        response = opener.open(request, timeout=config.timeout_seconds)
    except urllib.error.HTTPError as exc:
        response = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ProbeResult(issue=Issue(stage="http", target=report_url, message=str(exc)))

    with response:  # type: ignore[attr-defined]
        status_code = getattr(response, "status", None) or getattr(response, "code", None)
        response_headers = getattr(response, "headers", None)
        safe_headers: dict[str, str] = {}
        if response_headers is not None:
            for key in _SAFE_HEADERS:
                if key in {"www-authenticate", "proxy-authenticate"}:
                    values = response_headers.get_all(key, [])
                    if values:
                        safe_headers[key] = ", ".join(str(value) for value in values)[:1000]
                else:
                    value = response_headers.get(key)
                    if value:
                        safe_headers[key] = str(value)[:1000]
        body_bytes = response.read(config.max_response_bytes + 1)  # type: ignore[attr-defined]
        if len(body_bytes) > config.max_response_bytes:
            body_bytes = body_bytes[: config.max_response_bytes]
        charset = None
        if response_headers is not None:
            try:
                charset = response_headers.get_content_charset()
            except AttributeError:
                charset = None
        try:
            body = body_bytes.decode(charset or "utf-8", errors="replace")
        except LookupError:
            body = body_bytes.decode("utf-8", errors="replace")
        transport_final_url = normalize_url(
            response.geturl(), redact_query=False  # type: ignore[attr-defined]
        )
        final_url = normalize_url(transport_final_url)

    title = ""
    text = ""
    forms = []
    links = []
    content_type = safe_headers.get("content-type", "").lower()
    if "html" in content_type or "<html" in body[:2000].lower() or "<form" in body[:2000].lower():
        title, text, forms, links = parse_html(body, transport_final_url)
    location = safe_headers.get("location")
    if location:
        try:
            safe_headers["location"] = normalize_url(urljoin(final_url, location))
        except ValueError:
            safe_headers.pop("location", None)
    return ProbeResult(
        observation=WebObservation(
            url=final_url,
            source=Source.HTTP_PROBE,
            status_code=int(status_code) if status_code is not None else None,
            headers=safe_headers,
            title=title,
            text=text,
            body=body,
            forms=forms,
            links=links,
            redirects=redirect_handler.redirects,
            redirect_target=safe_headers.get("location", ""),
            blocked_redirect=redirect_handler.blocked_redirect,
        )
    )
