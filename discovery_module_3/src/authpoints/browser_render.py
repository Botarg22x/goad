"""Capture the post-JavaScript DOM of scoped login candidates.

This is a discovery step only: it never submits a form or follows a POST.
"""

from __future__ import annotations

import json
import ipaddress
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urljoin, urlsplit

from .browser_diagnostics import diagnostic_url, save_browser_diagnostics
from .classifier import classify_web
from .config import (
    KatanaConfig, validate_browser_resource_domain, validate_proxy_url, validate_user_agent,
)
from .normalize import is_logout_url
from .models import Issue, Source, WebObservation
from .parsers.html import parse_html
from .runners.common import ToolError
from .runners.katana import KatanaPartialError, resolve_system_chromium
from .scope import Scope


_LOGIN_MODE_LABEL = re.compile(
    r"^\s*(?:sign\s*in|log\s*in|sign\s*in\s+with\s+password|"
    r"log\s*in\s+with\s+password|use(?:\s+your)?\s+password|"
    r"i\s+already\s+have\s+an?\s+account|already\s+have\s+an?\s+account\??|"
    r"у\s+меня\s+уже\s+есть\s+аккаунт|уже\s+есть\s+аккаунт\??|"
    r"войти|вход|вход\s+по\s+паролю)\s*$",
    re.IGNORECASE,
)
_OTP_SEND_PATH = re.compile(
    r"(?:send|resend|request|issue)[/_-]?(?:email[/_-]?)?(?:otp|code|magic|email)|"
    r"(?:otp|code|magic)[/_-]?(?:send|resend|request)",
    re.IGNORECASE,
)
_PASSIVE_RESOURCE_TYPES = {"script", "stylesheet", "font", "image"}
_MAX_AUTO_RESOURCE_HOSTS = 32
_MAX_AUTO_RESOURCE_REQUESTS = 128


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        # Handle redirects ourselves: Playwright cannot intercept the second
        # hop after route.fulfill(3xx), so Chromium would lose the custom CA.
        return None


def _fetch_with_ca(
    request,
    *,
    opener: urllib.request.OpenerDirector,
    timeout_seconds: int,
    max_response_bytes: int,
    scope: Scope,
    resource_hosts: set[str],
    auto_resource_hosts: set[str],
    auto_resource_count: list[int],
) -> tuple[int, dict[str, str], bytes, str]:
    blocked_headers = {
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-authorization",
        "proxy-connection",
        "accept-encoding",
    }
    base_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in blocked_headers and not key.startswith(":")
    }
    base_headers["Accept-Encoding"] = "identity"
    current_url = request.url
    method = request.method
    seen: set[str] = set()
    for redirect_count in range(6):
        if current_url in seen:
            raise ToolError("browser redirect loop")
        seen.add(current_url)
        headers = base_headers
        if not scope.allows_url(current_url):
            headers = {
                key: value for key, value in base_headers.items()
                if key.lower() not in {"cookie", "authorization", "referer"}
            }
        outbound = urllib.request.Request(current_url, headers=headers, method=method)
        try:
            response = opener.open(outbound, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            status = int(response.code)
            location = response.headers.get("Location")
            if status in {301, 302, 303, 307, 308} and location:
                if redirect_count == 5:
                    raise ToolError("browser redirect limit exceeded")
                try:
                    next_url = urljoin(current_url, location)
                    next_request = SimpleNamespace(
                        method="GET" if status == 303 else method,
                        url=next_url,
                        resource_type=request.resource_type,
                    )
                    reason = _request_block_reason(next_request, scope, resource_hosts)
                    if not reason:
                        reason = _consume_auto_resource_budget(
                            next_request, scope, resource_hosts,
                            auto_resource_hosts, auto_resource_count,
                        )
                except ValueError as exc:
                    raise ToolError("invalid browser redirect target") from exc
                if reason:
                    raise ToolError(f"browser redirect blocked: {reason}")
                current_url = next_url
                if status == 303:
                    method = "GET"
                continue
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise ToolError("browser resource exceeded the response size limit")
            response_headers = {
                key: value for key, value in response.headers.items()
                if key.lower() not in {"content-length", "transfer-encoding", "connection"}
            }
            return status, response_headers, body, current_url
    raise ToolError("browser redirect limit exceeded")


def _url_block_reason(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or parts.username or parts.password:
            return "unsupported_url"
        if _OTP_SEND_PATH.search(unquote(parts.path + "?" + parts.query)):
            return "otp_or_email_send"
        if is_logout_url(url):
            return "logout_url"
    except ValueError:
        return "unsupported_url"
    return ""


def _request_block_reason(
    request, scope: Scope, resource_hosts: set[str],
) -> str:
    if request.method not in {"GET", "HEAD"}:
        return "non_read_only_method"
    reason = _url_block_reason(request.url)
    if reason:
        return reason
    parts = urlsplit(request.url)
    if scope.allows_url(request.url):
        return ""
    host = (parts.hostname or "").lower().rstrip(".")
    if request.resource_type in _PASSIVE_RESOURCE_TYPES and (
        host in resource_hosts or _auto_resource_host_allowed(host)
    ):
        return ""
    return "outside_scope"


def _auto_resource_host_allowed(host: str) -> bool:
    """Allow public DNS asset hosts, never local names or IP literals."""

    if not host or "." not in host or host.endswith((".local", ".localhost", ".internal")):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            return validate_browser_resource_domain(host) == host
        except ValueError:
            return False
    else:
        return False


def _consume_auto_resource_budget(
    request, scope: Scope, resource_hosts: set[str],
    auto_hosts: set[str], request_count: list[int],
) -> str:
    """Bound automatic third-party asset traffic, including redirect hops."""

    if scope.allows_url(request.url) or request.resource_type not in _PASSIVE_RESOURCE_TYPES:
        return ""
    try:
        host = (urlsplit(request.url).hostname or "").lower().rstrip(".")
    except ValueError:
        return "outside_scope"
    if host in resource_hosts or not _auto_resource_host_allowed(host):
        return ""
    if host not in auto_hosts and len(auto_hosts) >= _MAX_AUTO_RESOURCE_HOSTS:
        return "external_asset_host_limit"
    if request_count[0] >= _MAX_AUTO_RESOURCE_REQUESTS:
        return "external_asset_request_limit"
    auto_hosts.add(host)
    request_count[0] += 1
    return ""


def _resource_hosts(config: KatanaConfig) -> set[str]:
    result: set[str] = set()
    for value in config.browser_resource_domains:
        try:
            result.add(validate_browser_resource_domain(value))
        except ValueError as exc:
            raise ToolError("invalid browser resource domain") from exc
    return result


def _click_login_mode(
    page, clicked: set[str], *, scope: Scope, same_page_only: bool = False,
) -> dict[str, str] | None:
    """Open a visible login/password mode without submitting a form."""

    for role in ("button", "link"):
        candidates = page.get_by_role(role, name=_LOGIN_MODE_LABEL)
        for index in range(min(candidates.count(), 4)):
            candidate = candidates.nth(index)
            if not candidate.is_visible() or not candidate.is_enabled():
                continue
            label = (
                candidate.get_attribute("aria-label") or candidate.inner_text(timeout=1000)
            ).strip().casefold()
            if not label or label in clicked:
                continue
            if candidate.evaluate(
                "element => (!!element.form && ['submit', 'reset'].includes(element.type)) || "
                "element.getAttribute('aria-disabled') === 'true'"
            ):
                continue
            target = ""
            href = candidate.get_attribute("href")
            if role == "link" or href is not None:
                href = (href or "").strip()
                if href and not href.startswith("#"):
                    try:
                        target = urljoin(page.url, href)
                    except ValueError:
                        continue
                    if not scope.allows_url(target):
                        continue
                    if same_page_only and target.split("#", 1)[0] != page.url.split("#", 1)[0]:
                        continue
                    if _url_block_reason(target):
                        continue
            clicked.add(label)
            candidate.click(timeout=1500)
            return {"label": label, "target": diagnostic_url(target) if target else ""}
    return None


def _visible_login_form(page) -> bool:
    """Classify only forms containing a visible password input.

    A landing page may show a registration form with a new-password field
    while the actual sign-in control is elsewhere on the same page.
    """

    passwords = page.locator("input[type='password']:visible:enabled")
    for index in range(min(passwords.count(), 8)):
        markup = passwords.nth(index).evaluate(
            "input => input.closest('form')?.outerHTML || ''"
        )
        if not markup:
            continue
        _, _, forms, _ = parse_html(markup, page.url)
        observation = WebObservation(
            url=page.url,
            source=Source.KATANA,
            status_code=200,
            title=page.title(),
            forms=forms,
        )
        if any(finding.auth_type == "password_form" for finding in classify_web(observation)):
            return True
    return False


def _wait_for_login_dom(page, *, timeout_ms: int) -> None:
    """Wait for a login form after a click, even if signup stays visible."""

    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if _visible_login_form(page):
            return
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms > 0:
            page.wait_for_timeout(min(200, remaining_ms))


def render_pages(
    urls: Sequence[str],
    *,
    config: KatanaConfig,
    scope: Scope,
    same_page_only: bool = False,
) -> str:
    """Return Katana-compatible JSONL containing rendered HTML snapshots."""

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ToolError(
            "browser DOM capture requires Playwright; install pointfinder[browser]"
        ) from exc

    executable: Path | None
    if config.chrome_executable:
        executable = Path(config.chrome_executable).expanduser().resolve()
        if not executable.is_file():
            raise ToolError(f"Chrome executable not found: {executable}")
    else:
        executable = resolve_system_chromium()

    launch_options: dict[str, object] = {"headless": True}
    if executable is not None:
        launch_options["executable_path"] = str(executable)
    proxy = validate_proxy_url(config.proxy)
    if proxy:
        launch_options["proxy"] = {"server": proxy}
    else:
        launch_options["args"] = ["--no-proxy-server"]

    opener = None
    if config.ca_cert:
        try:
            ssl_context = ssl.create_default_context(cafile=config.ca_cert)
        except (OSError, ssl.SSLError) as exc:
            raise ToolError(f"invalid CA certificate for browser capture: {exc}") from exc
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
            urllib.request.HTTPSHandler(context=ssl_context),
            _NoRedirectHandler(),
        )
    # Explicit external assets are fulfilled by a separate HTTP client even
    # without a custom CA: Chromium ignores attempts to override Cookie in
    # route.continue_, so this is the reliable way to send no session headers.
    resource_context = (
        ssl._create_unverified_context() if proxy and not config.ca_cert
        else ssl.create_default_context()
    )
    resource_opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}),
        urllib.request.HTTPSHandler(context=resource_context),
        _NoRedirectHandler(),
    )

    resource_hosts = _resource_hosts(config)
    records: list[str] = []
    issues: list[Issue] = []
    captured_dom = False
    route_errors: list[str] = []
    timeout_ms = min(config.auto_headless_timeout_seconds, config.timeout_seconds) * 1000
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_options, timeout=timeout_ms)
            try:
                context = browser.new_context(
                    user_agent=validate_user_agent(config.user_agent),
                    service_workers="block",
                    ignore_https_errors=bool(proxy and not config.ca_cert),
                )
                try:
                    # The same read-only policy applies before and after a
                    # login opener is clicked; lazy modal GETs remain usable.
                    blocked_requests: list[dict[str, str]] = []
                    blocked_keys: set[tuple[str, str]] = set()
                    blocked_hosts: set[str] = set()
                    auto_resource_hosts: set[str] = set()
                    auto_resource_count = [0]
                    blocked_count = 0
                    network_errors: list[dict[str, str]] = []
                    network_error_count = 0
                    network_error_keys: set[tuple[str, str]] = set()
                    cached_documents: dict[str, tuple[int, dict[str, str], bytes]] = {}
                    redirected_documents: dict[str, str] = {}
                    current_document_url = ""

                    def record_network_error(request, category: str) -> None:
                        nonlocal network_error_count
                        key = (request.method, request.url)
                        if key in network_error_keys:
                            return
                        network_error_keys.add(key)
                        network_error_count += 1
                        if len(network_errors) < 20:
                            network_errors.append({
                                "url": diagnostic_url(request.url), "category": category,
                            })

                    def route_request(route) -> None:
                        nonlocal blocked_count
                        request = route.request
                        reason = _request_block_reason(
                            request, scope, resource_hosts,
                        )
                        if not reason:
                            reason = _consume_auto_resource_budget(
                                request, scope, resource_hosts,
                                auto_resource_hosts, auto_resource_count,
                            )
                        try:
                            asset_host = (urlsplit(request.url).hostname or "").lower().rstrip(".")
                        except ValueError:
                            asset_host = ""
                        if (
                            same_page_only and current_document_url
                            and request.resource_type == "document"
                            and request.url.split("#", 1)[0] != current_document_url.split("#", 1)[0]
                        ):
                            reason = "page_only_navigation"
                        if reason:
                            blocked_count += 1
                            blocked_keys.add((request.method, request.url))
                            if reason == "outside_scope":
                                host = urlsplit(request.url).hostname
                                if host:
                                    blocked_hosts.add(host.lower().rstrip("."))
                            elif reason.startswith("external_asset_") and asset_host:
                                blocked_hosts.add(asset_host)
                            if len(blocked_requests) < 100:
                                blocked_requests.append({
                                    "url": diagnostic_url(request.url),
                                    "method": request.method,
                                    "resource_type": request.resource_type,
                                    "reason": reason,
                                })
                            route.abort()
                        elif opener is not None or not scope.allows_url(request.url):
                            try:
                                cached = (
                                    cached_documents.pop(request.url, None)
                                    if request.resource_type == "document" else None
                                )
                                if cached is not None:
                                    status, headers, body = cached
                                    final_url = request.url
                                else:
                                    status, headers, body, final_url = _fetch_with_ca(
                                        request,
                                        opener=opener or resource_opener,
                                        timeout_seconds=config.request_timeout_seconds,
                                        max_response_bytes=max(
                                            config.max_response_bytes,
                                            config.max_dom_bytes,
                                            8 * 1024 * 1024,
                                        ),
                                        scope=scope,
                                        resource_hosts=resource_hosts,
                                        auto_resource_hosts=auto_resource_hosts,
                                        auto_resource_count=auto_resource_count,
                                    )
                                if request.resource_type == "document" and final_url != request.url:
                                    # First finish the original navigation with an inert
                                    # page, then navigate to the verified final URL. Cache
                                    # the response so the second navigation makes no GET.
                                    cached_documents[final_url] = (status, headers, body)
                                    redirected_documents[request.url] = final_url
                                    route.fulfill(
                                        status=200,
                                        content_type="text/html",
                                        body="<html></html>",
                                    )
                                else:
                                    route.fulfill(status=status, headers=headers, body=body)
                            except (OSError, PlaywrightError, ToolError) as exc:
                                if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                                    category = "CERTIFICATE_VERIFY_FAILED"
                                elif isinstance(exc, ToolError) and str(exc).startswith(
                                    "browser redirect blocked:"
                                ):
                                    category = "redirect_" + str(exc).split(": ", 1)[1]
                                else:
                                    category = "browser_resource_failed"
                                record_network_error(request, category)
                                if request.resource_type == "document":
                                    route_errors.append(category)
                                route.abort()
                        else:
                            route.continue_()

                    context.route("**/*", route_request)
                    if hasattr(context, "route_web_socket"):
                        def block_web_socket(web_socket) -> None:
                            nonlocal blocked_count
                            blocked_count += 1
                            host = urlsplit(web_socket.url).hostname
                            if host and not scope.allows_host(host):
                                blocked_hosts.add(host.lower().rstrip("."))
                            if len(blocked_requests) < 100:
                                blocked_requests.append({
                                    "url": diagnostic_url(web_socket.url),
                                    "method": "GET",
                                    "resource_type": "websocket",
                                    "reason": "unsupported_transport",
                                })
                            web_socket.close()

                        context.route_web_socket("**/*", block_web_socket)
                        blocked_apis = ["WebTransport"]
                    else:
                        blocked_apis = ["WebSocket", "WebTransport"]
                    context.add_init_script(
                        "(() => { for (const api of " + json.dumps(blocked_apis) + ") {"
                        "if (api in window) Object.defineProperty(window, api, {value: class {"
                        "constructor() {throw new DOMException('Transport disabled during read-only discovery');}"
                        "}}); } })()"
                    )
                    for url in urls:
                        current_document_url = ""
                        if not scope.allows_url(url):
                            raise ToolError("browser candidate is outside the allowed scope")
                        route_errors.clear()
                        blocked_requests.clear()
                        blocked_keys.clear()
                        blocked_hosts.clear()
                        auto_resource_hosts.clear()
                        auto_resource_count[0] = 0
                        network_errors.clear()
                        network_error_keys.clear()
                        network_error_count = 0
                        blocked_count = 0
                        cached_documents.clear()
                        redirected_documents.clear()
                        page = context.new_page()
                        page_records: list[dict[str, object]] = []
                        snapshots: list[str] = []
                        clicks: list[dict[str, str]] = []
                        status_code = None
                        password_field_found = False
                        login_form_found = False
                        failure = ""

                        def request_failed(request) -> None:
                            if (request.method, request.url) not in blocked_keys:
                                record_network_error(request, "request_failed")

                        def document_response(response) -> None:
                            nonlocal status_code
                            if (
                                response.request.resource_type == "document"
                                and response.request.frame == page.main_frame
                            ):
                                status_code = response.status

                        page.on("requestfailed", request_failed)
                        page.on("response", document_response)
                        try:
                            deadline = time.monotonic() + timeout_ms / 1000
                            response = page.goto(
                                url,
                                wait_until="domcontentloaded",
                                timeout=timeout_ms,
                            )
                            status_code = response.status if response else None
                            redirect_url = redirected_documents.pop(url, None)
                            if redirect_url:
                                response = page.goto(
                                    redirect_url,
                                    wait_until="domcontentloaded",
                                    timeout=max(1, int((deadline - time.monotonic()) * 1000)),
                                )
                                status_code = response.status if response else None
                            current_document_url = page.url
                            if route_errors:
                                raise ToolError(f"browser resource failed: {route_errors[0]}")
                            if config.dom_wait_seconds:
                                page.wait_for_timeout(min(
                                    config.dom_wait_seconds * 1000,
                                    max(0, (deadline - time.monotonic()) * 1000),
                                ))
                            if route_errors:
                                raise ToolError(f"browser resource failed: {route_errors[0]}")
                            clicked: set[str] = set()
                            for step in range(3):
                                if not scope.allows_url(page.url):
                                    raise ToolError("browser navigation left the allowed scope")
                                body = page.content()
                                snapshots.append(body)
                                if len(body.encode("utf-8")) > config.max_dom_bytes:
                                    limit_mb = config.max_dom_bytes / (1024 * 1024)
                                    raise ToolError(
                                        "rendered DOM exceeded the "
                                        f"{limit_mb:g} MiB limit; increase "
                                        "--katana-max-dom-mb if this page is trusted"
                                    )
                                page_records.append({
                                    "request": {"method": "GET", "endpoint": page.url},
                                    "response": {
                                        "status_code": status_code,
                                        "headers": {"content-type": "text/html"},
                                        "body": body,
                                    },
                                })
                                captured_dom = True
                                password_field_found = bool(
                                    page.locator("input[type='password']:visible:enabled").count()
                                )
                                login_form_found = (
                                    _visible_login_form(page) if password_field_found else False
                                )
                                if step == 2 or login_form_found:
                                    break
                                try:
                                    changed = _click_login_mode(
                                        page, clicked, scope=scope,
                                        same_page_only=same_page_only,
                                    )
                                except PlaywrightError:
                                    failure = "login_opener_click_failed"
                                    issues.append(Issue(
                                        stage="katana_headless",
                                        target=diagnostic_url(url),
                                        message=(
                                            "Не удалось нажать кнопку входа; "
                                            "возможно, её перекрывает диалог или баннер cookies"
                                        ),
                                    ))
                                    break
                                if not changed:
                                    break
                                clicks.append(changed)
                                remaining_ms = int((deadline - time.monotonic()) * 1000)
                                if remaining_ms > 0:
                                    try:
                                        _wait_for_login_dom(page, timeout_ms=min(5000, remaining_ms))
                                    except PlaywrightError:
                                        # A legitimate opener may lead to an email-only
                                        # page. Capture it, but never press Continue.
                                        pass
                                if route_errors:
                                    raise ToolError(f"browser resource failed: {route_errors[0]}")
                        except (PlaywrightError, ToolError) as exc:
                            failure = route_errors[0] if route_errors else "browser_render_failed"
                            detail = str(exc) if isinstance(exc, ToolError) else "Chromium could not render the page"
                            if "ERR_CERT" in str(exc) or "certificate" in str(exc).lower():
                                detail = "Chromium rejected the HTTPS certificate"
                            if route_errors:
                                detail = (
                                    "Переход за пределы разрешённого домена остановлен"
                                    if route_errors[0] == "redirect_outside_scope"
                                    else f"browser resource failed: {route_errors[0]}"
                                )
                            issues.append(Issue(
                                stage="katana_headless", target=diagnostic_url(url), message=detail,
                            ))
                            if not snapshots:
                                try:
                                    snapshots.append(page.content())
                                except PlaywrightError:
                                    pass
                        finally:
                            metadata: dict[str, object] = {
                                "candidate_url": diagnostic_url(url),
                                "final_url": diagnostic_url(page.url),
                                "status_code": status_code,
                                "password_field_found": password_field_found,
                                "login_form_found": login_form_found,
                                "auto_resource_hosts": sorted(auto_resource_hosts),
                                "blocked_count": blocked_count,
                                "blocked_resource_hosts": sorted(blocked_hosts),
                                "blocked_requests": list(blocked_requests),
                                "network_error_count": network_error_count,
                                "network_errors": list(network_errors),
                                "click_count": len(clicks),
                                "clicks": clicks,
                            }
                            if failure:
                                metadata["failure"] = failure
                            metadata = save_browser_diagnostics(
                                config.browser_diagnostics_dir,
                                candidate_url=url,
                                snapshots=snapshots,
                                metadata=metadata,
                            )
                            if not page_records:
                                page_records.append({
                                    "request": {"method": "GET", "endpoint": url},
                                    "response": {
                                        "status_code": status_code,
                                        "headers": {"content-type": "text/html"},
                                        "body": "",
                                    },
                                })
                            page_records[-1]["discovery_diagnostics"] = metadata
                            records.extend(json.dumps(item, ensure_ascii=False) for item in page_records)
                            page.close()
                finally:
                    context.close()
            finally:
                browser.close()
    except PlaywrightError as exc:
        if route_errors:
            raise ToolError(f"browser resource failed: {route_errors[0]}") from exc
        detail = "Chromium could not render the page"
        if "ERR_CERT" in str(exc) or "certificate" in str(exc).lower():
            detail += "; the browser rejected the HTTPS certificate"
        raise ToolError(detail) from exc
    output = "\n".join(records)
    if issues:
        if len(urls) == 1 and not captured_dom:
            raise ToolError(issues[0].message)
        raise KatanaPartialError(output, issues)
    return output
