from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import AutoConfig


BLOCKED_STATUS_CODES = {401, 403}
RATE_LIMIT_STATUS_CODE = 429
PAGE_READY_STATE = "domcontentloaded"


def _is_certificate_hostname_mismatch(error: Exception) -> bool:
    message = str(error).lower()
    return any(
        marker in message
        for marker in (
            "hostname/ip does not match certificate's altnames",
            "err_tls_cert_altname_invalid",
            "err_cert_common_name_invalid",
        )
    )


class PlaywrightUnavailableError(RuntimeError):
    pass


class PlaywrightFetchError(RuntimeError):
    pass


class PlaywrightFetchTimeoutError(PlaywrightFetchError):
    pass


@dataclass(frozen=True)
class FetchResponse:
    url: str
    status_code: int
    body: str
    content_type: str = ""


@dataclass(frozen=True)
class FetchBinaryResponse:
    url: str
    status_code: int
    body: bytes
    content_type: str = ""
    tls_warning: str = ""


class PlaywrightFetchTransport:
    def __init__(self, config: AutoConfig) -> None:
        self._config = config
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as error:
            raise PlaywrightUnavailableError(
                "Playwright is not installed. Install it with: python -m pip install '.[browser]' "
                "and then run: python -m playwright install chromium"
            ) from error

        self._playwright_error = PlaywrightError
        self._playwright_timeout_error = PlaywrightTimeoutError
        # Playwright's APIRequestContext runs in the Node driver process.  Give
        # that child only the CA explicitly selected by the user; Chromium is
        # configured separately with verified SPKI pins below.
        with _node_extra_ca_environment(config.ca_cert):
            self._playwright = sync_playwright().start()
        request_options: dict[str, Any] = {
            "user_agent": config.user_agent,
            "extra_http_headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.7",
            },
        }
        if config.proxy_url:
            request_options["proxy"] = {"server": config.proxy_url}
            if config.ca_cert is None:
                request_options["ignore_https_errors"] = True
        self._request_options = request_options
        self._request_context = self._playwright.request.new_context(**request_options)
        self._pdf_unverified_request_context: Any | None = None
        self._browser: Any | None = None
        self._browser_context: Any | None = None
        self._browser_headless: bool | None = None
        self._browser_tls_pins: tuple[str, ...] = ()
        self._browser_tls_pin_cache: dict[tuple[str, str, int], tuple[str, ...]] = {}
        self._manual_page: Any | None = None
        self._closed = False
        self._request_clock = time.monotonic
        self._request_sleep = time.sleep
        self._last_request_started: float | None = None
        self._last_search_request_started: float | None = None

    def fetch_text(
        self,
        url: str,
        *,
        timeout_seconds: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResponse:
        self._wait_for_request_slot(url)
        try:
            response = self._request_context.get(
                url,
                headers=headers,
                timeout=(timeout_seconds or self._config.timeout_seconds) * 1000,
            )
        except self._playwright_timeout_error as error:
            raise PlaywrightFetchTimeoutError(str(error)) from error
        except self._playwright_error as error:
            raise PlaywrightFetchError(str(error)) from error

        content_type = response.headers.get("content-type", "")
        return FetchResponse(
            url=url,
            status_code=response.status,
            body=_decode_bytes(response.body(), _charset_from_content_type(content_type)),
            content_type=content_type,
        )

    def fetch_bytes(
        self,
        url: str,
        *,
        timeout_seconds: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchBinaryResponse:
        self._wait_for_request_slot(url)
        request_kwargs = {
            "headers": headers,
            "timeout": (timeout_seconds or self._config.timeout_seconds) * 1000,
        }
        tls_warning = ""
        try:
            response = self._request_context.get(url, **request_kwargs)
        except self._playwright_timeout_error as error:
            raise PlaywrightFetchTimeoutError(str(error)) from error
        except self._playwright_error as error:
            if not _is_certificate_hostname_mismatch(error):
                raise PlaywrightFetchError(str(error)) from error
            # Some public PDFs are hosted behind a certificate for another
            # hostname. Retry only this binary request, never HTML/search or
            # browser requests, and report that its TLS check was bypassed.
            try:
                if self._pdf_unverified_request_context is None:
                    self._pdf_unverified_request_context = self._playwright.request.new_context(
                        **self._request_options,
                        ignore_https_errors=True,
                    )
                response = self._pdf_unverified_request_context.get(url, **request_kwargs)
            except self._playwright_timeout_error as retry_error:
                raise PlaywrightFetchTimeoutError(str(retry_error)) from retry_error
            except self._playwright_error as retry_error:
                raise PlaywrightFetchError(
                    f"certificate hostname mismatch; PDF retry failed: {retry_error}"
                ) from retry_error
            tls_warning = f"PDF: сертификат не соответствует домену; повторный запрос без проверки TLS: {url}"

        return FetchBinaryResponse(
            url=url,
            status_code=response.status,
            body=response.body(),
            content_type=response.headers.get("content-type", ""),
            tls_warning=tls_warning,
        )

    def fetch_rendered_html(self, url: str) -> FetchResponse:
        self._ensure_browser(url=url)
        page = self._browser_context.new_page()
        try:
            response = self._goto_page(page, url)
        except self._playwright_error as error:
            raise PlaywrightFetchError(str(error)) from error
        finally:
            page.close()

        return response.to_fetch_response()

    def fetch_rendered_html_with_manual_access(
        self,
        url: str,
        *,
        prompt_stream=None,
        input_stream=None,
    ) -> FetchResponse:
        response = self._fetch_rendered_html_keep_page(url, headless=self._config.browser_headless)
        if response.status_code not in BLOCKED_STATUS_CODES:
            response.page.close()
            return response.to_fetch_response()

        if self._config.browser_headless:
            response.page.close()
            response = self._fetch_rendered_html_keep_page(url, headless=False)
            if response.status_code not in BLOCKED_STATUS_CODES:
                response.page.close()
                return response.to_fetch_response()

        prompt_stream = prompt_stream or sys.stderr
        input_stream = input_stream or sys.stdin
        print(
            f"[БРАУЗЕР] Сайт вернул HTTP {response.status_code}. Открыто окно браузера. "
            "Проверьте доступ в нём, затем нажмите Enter здесь.",
            file=prompt_stream,
        )
        if input_stream.isatty():
            input_stream.readline()
            try:
                response.page.wait_for_load_state(
                    PAGE_READY_STATE,
                    timeout=self._config.browser_timeout_seconds * 1000,
                )
            except (self._playwright_timeout_error, self._playwright_error):
                pass
            if self._config.browser_wait_ms:
                response.page.wait_for_timeout(self._config.browser_wait_ms)
            body = response.page.content()
            current_url = getattr(response.page, "url", None) or response.url
            response.page.close()
            return FetchResponse(
                url=current_url,
                status_code=200,
                body=body,
                content_type=response.content_type or "text/html",
            )

        print(
            "[БРАУЗЕР] Интерактивный ввод недоступен; заблокированная страница сохранена без изменений.",
            file=prompt_stream,
        )
        response.page.close()
        return response.to_fetch_response()

    def fetch_rendered_html_with_manual_captcha(
        self,
        url: str,
        captcha_detector: Callable[[str], bool],
        *,
        prompt_stream=None,
        input_stream=None,
    ) -> FetchResponse:
        response = self._fetch_rendered_html_keep_page(url, headless=self._config.browser_headless)
        if not captcha_detector(response.body):
            response.page.close()
            return response.to_fetch_response()

        response.page.close()
        response = self._fetch_rendered_html_keep_page(url, headless=False)
        if not captcha_detector(response.body):
            response.page.close()
            return response.to_fetch_response()

        prompt_stream = prompt_stream or sys.stderr
        input_stream = input_stream or sys.stdin
        print(
            "[БРАУЗЕР] Обнаружена SmartCaptcha Яндекса. Открыто окно браузера. "
            "Пройдите CAPTCHA в нём; после этого поиск продолжится автоматически.",
            file=prompt_stream,
        )
        response = self._wait_for_captcha_solution(response, captcha_detector, url, prompt_stream)

        response.page.close()
        return response.to_fetch_response()

    def fetch_rendered_html_in_manual_session(
        self,
        url: str,
        captcha_detector: Callable[[str], bool],
        *,
        prompt_stream=None,
        input_stream=None,
    ) -> FetchResponse:
        if self._manual_page is not None and not self._manual_page.is_closed():
            response = self._fetch_rendered_html_on_reusable_page(url)
        else:
            response = self._fetch_rendered_html_keep_page(url, headless=True)
            if (
                response.status_code != RATE_LIMIT_STATUS_CODE
                and not captcha_detector(response.body)
            ):
                response.page.close()
                return response.to_fetch_response()
            response.page.close()
            response = self._fetch_rendered_html_on_reusable_page(url)

        captcha_detected = captcha_detector(response.body)
        rate_limited = response.status_code == RATE_LIMIT_STATUS_CODE
        if not captcha_detected and not rate_limited:
            return response.to_fetch_response()

        prompt_stream = prompt_stream or sys.stderr
        input_stream = input_stream or sys.stdin
        if rate_limited and not captcha_detected:
            print(
                "[БРАУЗЕР] Поисковик вернул HTTP 429. Открыто окно браузера. "
                "Откройте или обновите результат поиска в нём, затем нажмите Enter здесь.",
                file=prompt_stream,
            )
            if not input_stream.isatty():
                print(
                    "[БРАУЗЕР] Интерактивный ввод недоступен; "
                    "оставшиеся запросы к этому поисковику остановлены.",
                    file=prompt_stream,
                )
                return response.to_fetch_response()
            input_stream.readline()
            refreshed = self._refresh_manual_page_response(url)
            if refreshed.body == response.body and refreshed.url == response.url:
                return response.to_fetch_response()
            return refreshed.to_fetch_response()

        print(
            "[БРАУЗЕР] Обнаружена SmartCaptcha Яндекса. Окно останется открытым до конца поиска. "
            "Пройдите CAPTCHA в нём; после этого поиск продолжится автоматически.",
            file=prompt_stream,
        )
        response = self._wait_for_captcha_solution(response, captcha_detector, url, prompt_stream)

        return response.to_fetch_response()

    def close(self) -> None:
        if self._closed:
            return
        # Mark the transport closed before talking to the driver.  During
        # Ctrl+C Playwright can terminate its driver first; cleanup calls then
        # raise a secondary "Connection closed" exception which would mask the
        # original KeyboardInterrupt and produce a misleading traceback.
        self._closed = True
        resources = (
            ("_manual_page", "close"),
            ("_browser_context", "close"),
            ("_browser", "close"),
            ("_pdf_unverified_request_context", "dispose"),
            ("_request_context", "dispose"),
            ("_playwright", "stop"),
        )
        for attribute, operation in resources:
            resource = getattr(self, attribute, None)
            if resource is None:
                continue
            try:
                getattr(resource, operation)()
            except Exception:
                # Cleanup is best-effort.  In particular it must not replace
                # KeyboardInterrupt or the actual collection error.
                pass
            finally:
                if attribute in {"_manual_page", "_browser_context", "_browser"}:
                    setattr(self, attribute, None)
        self._browser_headless = None

    def _ensure_browser(self, headless: bool | None = None, *, url: str | None = None) -> None:
        desired_headless = self._config.browser_headless if headless is None else headless
        tls_changed = self._add_browser_tls_pins(url)
        if (
            self._browser_context is not None
            and self._browser_headless == desired_headless
            and not tls_changed
        ):
            return
        if self._manual_page is not None:
            self._manual_page.close()
            self._manual_page = None
        if self._browser_context is not None:
            self._browser_context.close()
            self._browser_context = None
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        try:
            launch_options = _browser_launch_options(
                self._config,
                desired_headless,
                tls_pins=self._browser_tls_pins,
            )
            if self._config.browser_user_data_dir is not None:
                self._config.browser_user_data_dir.mkdir(parents=True, exist_ok=True)
                self._browser_context = self._playwright.chromium.launch_persistent_context(
                    str(self._config.browser_user_data_dir),
                    **launch_options,
                    **_browser_context_options(self._config),
                )
                self._browser = None
            else:
                self._browser = self._playwright.chromium.launch(**launch_options)
                self._browser_context = self._browser.new_context(**_browser_context_options(self._config))
            self._browser_headless = desired_headless
        except self._playwright_error as error:
            if self._browser_context is not None:
                self._browser_context.close()
                self._browser_context = None
            if self._browser is not None:
                self._browser.close()
                self._browser = None
            self._browser_headless = None
            raise PlaywrightFetchError(str(error)) from error

    def _add_browser_tls_pins(self, url: str | None) -> bool:
        if self._config.ca_cert is None or url is None:
            return False
        cache_key = _tls_cache_key(url)
        pins = self._browser_tls_pin_cache.get(cache_key)
        if pins is None:
            try:
                pins = _browser_tls_pins(
                    url,
                    ca_cert=self._config.ca_cert,
                    proxy=self._config.proxy_url or None,
                    timeout_seconds=min(float(self._config.browser_timeout_seconds), 30.0),
                )
            except ValueError as error:
                raise PlaywrightFetchError(str(error)) from error
            self._browser_tls_pin_cache[cache_key] = pins
        combined = tuple(dict.fromkeys((*self._browser_tls_pins, *pins)))
        if combined == self._browser_tls_pins:
            return False
        self._browser_tls_pins = combined
        return True

    def _fetch_rendered_html_keep_page(self, url: str, *, headless: bool) -> "_PageFetchResponse":
        self._ensure_browser(headless=headless, url=url)
        page = self._browser_context.new_page()
        try:
            return self._goto_page(page, url)
        except self._playwright_error as error:
            page.close()
            raise PlaywrightFetchError(str(error)) from error

    def _fetch_rendered_html_on_reusable_page(self, url: str) -> "_PageFetchResponse":
        self._ensure_browser(headless=False, url=url)
        if self._manual_page is None or self._manual_page.is_closed():
            self._manual_page = self._browser_context.new_page()
        return self._goto_existing_page(self._manual_page, url)

    def _refresh_manual_page_response(self, url: str) -> "_PageFetchResponse":
        if self._manual_page is None or self._manual_page.is_closed():
            return self._fetch_rendered_html_on_reusable_page(url)
        try:
            self._manual_page.wait_for_load_state(
                PAGE_READY_STATE,
                timeout=self._config.browser_timeout_seconds * 1000,
            )
        except (self._playwright_timeout_error, self._playwright_error):
            pass
        if self._config.browser_wait_ms:
            self._manual_page.wait_for_timeout(self._config.browser_wait_ms)
        body = self._read_page_content(self._manual_page)
        if self._manual_page.url == "about:blank":
            return self._goto_existing_page(self._manual_page, url)
        return _PageFetchResponse(
            url=url,
            status_code=200,
            body=body,
            content_type="text/html",
            page=self._manual_page,
        )

    def _wait_for_captcha_solution(
        self,
        response: "_PageFetchResponse",
        captcha_detector: Callable[[str], bool],
        url: str,
        prompt_stream,
    ) -> "_PageFetchResponse":
        wait_seconds = max(self._config.captcha_wait_seconds, 1)
        poll_ms = max(self._config.captcha_poll_seconds * 1000, 250)
        deadline = time.monotonic() + wait_seconds
        last_response = response

        while True:
            last_response = self._try_open_page_response(response.page, url, response.content_type) or last_response
            if not captcha_detector(last_response.body):
                print("[БРАУЗЕР] CAPTCHA пройдена; продолжаю поиск.", file=prompt_stream)
                return last_response
            if time.monotonic() >= deadline:
                print(
                    f"[БРАУЗЕР] CAPTCHA не пройдена за {wait_seconds} с; "
                    "страница сохранена без изменений.",
                    file=prompt_stream,
                )
                return last_response
            try:
                response.page.wait_for_timeout(poll_ms)
            except (self._playwright_timeout_error, self._playwright_error):
                time.sleep(min(poll_ms / 1000, 1))

    def _try_open_page_response(
        self,
        page: Any,
        url: str,
        content_type: str = "text/html",
    ) -> "_PageFetchResponse | None":
        try:
            return self._open_page_response(page, url, content_type)
        except PlaywrightFetchError:
            return None

    def _open_page_response(self, page: Any, url: str, content_type: str = "text/html") -> "_PageFetchResponse":
        try:
            page.wait_for_load_state(
                PAGE_READY_STATE,
                timeout=max(self._config.captcha_poll_seconds, 1) * 1000,
            )
        except (self._playwright_timeout_error, self._playwright_error):
            pass
        body = self._read_page_content(page)
        current_url = getattr(page, "url", None) or url
        if current_url == "about:blank":
            return self._goto_existing_page(page, url)
        return _PageFetchResponse(
            url=current_url,
            status_code=200,
            body=body,
            content_type=content_type or "text/html",
            page=page,
        )

    def _goto_existing_page(self, page: Any, url: str) -> "_PageFetchResponse":
        try:
            return self._goto_page(page, url)
        except self._playwright_error as error:
            raise PlaywrightFetchError(str(error)) from error

    def _read_page_content(self, page: Any, attempts: int = 3) -> str:
        last_error = None
        for attempt in range(max(attempts, 1)):
            try:
                return page.content()
            except (self._playwright_timeout_error, self._playwright_error) as error:
                last_error = error
                if attempt >= attempts - 1:
                    break
                try:
                    page.wait_for_load_state(PAGE_READY_STATE, timeout=1000)
                    page.wait_for_timeout(250)
                except (self._playwright_timeout_error, self._playwright_error):
                    time.sleep(0.25)
        raise PlaywrightFetchError(str(last_error))

    def _goto_page(self, page: Any, url: str) -> "_PageFetchResponse":
        self._wait_for_request_slot(url)
        response = None
        try:
            response = page.goto(
                url,
                wait_until=PAGE_READY_STATE,
                timeout=self._config.browser_timeout_seconds * 1000,
            )
        except self._playwright_timeout_error:
            html = self._read_page_content(page)
            return _PageFetchResponse(
                url=getattr(page, "url", None) or url,
                status_code=0,
                body=html,
                content_type="text/html",
                page=page,
            )

        if self._config.browser_wait_ms:
            page.wait_for_timeout(self._config.browser_wait_ms)
        html = self._read_page_content(page)
        status_code = response.status if response else 0
        content_type = response.headers.get("content-type", "") if response else ""
        return _PageFetchResponse(
            url=url,
            status_code=status_code,
            body=html,
            content_type=content_type,
            page=page,
        )

    def _wait_for_request_slot(self, url: str | None = None) -> None:
        """Pace top-level requests without adding a delay before the first one."""

        delay = max(float(self._config.request_delay_seconds), 0.0)
        search_query = _is_search_query_url(url)
        search_delay = max(float(self._config.search_delay_seconds), 0.0) if search_query else 0.0
        clock = getattr(self, "_request_clock", time.monotonic)
        sleeper = getattr(self, "_request_sleep", time.sleep)
        now = clock()
        previous = getattr(self, "_last_request_started", None)
        last_search = getattr(self, "_last_search_request_started", None)
        remaining = max(
            delay - (now - previous) if previous is not None else 0.0,
            search_delay - (now - last_search) if last_search is not None else 0.0,
        )
        if remaining > 0:
            sleeper(remaining)
        started = clock()
        self._last_request_started = started
        if search_query:
            self._last_search_request_started = started


def _is_search_query_url(url: str | None) -> bool:
    if not url:
        return False
    parts = urlsplit(url)
    return parts.hostname in {"yandex.ru", "www.google.com"} and parts.path.rstrip("/") == "/search"


@dataclass(frozen=True)
class _PageFetchResponse:
    url: str
    status_code: int
    body: str
    content_type: str
    page: Any

    def with_body(self, body: str) -> "_PageFetchResponse":
        return _PageFetchResponse(
            url=self.url,
            status_code=self.status_code,
            body=body,
            content_type=self.content_type,
            page=self.page,
        )

    def to_fetch_response(self) -> FetchResponse:
        return FetchResponse(
            url=self.url,
            status_code=self.status_code,
            body=self.body,
            content_type=self.content_type,
        )


def _charset_from_content_type(content_type: str) -> str | None:
    match = re.search(r"charset=([^\s;]+)", content_type, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip("\"'")


def _decode_bytes(value: bytes, charset: str | None) -> str:
    for encoding in (charset, "utf-8", "windows-1251", "cp1251"):
        if not encoding:
            continue
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    return value.decode("utf-8", errors="replace")


def _browser_launch_options(
    config: AutoConfig,
    headless: bool,
    *,
    tls_pins: tuple[str, ...] = (),
) -> dict[str, Any]:
    options: dict[str, Any] = {"headless": headless}
    browser_channel = config.browser_channel.strip()
    if browser_channel:
        options["channel"] = browser_channel
    if config.proxy_url:
        options["proxy"] = {"server": config.proxy_url}
    if tls_pins:
        options["args"] = [
            f"--ignore-certificate-errors-spki-list={','.join(tls_pins)}"
        ]
    return options


@contextmanager
def _node_extra_ca_environment(ca_cert: Path | None) -> Iterator[None]:
    """Expose an explicit proxy CA only while Playwright starts its driver."""

    if ca_cert is None:
        yield
        return
    certificate = ca_cert.expanduser().resolve()
    if not certificate.is_file():
        raise PlaywrightFetchError(f"--ca-cert file not found: {certificate}")
    try:
        ssl.create_default_context(cafile=str(certificate))
    except (OSError, ssl.SSLError) as error:
        raise PlaywrightFetchError(f"invalid --ca-cert: {error}") from error

    previous = os.environ.get("NODE_EXTRA_CA_CERTS")
    combined_path: Path | None = None
    selected_path = certificate
    if previous:
        previous_path = Path(previous).expanduser()
        if previous_path.is_file() and previous_path.resolve() != certificate:
            with tempfile.NamedTemporaryFile(prefix="logingen-ca-", suffix=".pem", delete=False) as bundle:
                bundle.write(previous_path.read_bytes())
                bundle.write(b"\n")
                bundle.write(certificate.read_bytes())
                combined_path = Path(bundle.name)
                selected_path = combined_path
    os.environ["NODE_EXTRA_CA_CERTS"] = str(selected_path)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("NODE_EXTRA_CA_CERTS", None)
        else:
            os.environ["NODE_EXTRA_CA_CERTS"] = previous
        if combined_path is not None:
            try:
                combined_path.unlink()
            except OSError:
                pass


def _tls_cache_key(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise PlaywrightFetchError("browser TLS target must be an HTTP(S) URL")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as error:
        raise PlaywrightFetchError("browser TLS target contains an invalid port") from error
    return scheme, parts.hostname.casefold(), port


def _browser_tls_pins(
    url: str,
    *,
    ca_cert: Path,
    proxy: str | None,
    timeout_seconds: float,
) -> tuple[str, ...]:
    """Verify one HTTPS peer with the selected CA and return Chromium SPKI pins."""

    scheme, hostname, port = _tls_cache_key(url)
    if scheme == "http":
        return ()
    certificate = ca_cert.expanduser().resolve()
    if not certificate.is_file():
        raise ValueError(f"--ca-cert file not found: {certificate}")
    try:
        ssl_context = ssl.create_default_context(cafile=str(certificate))
    except (OSError, ssl.SSLError) as error:
        raise ValueError(f"invalid --ca-cert for browser TLS: {error}") from error
    executable = shutil.which("openssl")
    if executable is None:
        raise ValueError("browser --ca-cert requires the openssl executable")
    connection = _tls_connection(
        hostname,
        port,
        proxy=proxy,
        timeout_seconds=timeout_seconds,
        ssl_context=ssl_context,
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise ValueError("browser TLS preflight returned no TLS socket")
        peer_certificate = connection.sock.getpeercert(binary_form=True)
        if not peer_certificate:
            raise ValueError("browser TLS preflight returned no peer certificate")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise ValueError(f"browser TLS preflight failed: {error}") from error
    finally:
        connection.close()

    certificates = dict.fromkeys([
        peer_certificate,
        *ssl_context.get_ca_certs(binary_form=True),
    ])
    return tuple(dict.fromkeys(
        _certificate_spki_pin(
            item,
            executable=executable,
            timeout_seconds=timeout_seconds,
        )
        for item in certificates
    ))


def _tls_connection(
    hostname: str,
    port: int,
    *,
    proxy: str | None,
    timeout_seconds: float,
    ssl_context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    if not proxy:
        return http.client.HTTPSConnection(
            hostname,
            port,
            timeout=timeout_seconds,
            context=ssl_context,
        )
    parts = urlsplit(proxy)
    if (
        parts.scheme.casefold() != "http"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("browser TLS --proxy must be http://HOST:PORT without credentials or a path")
    try:
        proxy_port = parts.port or 80
    except ValueError as error:
        raise ValueError("browser TLS --proxy contains an invalid port") from error
    connection = http.client.HTTPSConnection(
        parts.hostname,
        proxy_port,
        timeout=timeout_seconds,
        context=ssl_context,
    )
    connection.set_tunnel(hostname, port)
    return connection


def _certificate_spki_pin(
    certificate: bytes,
    *,
    executable: str,
    timeout_seconds: float,
) -> str:
    try:
        public_key = subprocess.run(
            [executable, "x509", "-inform", "DER", "-pubkey", "-noout"],
            input=certificate,
            capture_output=True,
            check=True,
            timeout=timeout_seconds,
        ).stdout
        spki = subprocess.run(
            [executable, "pkey", "-pubin", "-outform", "DER"],
            input=public_key,
            capture_output=True,
            check=True,
            timeout=timeout_seconds,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("could not derive a browser TLS public-key pin with openssl") from error
    if not spki:
        raise ValueError("openssl returned an empty browser TLS public key")
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _browser_context_options(config: AutoConfig) -> dict[str, Any]:
    options: dict[str, Any] = {
        "locale": "ru-RU",
        "viewport": {"width": 1366, "height": 768},
        "extra_http_headers": {
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        },
    }
    user_agent = _browser_user_agent(config.user_agent)
    if user_agent:
        options["user_agent"] = user_agent
    if config.proxy_url and config.ca_cert is None:
        options["ignore_https_errors"] = True
    return options


def _browser_user_agent(configured_user_agent: str) -> str:
    return configured_user_agent.strip()
