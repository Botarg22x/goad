from __future__ import annotations

import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from logingen.models import AutoConfig
from logingen.playwright_fetcher import (
    PAGE_READY_STATE,
    PlaywrightFetchTransport,
    _PageFetchResponse,
    _browser_context_options,
    _browser_launch_options,
    _node_extra_ca_environment,
)


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class ProxyTlsOptionsTests(unittest.TestCase):
    def test_http_fetch_ignores_tls_only_for_proxy_without_ca(self) -> None:
        with mock.patch("playwright.sync_api.sync_playwright") as factory:
            transport = PlaywrightFetchTransport(AutoConfig(proxy_url="http://127.0.0.1:9090"))
            options = factory.return_value.start.return_value.request.new_context.call_args.kwargs
            self.assertTrue(options["ignore_https_errors"])
            transport.close()

        with mock.patch("playwright.sync_api.sync_playwright") as factory:
            transport = PlaywrightFetchTransport(AutoConfig())
            options = factory.return_value.start.return_value.request.new_context.call_args.kwargs
            self.assertNotIn("ignore_https_errors", options)
            transport.close()


class FakePage:
    def __init__(self, body="<html>allowed</html>", url: str = "https://company.test/") -> None:
        self.closed = False
        self.url = url
        self._body = body
        self.wait_timeout_calls: list[int] = []

    def close(self) -> None:
        self.closed = True

    def is_closed(self) -> bool:
        return self.closed

    def wait_for_load_state(self, *args, **kwargs) -> None:
        return None

    def wait_for_timeout(self, *args, **kwargs) -> None:
        if args:
            self.wait_timeout_calls.append(args[0])
        return None

    def content(self) -> str:
        if isinstance(self._body, list):
            if len(self._body) > 1:
                value = self._body.pop(0)
            else:
                value = self._body[0]
            if isinstance(value, Exception):
                raise value
            return value
        return self._body


class FakeLazyYandexTransport(PlaywrightFetchTransport):
    def __init__(
        self,
        headless_body: str,
        visible_body="<html>visible</html>",
        *,
        headless_status: int = 200,
        visible_status: int = 200,
    ) -> None:
        self._config = AutoConfig(browser_wait_ms=0, captcha_wait_seconds=3, captcha_poll_seconds=1)
        self._playwright_timeout_error = Exception
        self._playwright_error = Exception
        self._manual_page = None
        self._headless_body = headless_body
        self._visible_body = visible_body
        self._headless_status = headless_status
        self._visible_status = visible_status
        self.headless_calls: list[bool] = []
        self.visible_calls: list[str] = []

    def _fetch_rendered_html_keep_page(self, url: str, *, headless: bool) -> _PageFetchResponse:
        self.headless_calls.append(headless)
        return _PageFetchResponse(
            url=url,
            status_code=self._headless_status,
            body=self._headless_body,
            content_type="text/html",
            page=FakePage(),
        )

    def _fetch_rendered_html_on_reusable_page(self, url: str) -> _PageFetchResponse:
        self.visible_calls.append(url)
        self._manual_page = FakePage(self._visible_body, url)
        return _PageFetchResponse(
            url=url,
            status_code=self._visible_status,
            body=self._read_page_content(self._manual_page),
            content_type="text/html",
            page=self._manual_page,
        )


class FakeManualAccessTransport(PlaywrightFetchTransport):
    def __init__(self) -> None:
        self._config = AutoConfig(browser_headless=True, browser_wait_ms=0)
        self.headless_calls: list[bool] = []

    def _fetch_rendered_html_keep_page(self, url: str, *, headless: bool) -> _PageFetchResponse:
        self.headless_calls.append(headless)
        body = "<html>allowed after manual check</html>" if not headless else "<html>blocked</html>"
        return _PageFetchResponse(
            url=url,
            status_code=403,
            body="<html>blocked</html>",
            content_type="text/html",
            page=FakePage(body, url),
        )


class FakeTimeoutError(Exception):
    pass


class FakePlaywrightError(Exception):
    pass


class FakeGotoResponse:
    status = 200
    headers = {"content-type": "text/html"}


class FakeGotoPage(FakePage):
    def __init__(self, body: str = "<html>loaded</html>", *, fail_with_timeout: bool = False) -> None:
        super().__init__(body=body)
        self.fail_with_timeout = fail_with_timeout
        self.goto_args: dict[str, object] = {}

    def goto(self, url: str, **kwargs) -> FakeGotoResponse:
        self.url = url
        self.goto_args = kwargs
        if self.fail_with_timeout:
            raise FakeTimeoutError("timeout")
        return FakeGotoResponse()


class FakeGotoTransport(PlaywrightFetchTransport):
    def __init__(self) -> None:
        self._config = AutoConfig(browser_wait_ms=0, browser_timeout_seconds=7)
        self._playwright_timeout_error = FakeTimeoutError
        self._playwright_error = FakePlaywrightError


class FailingCleanupResource:
    def __init__(self, calls: list[str], operation: str) -> None:
        self._calls = calls
        self._operation = operation

    def close(self) -> None:
        self._fail("close")

    def dispose(self) -> None:
        self._fail("dispose")

    def stop(self) -> None:
        self._fail("stop")

    def _fail(self, operation: str) -> None:
        if operation != self._operation:
            raise AssertionError(f"unexpected cleanup operation: {operation}")
        self._calls.append(operation)
        raise RuntimeError("Connection closed while reading from the driver")


class PlaywrightFetcherTests(unittest.TestCase):
    def test_pdf_retries_hostname_mismatch_without_changing_normal_tls(self) -> None:
        url = "https://example.test/contacts.pdf"
        transport = object.__new__(PlaywrightFetchTransport)
        transport._config = AutoConfig(proxy_url="http://127.0.0.1:8085")
        transport._playwright_error = FakePlaywrightError
        transport._playwright_timeout_error = FakeTimeoutError
        transport._request_options = {
            "user_agent": transport._config.user_agent,
            "proxy": {"server": transport._config.proxy_url},
        }
        transport._request_context = mock.Mock()
        transport._request_context.get.side_effect = FakePlaywrightError(
            "Hostname/IP does not match certificate's altnames"
        )
        transport._pdf_unverified_request_context = None
        transport._playwright = mock.Mock()
        retry_context = transport._playwright.request.new_context.return_value
        retry_response = retry_context.get.return_value
        retry_response.status = 200
        retry_response.body.return_value = b"%PDF-1.7"
        retry_response.headers = {"content-type": "application/pdf"}
        transport._wait_for_request_slot = mock.Mock()

        result = transport.fetch_bytes(url)

        self.assertEqual(result.body, b"%PDF-1.7")
        self.assertIn("без проверки TLS", result.tls_warning)
        self.assertIn(url, result.tls_warning)
        transport._playwright.request.new_context.assert_called_once_with(
            **transport._request_options,
            ignore_https_errors=True,
        )
        retry_context.get.assert_called_once_with(
            url, headers=None, timeout=10000,
        )

    def test_pdf_does_not_retry_other_certificate_errors(self) -> None:
        transport = object.__new__(PlaywrightFetchTransport)
        transport._config = AutoConfig()
        transport._playwright_error = FakePlaywrightError
        transport._playwright_timeout_error = FakeTimeoutError
        transport._request_context = mock.Mock()
        transport._request_context.get.side_effect = FakePlaywrightError(
            "certificate verify failed: unable to get local issuer certificate"
        )
        transport._playwright = mock.Mock()
        transport._wait_for_request_slot = mock.Mock()

        with self.assertRaisesRegex(Exception, "certificate verify failed"):
            transport.fetch_bytes("https://example.test/contacts.pdf")

        transport._playwright.request.new_context.assert_not_called()

    def test_close_suppresses_driver_shutdown_errors_and_finishes_cleanup(self) -> None:
        calls: list[str] = []
        transport = object.__new__(PlaywrightFetchTransport)
        transport._closed = False
        transport._manual_page = FailingCleanupResource(calls, "close")
        transport._browser_context = FailingCleanupResource(calls, "close")
        transport._browser = FailingCleanupResource(calls, "close")
        transport._request_context = FailingCleanupResource(calls, "dispose")
        transport._playwright = FailingCleanupResource(calls, "stop")
        transport._browser_headless = True

        transport.close()
        transport.close()

        self.assertEqual(calls, ["close", "close", "close", "dispose", "stop"])
        self.assertTrue(transport._closed)
        self.assertIsNone(transport._manual_page)
        self.assertIsNone(transport._browser_context)
        self.assertIsNone(transport._browser)
        self.assertIsNone(transport._browser_headless)

    def test_request_pacer_waits_between_top_level_requests(self) -> None:
        transport = object.__new__(PlaywrightFetchTransport)
        transport._config = AutoConfig(request_delay_seconds=15)
        current = [100.0]
        sleeps: list[float] = []
        transport._request_clock = lambda: current[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            current[0] += seconds

        transport._request_sleep = sleep
        transport._last_request_started = None

        transport._wait_for_request_slot()
        transport._wait_for_request_slot()
        current[0] += 4
        transport._wait_for_request_slot()

        self.assertEqual(sleeps, [15.0, 11.0])

    def test_search_queries_wait_ten_seconds_even_with_documents_between_them(self) -> None:
        transport = object.__new__(PlaywrightFetchTransport)
        transport._config = AutoConfig(request_delay_seconds=1)
        current = [100.0]
        sleeps: list[float] = []
        transport._request_clock = lambda: current[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            current[0] += seconds

        transport._request_sleep = sleep
        transport._last_request_started = None
        transport._last_search_request_started = None

        transport._wait_for_request_slot("https://yandex.ru/search/?text=one")
        current[0] += 3
        transport._wait_for_request_slot("https://company.test/file.pdf")
        current[0] += 2
        transport._wait_for_request_slot("https://www.google.com/search?q=two")
        current[0] += 4
        transport._wait_for_request_slot("https://company.test/page")
        current[0] += 1
        transport._wait_for_request_slot("https://yandex.ru/search/?text=three")

        self.assertEqual(sleeps, [5.0, 5.0])

    def test_browser_launch_options_include_browser_channel(self) -> None:
        options = _browser_launch_options(AutoConfig(browser_channel="chrome"), headless=False)

        self.assertEqual(options, {"headless": False, "channel": "chrome"})

    def test_browser_launch_options_include_proxy(self) -> None:
        options = _browser_launch_options(
            AutoConfig(proxy_url="http://127.0.0.1:9090"), headless=True
        )

        self.assertEqual(options["proxy"], {"server": "http://127.0.0.1:9090"})

    def test_browser_launch_options_include_only_selected_tls_pins(self) -> None:
        options = _browser_launch_options(
            AutoConfig(proxy_url="http://127.0.0.1:9090"),
            headless=True,
            tls_pins=("leaf-pin", "ca-pin"),
        )

        self.assertEqual(
            options["args"],
            ["--ignore-certificate-errors-spki-list=leaf-pin,ca-pin"],
        )
        self.assertNotIn("ignore_https_errors", options)

    def test_node_extra_ca_is_scoped_to_playwright_start(self) -> None:
        with TemporaryDirectory() as directory:
            certificate = Path(directory) / "proxy-ca.pem"
            certificate.write_text(
                "-----BEGIN CERTIFICATE-----\ninvalid-for-this-test\n-----END CERTIFICATE-----\n",
                encoding="utf-8",
            )
            with mock.patch("logingen.playwright_fetcher.ssl.create_default_context"):
                with mock.patch.dict(os.environ, {}, clear=True):
                    with _node_extra_ca_environment(certificate):
                        self.assertEqual(os.environ["NODE_EXTRA_CA_CERTS"], str(certificate))
                    self.assertNotIn("NODE_EXTRA_CA_CERTS", os.environ)

    def test_browser_context_uses_real_browser_user_agent_by_default(self) -> None:
        options = _browser_context_options(AutoConfig())

        self.assertEqual(options["user_agent"], AutoConfig().user_agent)
        self.assertTrue(options["user_agent"].startswith("Mozilla/5.0 "))
        self.assertEqual(options["locale"], "ru-RU")
        self.assertNotIn("ignore_https_errors", options)

    def test_browser_context_skips_tls_only_for_proxy_without_ca(self) -> None:
        proxy = "http://127.0.0.1:9090"
        self.assertTrue(_browser_context_options(AutoConfig(proxy_url=proxy))["ignore_https_errors"])
        self.assertNotIn(
            "ignore_https_errors",
            _browser_context_options(AutoConfig(proxy_url=proxy, ca_cert=Path("ca.pem"))),
        )

    def test_browser_context_keeps_explicit_user_agent(self) -> None:
        options = _browser_context_options(AutoConfig(user_agent="Mozilla/5.0 Test Browser"))

        self.assertEqual(options["user_agent"], "Mozilla/5.0 Test Browser")

    def test_yandex_manual_session_opens_visible_browser_only_after_captcha(self) -> None:
        transport = FakeLazyYandexTransport("<html>search results</html>")

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
        )

        self.assertEqual(response.body, "<html>search results</html>")
        self.assertEqual(transport.headless_calls, [True])
        self.assertEqual(transport.visible_calls, [])

    def test_yandex_manual_session_keeps_visible_browser_after_captcha(self) -> None:
        transport = FakeLazyYandexTransport("<html>captcha</html>", "<html>solved results</html>")

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
        )

        self.assertEqual(response.body, "<html>solved results</html>")
        self.assertEqual(transport.headless_calls, [True])
        self.assertEqual(transport.visible_calls, ["https://yandex.ru/search/"])
        self.assertIsNotNone(transport._manual_page)

    def test_search_http_429_retries_in_visible_browser(self) -> None:
        transport = FakeLazyYandexTransport(
            "<html>too many requests</html>",
            "<html>search results</html>",
            headless_status=429,
            visible_status=200,
        )

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, "<html>search results</html>")
        self.assertEqual(transport.headless_calls, [True])
        self.assertEqual(transport.visible_calls, ["https://yandex.ru/search/"])

    def test_search_http_429_waits_for_manual_reload_when_still_limited(self) -> None:
        transport = FakeLazyYandexTransport(
            "<html>too many requests</html>",
            ["<html>still limited</html>", "<html>search results</html>"],
            headless_status=429,
            visible_status=429,
        )
        prompt = io.StringIO()

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
            prompt_stream=prompt,
            input_stream=TtyInput("\n"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, "<html>search results</html>")
        self.assertIn("HTTP 429", prompt.getvalue())

    def test_search_http_429_remains_limited_if_manual_page_did_not_change(self) -> None:
        transport = FakeLazyYandexTransport(
            "<html>too many requests</html>",
            "<html>still limited</html>",
            headless_status=429,
            visible_status=429,
        )

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
            prompt_stream=io.StringIO(),
            input_stream=TtyInput("\n"),
        )

        self.assertEqual(response.status_code, 429)

    def test_yandex_manual_session_detects_captcha_solution_without_enter(self) -> None:
        input_stream = TtyInput("should-not-be-read\n")
        transport = FakeLazyYandexTransport("<html>captcha</html>", ["<html>captcha</html>", "<html>results</html>"])

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
            prompt_stream=io.StringIO(),
            input_stream=input_stream,
        )

        self.assertEqual(response.body, "<html>results</html>")
        self.assertEqual(input_stream.tell(), 0)

    def test_yandex_manual_session_waits_while_page_is_navigating_after_captcha(self) -> None:
        input_stream = TtyInput("should-not-be-read\n")
        transport = FakeLazyYandexTransport(
            "<html>captcha</html>",
            [FakePlaywrightError("page is navigating"), "<html>results</html>"],
        )
        transport._playwright_error = FakePlaywrightError

        response = transport.fetch_rendered_html_in_manual_session(
            "https://yandex.ru/search/",
            lambda html: "captcha" in html.lower(),
            prompt_stream=io.StringIO(),
            input_stream=input_stream,
        )

        self.assertEqual(response.body, "<html>results</html>")
        self.assertEqual(input_stream.tell(), 0)

    def test_company_manual_access_reopens_visible_browser_after_403(self) -> None:
        transport = FakeManualAccessTransport()

        response = transport.fetch_rendered_html_with_manual_access(
            "https://company.test/",
            prompt_stream=io.StringIO(),
            input_stream=TtyInput("\n"),
        )

        self.assertEqual(transport.headless_calls, [True, False])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, "<html>allowed after manual check</html>")

    def test_goto_page_waits_for_domcontentloaded(self) -> None:
        transport = FakeGotoTransport()
        page = FakeGotoPage()

        response = transport._goto_page(page, "https://company.test/")

        self.assertEqual(page.goto_args["wait_until"], PAGE_READY_STATE)
        self.assertEqual(page.goto_args["timeout"], 7000)
        self.assertEqual(response.body, "<html>loaded</html>")

    def test_goto_page_returns_partial_html_on_timeout(self) -> None:
        transport = FakeGotoTransport()
        page = FakeGotoPage("<html>partial</html>", fail_with_timeout=True)

        response = transport._goto_page(page, "https://company.test/")

        self.assertEqual(response.status_code, 0)
        self.assertEqual(response.body, "<html>partial</html>")


if __name__ == "__main__":
    unittest.main()
