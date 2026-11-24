from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authchecker.adapters.http import TargetScope
from authchecker.discovery import _run_pointfinder, discover_login_pages, discover_login_url
from authchecker.defaults import DEFAULT_USER_AGENT
from authpoints.models import Report

from support import valid_report


class _RawReport:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def to_dict(self) -> dict[str, object]:
        return self.payload


class DiscoveryTests(unittest.TestCase):
    def test_pages_use_page_only_scan_and_product_template(self) -> None:
        raw = _RawReport(valid_report())
        with patch("authpoints.pipeline.run_active_scan", return_value=raw) as scan:
            report = discover_login_pages(
                ["https://example.test/bitrix/admin/"],
                template="bitrix",
                timeout_seconds=5,
                target_scope=TargetScope.from_domain("example.test"),
            )

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(scan.call_args.args[:2], ([], ["https://example.test/bitrix/admin/"]))
        config = scan.call_args.args[2]
        self.assertTrue(config.page_only)
        self.assertEqual(config.login_templates, ("bitrix",))
        self.assertFalse(config.katana.enabled)
        self.assertFalse(config.nmap.enabled)
        self.assertEqual(config.standard_paths, [])

    def test_exact_url_uses_browser_dom_when_http_finds_no_form(self) -> None:
        raw = Report(scope=["127.0.0.1"])
        rendered = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "http://127.0.0.1:8080/js-app"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><head><title>Login</title></head><body>"
                        "<form action='/session' method='post'>"
                        "<input name='username'><input name='password' type='password'>"
                        "<button type='submit'>Log in</button></form></body></html>"
                    ),
                },
            }
        )
        with (
            patch("authpoints.pipeline.run_active_scan", return_value=raw),
            patch("authpoints.browser_render.render_pages", return_value=rendered) as browser,
        ):
            report = _run_pointfinder(
                url="http://127.0.0.1:8080/js-app",
                exact_path="/js-app",
                proxy=None,
                user_agent="test-agent",
                ca_cert=None,
                timeout_seconds=5,
            )

        browser.assert_called_once()
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].auth_type, "password_form")
        self.assertEqual(
            report.findings[0].metadata["form_action"],
            "http://127.0.0.1:8080/session",
        )

    def test_exact_browser_receives_ca_cert(self) -> None:
        raw = Report(scope=["127.0.0.1"])
        with (
            patch("authpoints.pipeline.run_active_scan", return_value=raw),
            patch("authpoints.browser_render.render_pages", return_value="") as browser,
        ):
            _run_pointfinder(
                url="https://127.0.0.1/login",
                exact_path="/login",
                proxy="http://127.0.0.1:9090",
                user_agent="test-agent",
                ca_cert=Path("/tmp/test-ca.pem"),
                timeout_seconds=5,
            )
        browser.assert_called_once()
        self.assertEqual(browser.call_args.kwargs["config"].ca_cert, "/tmp/test-ca.pem")
        self.assertEqual(
            browser.call_args.kwargs["config"].proxy,
            "http://127.0.0.1:9090",
        )

    def test_exact_loopback_url_is_delegated_to_pointfinder(self) -> None:
        raw = _RawReport(valid_report())
        with patch("authchecker.discovery._run_pointfinder", return_value=raw) as scan:
            report = discover_login_url(
                "http://127.0.0.1:8080/login?view=compact#form",
                proxy="http://127.0.0.1:9090",
                timeout_seconds=2.1,
            )

        self.assertEqual(len(report.findings), 1)
        scan.assert_called_once_with(
            url="http://127.0.0.1:8080/login?view=compact#form",
            exact_path="/login?view=compact",
            proxy="http://127.0.0.1:9090",
            user_agent=DEFAULT_USER_AGENT,
            ca_cert=None,
            timeout_seconds=3,
            browser_fallback=True,
        )

    def test_adaptive_caller_can_disable_pointfinder_browser_fallback(self) -> None:
        raw = Report(scope=["127.0.0.1"])
        with (
            patch("authpoints.pipeline.run_active_scan", return_value=raw),
            patch("authpoints.browser_render.render_pages") as browser,
        ):
            report = _run_pointfinder(
                url="http://127.0.0.1:8080/js-app",
                exact_path="/js-app",
                proxy=None,
                user_agent="test-agent",
                ca_cert=None,
                timeout_seconds=5,
                browser_fallback=False,
            )

        browser.assert_not_called()
        self.assertEqual(report.findings, [])

    def test_optional_discovery_report_is_written(self) -> None:
        raw = _RawReport(valid_report())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory, "nested", "pointfinder.json")
            with patch("authchecker.discovery._run_pointfinder", return_value=raw):
                discover_login_url(
                    "http://localhost:8080/login",
                    proxy="http://127.0.0.1:9090",
                    timeout_seconds=2,
                    save_report=output,
                )
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), raw.payload)

    def test_external_url_is_rejected_before_pointfinder(self) -> None:
        with patch("authchecker.discovery._run_pointfinder") as scan:
            with self.assertRaisesRegex(ValueError, "scope-domain"):
                discover_login_url(
                    "http://example.test/login",
                    proxy="http://127.0.0.1:9090",
                    timeout_seconds=2,
                )
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
