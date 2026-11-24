from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from authpoints.cli import main
from authpoints.config import (
    HttpConfig, KatanaConfig, NmapConfig, ScanConfig,
    validate_browser_resource_domain,
)
from authpoints.models import Report
from authpoints.parsers.katana_jsonl import parse_katana_jsonl
from authpoints.pipeline import run_active_scan


def page_record(body: str, **diagnostics) -> str:
    return json.dumps({
        "request": {"method": "GET", "endpoint": "https://example.test/"},
        "response": {
            "status_code": 200, "headers": {"content-type": "text/html"}, "body": body,
        },
        "discovery_diagnostics": diagnostics,
    })


def config(*, auto_headless: bool = False) -> ScanConfig:
    return ScanConfig(
        nmap=NmapConfig(enabled=False),
        katana=KatanaConfig(auto_headless=auto_headless),
        http=HttpConfig(enabled=False),
    )


class DiscoveryDiagnosticsTests(unittest.TestCase):
    def test_found_modal_keeps_diagnostics_without_treating_blocked_telemetry_as_failure(self) -> None:
        output = page_record(
            '<form action="/session" method="post"><input name="username">'
            '<input type="password" name="password"></form>',
            candidate_url="https://example.test/?state=private-state",
            final_url="https://example.test/?token=private-token",
            password_field_found=True,
            login_form_found=True,
            click_count=1,
            blocked_count=1,
            blocked_resource_hosts=["telemetry.example.test"],
            auto_resource_hosts=["cdn.example.test"],
            diagnostics_path="/tmp/discovery-debug/snapshot.json",
            cookies="private-cookie",
        )
        with patch("authpoints.pipeline.run_katana", return_value=output):
            report = run_active_scan([], ["https://example.test/"], config())

        self.assertTrue(any(f.auth_type == "password_form" for f in report.findings))
        self.assertFalse(report.partial)
        metadata = report.config["browser_diagnostics"][0]
        self.assertEqual(metadata["click_count"], 1)
        self.assertEqual(metadata["auto_resource_hosts"], ["cdn.example.test"])
        self.assertEqual(metadata["final_url"], "https://example.test/?token=private-token")
        saved = json.dumps(report.to_dict())
        self.assertIn("private-state", saved)
        self.assertIn("private-token", saved)
        self.assertNotIn("private-cookie", saved)

    def test_missing_modal_with_blocked_resources_has_actionable_issue(self) -> None:
        output = page_record(
            "<p>Welcome</p>",
            candidate_url="https://example.test/",
            password_field_found=False,
            blocked_count=2,
            blocked_resource_hosts=["cdn.example.test"],
            blocked_requests=[{
                "url": "https://cdn.example.test/app.js",
                "method": "GET", "resource_type": "script", "reason": "outside_scope",
            }],
            network_error_count=1,
            diagnostics_path="/tmp/discovery-debug/snapshot.json",
        )
        with patch("authpoints.pipeline.run_katana", return_value=output):
            report = run_active_scan([], ["https://example.test/"], config())

        self.assertTrue(report.partial)
        self.assertEqual(len(report.issues), 1)
        self.assertEqual(report.issues[0].stage, "browser_render")
        self.assertIn("cdn.example.test", report.issues[0].message)
        self.assertIn("--browser-resource-domain", report.issues[0].message)
        self.assertIn("snapshot.json", report.issues[0].message)

    def test_blocked_external_iframe_alone_is_not_a_login_detection_error(self) -> None:
        output = page_record(
            "<p>Welcome</p>", candidate_url="https://example.test/",
            password_field_found=False, login_form_found=False,
            blocked_count=1, blocked_resource_hosts=["video.example.test"],
            blocked_requests=[{
                "url": "https://video.example.test/embed/1",
                "method": "GET", "resource_type": "document", "reason": "outside_scope",
            }],
        )
        with patch("authpoints.pipeline.run_katana", return_value=output):
            report = run_active_scan([], ["https://example.test/"], config())

        self.assertFalse(report.findings)
        self.assertFalse(report.issues)

    def test_signup_password_and_blocked_script_report_missing_login(self) -> None:
        output = page_record(
            '<form method="post"><input name="email" type="email">'
            '<input name="password" type="password" autocomplete="new-password">'
            '<button>Create account</button></form>',
            candidate_url="https://example.test/",
            password_field_found=True,
            login_form_found=False,
            blocked_count=1,
            blocked_resource_hosts=["cdn.example.test"],
        )
        progress: list[str] = []
        with patch("authpoints.pipeline.run_katana", return_value=output):
            report = run_active_scan(
                [], ["https://example.test/"], config(), on_progress=progress.append,
            )

        self.assertFalse(report.findings)
        self.assertTrue(report.partial)
        self.assertIn("Поле пароля найдено, но форма входа не подтверждена", report.issues[0].message)
        self.assertIn("cdn.example.test", report.issues[0].message)
        self.assertTrue(any("форма входа: не подтверждена" in line for line in progress))

    def test_parser_retains_browser_diagnostics_for_pipeline(self) -> None:
        observations, errors = parse_katana_jsonl(page_record(
            "<p>Welcome</p>", password_field_found=False, blocked_count=1,
        ))

        self.assertFalse(errors)
        self.assertEqual(observations[0].discovery_diagnostics["blocked_count"], 1)

    def test_static_response_count_excludes_input_url_placeholder(self) -> None:
        output = "\n".join(page_record("<p>Welcome</p>") for _ in range(3))
        progress: list[str] = []
        with (
            patch("authpoints.pipeline.run_katana", side_effect=[output, ""]),
            patch("authpoints.pipeline.render_pages", return_value=""),
        ):
            run_active_scan([], ["https://example.test/"], config(auto_headless=True), on_progress=progress.append)

        self.assertIn("[ANALYZE] Статический этап: 3 web-ответов", progress)
        self.assertNotIn("[ANALYZE] Статический этап: 4 web-ответов", progress)

    def test_cli_wires_asset_domains_and_debug_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch("authpoints.cli.run_active_scan", return_value=Report(scope=["example.test"])) as scan,
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                code = main([
                    "-u", "https://example.test/", "--tools", "katana",
                    "--browser-resource-domain", "CDN.example.test",
                    "--browser-resource-domain", "cdn.example.test",
                    "--output", str(output),
                ])

            self.assertEqual(code, 0)
            selected = scan.call_args.args[2]
            self.assertEqual(selected.katana.browser_resource_domains, ("cdn.example.test",))
            self.assertEqual(selected.katana.browser_diagnostics_dir, str(Path(directory) / "discovery-debug"))

    def test_asset_domain_is_exact_host_without_wildcards_or_urls(self) -> None:
        self.assertEqual(validate_browser_resource_domain("CDN.Example.test."), "cdn.example.test")
        for value in ("https://cdn.example.test", "*.example.test", "cdn.example.test:443", "user@cdn.example.test", "cdn.example.test\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_browser_resource_domain(value)


if __name__ == "__main__":
    unittest.main()
