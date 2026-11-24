"""Discovery JSON -> module 4 fields; no requests to external systems."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "discovery_module_3" / "src", ROOT / "check_module_4" / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from authpoints.classifier import classify_web
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authchecker.importer import parse_report
from authchecker.jobs import build_jobs
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter
from authchecker.browser import BrowserCheckConfig, BrowserCheckResult
from authchecker.browser_adapter import BrowserAdapter
from authchecker.models import Credential, Outcome, OutcomeStatus


class LoginTemplateBridgeTests(unittest.TestCase):
    def test_discovery_fields_reach_http_and_browser_without_schema_change(self):
        url = "http://127.0.0.1:8080/wp-login.php"
        body = ('<form method="post"><input name="other_username">'
                '<input name="log"><input name="pwd" type="password"></form>')
        title, text, forms, links = parse_html(body, url)
        found = classify_web(WebObservation(url=url, source="http_probe", status_code=200,
                                           title=title, text=text, body=body, forms=forms, links=links))
        report = Report(scope=["127.0.0.1"], findings=found)
        report.finish()
        jobs = build_jobs(parse_report(report.to_dict()))
        self.assertEqual(len(jobs), 1)
        job = jobs[0]
        self.assertEqual(job.metadata["login_template"], "wordpress")
        calls = []

        class HttpClient:
            def __init__(self):
                self.calls = 0

            def request(self, method, target, *, headers=None, body=None):
                calls.append((method, target, body))
                self.calls += 1
                return (HttpResponse(200, body=body_page) if self.calls == 1
                        else HttpResponse(401, body="Invalid username or password"))

        body_page = body
        result = PasswordFormAdapter(HttpClient()).attempt(job, Credential("student", "wrong"))
        self.assertEqual(result.status, OutcomeStatus.FAILURE)
        self.assertEqual([call[0] for call in calls], ["GET", "POST"])
        self.assertEqual(calls[1][1], url)
        self.assertEqual(parse_qs(calls[1][2].decode()), {"log": ["student"], "pwd": ["wrong"]})

        configs = []

        def checker(target, credential, **options):
            configs.append(options["config"])
            return BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), 1, target, ("log", "pwd"))

        base_config = BrowserCheckConfig(headless=True)
        result = BrowserAdapter(base_config, checker=checker).attempt(job, Credential("student", "wrong"))
        self.assertEqual(result.status, OutcomeStatus.FAILURE)
        self.assertEqual(configs[0].username_field_hint, "log")
        self.assertEqual(configs[0].password_field_hint, "pwd")
        self.assertEqual(base_config.username_field_hint, "")
