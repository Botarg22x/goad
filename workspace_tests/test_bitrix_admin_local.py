"""Local-only integration for the primary page-template scenario."""
from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from test_bitrix_local_flow import Handler
from test_bitrix_admin_page import ADMIN, ADMIN_SUCCESS, job_for, report_for
from authchecker.adapters.http import ProxyHttpClient
from authchecker.browser import BrowserCheckConfig
from authchecker.browser_adapter import BrowserAdapter, TemplateFormAdapter
from authchecker.browser_http import BrowserHttpChecker
from authchecker.cli import main as check
from authchecker.models import Credential, OutcomeStatus
from authpoints.cli import main as discover


class AdminHandler(Handler):
    def do_GET(self):
        if urlsplit(self.path).path == "/result":
            case = parse_qs(urlsplit(self.path).query).get("case", ["success"])[0]
            if case in {"success", "js", "pre-captcha"}:
                self.send(ADMIN_SUCCESS)
                return
        if urlsplit(self.path).path != "/bitrix/admin/":
            return super().do_GET()
        case = parse_qs(urlsplit(self.path).query).get("case", ["success"])[0]
        self.server.tokens += 1
        token = f"token-{self.server.tokens}"
        body = ADMIN.replace("fresh-token", token)
        if case == "js":
            body = '<body><script>setTimeout(()=>document.body.innerHTML=' + json.dumps(body) + ',50)</script></body>'
        if case == "pre-captcha":
            body += '<script>{"CAPTCHA":true}</script>'
        self.send(body, Set_Cookie=f"sid={token}; Path=/")

    def do_POST(self):
        self.server.post_paths.append(self.path)
        return super().do_POST()


class BitrixAdminLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), AdminHandler)
        cls.server.tokens = 0
        cls.server.posts = []
        cls.server.raw_posts = []
        cls.server.post_paths = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.posts.clear()
        self.server.post_paths.clear()

    def job(self, case="success"):
        return job_for(ADMIN, self.base + "/bitrix/admin/?case=" + case)

    def test_admin_cli_report_runs_without_an_html_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                discovery_code = discover(["-u", self.job("failure").endpoint, "--page-only", "-t", "bitrix",
                                           "--output", str(report), "--links-output", str(Path(tmp) / "links.txt")])
            self.assertEqual(discovery_code, 0)
            saved = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(len(saved["findings"]), 1)
            self.assertEqual(saved["findings"][0]["metadata"]["login_template"], "bitrix")
            self.assertEqual(self.server.posts, [])
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = check(["run", "--live", "--report", str(report), "--login", "student",
                              "--password", "test-password", "--max-total", "1", "--audit", str(Path(tmp) / "audit.jsonl")])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["outcomes"], {"failure": 1})
            self.assertEqual(self.server.post_paths, ["/bitrix/admin/?login=yes"])

    def test_discover_links_feed_check_without_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            links = root / "auth-links.txt"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                discovery_code = discover([
                    "-u", self.job("failure").endpoint, "--page-only", "-t", "bitrix",
                    "--output", str(root / "report.json"),
                    "--links-output", str(links), "--no-json",
                ])
            self.assertEqual(discovery_code, 0)
            self.assertFalse((root / "report.json").exists())
            self.assertTrue(links.read_text(encoding="utf-8").strip())

            output = io.StringIO()
            error = io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                code = check([
                    "-u", str(links), "-l", "student",
                    "-p", "test-password", "--max-total", "1",
                ])

            self.assertEqual(code, 0, error.getvalue())
            self.assertIn("[НЕУСПЕШНО]", output.getvalue())
            self.assertEqual(self.server.post_paths, ["/bitrix/admin/?login=yes"])

    def test_js_fallback_and_browser_http_do_not_click_or_require_form(self):
        adapters = [TemplateFormAdapter(ProxyHttpClient(), None, BrowserCheckConfig(headless=True, timeout_seconds=5)),
                    BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5)),
                    BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5), checker=BrowserHttpChecker())]
        for adapter in adapters:
            with self.subTest(adapter=type(adapter).__name__):
                before = len(self.server.posts)
                outcome = adapter.attempt(self.job("js"), Credential("student", "test-password"))
                self.assertEqual(outcome.status, OutcomeStatus.SUCCESS, outcome.detail)
                self.assertEqual(len(self.server.posts) - before, 1)
                self.assertEqual(self.server.post_paths[-1], "/bitrix/admin/?login=yes")

    def test_browser_protection_stops_before_post(self):
        adapter = BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5))
        result = adapter.attempt(self.job("pre-captcha"), Credential("student", "test-password"))
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.evidence["reason"], "challenge")
        self.assertEqual(self.server.posts, [])
