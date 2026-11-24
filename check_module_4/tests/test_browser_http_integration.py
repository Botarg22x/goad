"""Local browser capture -> HTTP checks; never contacts external accounts."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

from authchecker.browser import BrowserCheckConfig, run_browser_check
from authchecker.browser_http import AdaptiveBrowserChecker, BrowserHttpChecker
from authchecker.models import Credential, OutcomeStatus


class _ReplayLab(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _ReplayHandler)
        self.sequence = 0
        self.posts = []

    @property
    def login_url(self):
        return f"http://127.0.0.1:{self.server_port}/login"


class _ReplayHandler(BaseHTTPRequestHandler):
    server: _ReplayLab

    def log_message(self, *_args):
        pass

    def _reply(self, body, headers=None):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.server.sequence += 1
        token = f"private-token-{self.server.sequence}"
        if self.path.startswith("/js-shell"):
            form = (
                '<form method="post" action="/js-shell-session">'
                '<input name="username" autocomplete="username">'
                '<input name="password" type="password" autocomplete="current-password">'
                '<button type="submit">Log in</button></form>'
            )
            self._reply('<div id="app"></div><script>document.querySelector("#app").innerHTML = '
                        + json.dumps(form) + ';</script>')
            return
        if self.path == "/account":
            self._reply('<h1>Account</h1><a id="logout" href="/logout">Logout</a>')
            return
        if self.path == "/js-form":
            self._reply(
                '<form id="login-form">'
                '<input id="input-21" type="text" autocomplete="login">'
                '<input name="password" type="password">'
                '<button type="submit">Log in</button></form>'
                '<script>document.querySelector("form").onsubmit = async event => {'
                'event.preventDefault(); const response = await fetch("/js-session", {'
                'method:"POST", body:new URLSearchParams({'
                'username:document.querySelector("#input-21").value,'
                'password:document.querySelector("[name=password]").value})});'
                'document.body.innerHTML = await response.text();};</script>'
            )
            return
        script = (
            '<script>document.querySelector("form").onsubmit = async event => {'
            'event.preventDefault(); const response = await fetch("/session", {'
            'method:"POST", headers:{"X-CSRF-Token":document.querySelector("[name=csrf_token]").value},'
            'body:new URLSearchParams(new FormData(event.target))});'
            'document.body.innerHTML = await response.text();};</script>'
        ) if self.path != "/native" else ""
        self._reply(
            '<form method="post" action="/session">'
            f'<input type="hidden" name="csrf_token" value="{token}">'
            '<input name="username" autocomplete="username">'
            '<input type="password" name="password" autocomplete="current-password">'
            '<button type="submit">Log in</button></form>' + script,
            {"Set-Cookie": "private_session=local-only; HttpOnly; SameSite=Lax; Path=/"},
        )

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        fields = parse_qs(body)
        self.server.posts.append((fields, self.headers.get("Cookie"), self.headers.get("X-CSRF-Token")))
        if self.path == "/js-shell-session":
            valid = fields.get("username") == ["student"] and fields.get("password") == ["local-good-password"]
            self.send_response(303)
            self.send_header("Location", "/account" if valid else "/js-shell?retry=1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/js-session":
            valid_password = fields.get("username") == ["student"] and fields.get("password") == ["local-good-password"]
            self._reply('<a id="logout" href="/logout">Logout</a>' if valid_password else '<p id="failure">Invalid username or password</p>')
            return
        fresh_token = f"private-token-{self.server.sequence}"
        valid_session = (
            fields.get("csrf_token") == [fresh_token]
            and self.headers.get("X-CSRF-Token") in {None, fresh_token}
            and "private_session=local-only" in self.headers.get("Cookie", "")
        )
        valid_password = fields.get("username") == ["student"] and fields.get("password") == ["local-good-password"]
        if valid_session and valid_password:
            self._reply('<a id="logout" href="/logout">Logout</a>')
        else:
            self._reply('<p id="failure">Invalid username or password</p>')


class BrowserHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise unittest.SkipTest("Playwright unavailable") from exc
        try:
            with sync_playwright() as playwright:
                options = {"headless": True}
                executable = shutil.which("chromium") or shutil.which("chromium-browser")
                if executable:
                    options["executable_path"] = executable
                browser = playwright.chromium.launch(**options)
                browser.close()
        except Exception as exc:
            raise unittest.SkipTest("Chromium unavailable") from exc
        cls.lab = _ReplayLab()
        cls.thread = threading.Thread(target=cls.lab.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()
        cls.thread.join(3)

    def setUp(self):
        self.lab.sequence = 0
        self.lab.posts.clear()

    def test_bootstrap_once_then_two_http_attempts_with_refreshed_csrf_and_cookies(self):
        checker = BrowserHttpChecker(timeout_seconds=3)
        config = BrowserCheckConfig(headless=True, timeout_seconds=5)
        submissions = []

        def before_submit(_waiter):
            submissions.append(len(self.lab.posts))

        with patch("authchecker.browser_http.run_browser_check", wraps=run_browser_check) as browser:
            first = checker(self.lab.login_url, Credential("student", "local-wrong-password"), config=config, before_submit=before_submit)
            second = checker(self.lab.login_url, Credential("student", "local-good-password"), config=config, before_submit=before_submit)
        self.assertEqual(first.outcome.status, OutcomeStatus.FAILURE, (first.outcome.detail, dict(first.outcome.evidence)))
        self.assertEqual(second.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual((first.attempted_count, second.attempted_count), (1, 1))
        self.assertEqual(browser.call_count, 1)
        self.assertEqual(submissions, [0, 1])
        self.assertEqual(len(self.lab.posts), 2)
        tokens = [post[0]["csrf_token"][0] for post in self.lab.posts]
        self.assertEqual(len(set(tokens)), 2)
        self.assertNotIn("private-token-1", tokens)
        self.assertEqual([post[2] for post in self.lab.posts], tokens)
        self.assertEqual([post[0]["password"][0] for post in self.lab.posts], ["local-wrong-password", "local-good-password"])

    def test_native_form_navigation_is_captured_without_duplicate_submission(self):
        checker = BrowserHttpChecker(timeout_seconds=3)
        result = checker(
            self.lab.login_url.replace("/login", "/native"),
            Credential("student", "local-good-password"),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5),
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result.outcome.detail)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.lab.posts), 1)
        self.assertNotEqual(self.lab.posts[0][0]["csrf_token"], ["private-token-1"])

    def test_js_form_without_method_captures_post_in_browser(self):
        checker = BrowserHttpChecker(timeout_seconds=3)
        result = checker(
            self.lab.login_url.replace("/login", "/js-form"),
            Credential("student", "local-good-password"),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5),
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result.outcome.detail)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.lab.posts), 1)
        self.assertEqual(self.lab.posts[0][0]["password"], ["local-good-password"])

    def test_auto_mode_uses_browser_before_js_only_login_post_and_reads_303_result(self):
        checker = AdaptiveBrowserChecker(timeout_seconds=3)
        config = BrowserCheckConfig(headless=True, timeout_seconds=5)
        progress = []
        url = self.lab.login_url.replace("/login", "/js-shell")
        wrong = checker(url, Credential("student", "local-wrong-password"), config=config, on_progress=progress.append)
        correct = checker(url, Credential("student", "local-good-password"), config=config, on_progress=progress.append)
        self.assertEqual(wrong.outcome.status, OutcomeStatus.FAILURE, wrong)
        self.assertEqual(correct.outcome.status, OutcomeStatus.SUCCESS, correct)
        self.assertEqual((wrong.attempted_count, correct.attempted_count), (1, 1))
        self.assertEqual(len(self.lab.posts), 2)
        self.assertTrue(any("JavaScript" in line for line in progress))

    def test_cli_retains_limits_and_does_not_persist_captured_session(self):
        from authchecker.cli import main

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            audit = Path(temporary) / "audit.jsonl"
            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                result = main([
                    "run", "--live", "--url", self.lab.login_url,
                    "--browser-http", "--headless", "--browser-timeout", "5",
                    "--login", "student", "--password", "local-wrong-password",
                    "--password", "local-good-password", "--max-total", "2",
                    "--max-per-account", "2", "--rate", "10", "--threads", "1",
                    "--audit", str(audit), "--save-report", str(report), "--compact",
                ])
            self.assertEqual(result, 0, errors.getvalue())
            payload = json.loads(report.read_text())
            self.assertEqual(payload["mode"], "browser_http")
            self.assertEqual(payload["attempted_count"], 2)
            self.assertEqual(payload["checked_count"], 2)
            self.assertEqual(payload["outcomes"], {"failure": 1, "success": 1})
            self.assertIn("УСПЕШНО", output.getvalue())
            self.assertEqual(len(self.lab.posts), 2)
            artifacts = report.read_text() + audit.read_text()
            for secret in ("local-good-password", "local-wrong-password", "private-token-", "private_session", "local-only"):
                self.assertNotIn(secret, artifacts)


if __name__ == "__main__":
    unittest.main()
