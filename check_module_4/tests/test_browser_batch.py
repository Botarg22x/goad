"""Exercise the real CLI, scheduler and browser on an isolated local lab."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from authchecker.cli import main
from authchecker.browser import run_browser_check

from test_browser import _CSRF, _PASSWORD, _USERNAME, _LabHandler, _LabServer, _form


class _SessionHandler(_LabHandler):
    def do_GET(self) -> None:
        if urlsplit(self.path).path != "/isolated":
            return super().do_GET()
        with self.server.lock:
            session_number = 1 + sum(
                request["method"] == "GET" and request["path"] == "/isolated"
                for request in self.server.requests
            )
            session = f"session-{session_number}"
            self.server.requests.append({
                "method": "GET", "path": "/isolated", "body": "",
                "cookie": self.headers.get("Cookie", ""), "session": session,
            })
        self._reply(
            _form(action="/session-isolated", hidden=True).replace(_CSRF, "csrf-" + session),
            headers={"Set-Cookie": f"lab_session={session}; HttpOnly; SameSite=Lax; Path=/"},
        )

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/session-isolated":
            return super().do_POST()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        fields = parse_qs(body)
        cookie = self.headers.get("Cookie", "")
        self.server.record({
            "method": "POST", "path": "/session-isolated", "body": body,
            "cookie": cookie, "received_at": time.monotonic(),
        })
        session = next(
            (value.removeprefix("lab_session=") for value in cookie.split("; ") if value.startswith("lab_session=")),
            "",
        )
        valid_session = bool(session) and fields.get("csrf_token") == ["csrf-" + session]
        valid_password = fields.get("username") == [_USERNAME] and fields.get("password") == [_PASSWORD]
        if valid_session and valid_password:
            self._reply(
                '<h1>Account</h1><a href="/logout" id="logout">Log out</a>',
                headers={"Set-Cookie": "authenticated=yes; HttpOnly; Path=/"},
            )
        else:
            self._reply(
                '<p id="error">Invalid username or password</p>' + _form(),
                headers={"Set-Cookie": "previous_attempt=failed; HttpOnly; Path=/"},
            )


class BrowserBatchIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise unittest.SkipTest("Playwright is not installed") from exc
        executable = shutil.which("chromium") or shutil.which("chromium-browser")
        try:
            with sync_playwright() as playwright:
                options = {"headless": True}
                if executable:
                    options["executable_path"] = executable
                browser = playwright.chromium.launch(**options)
                browser.close()
        except Exception as exc:
            raise unittest.SkipTest(f"Chromium is unavailable: {exc}") from exc

    def test_parallel_browsers_share_actual_credential_post_rate(self) -> None:
        lab = _LabServer()
        lab.RequestHandlerClass = _SessionHandler
        server_thread = threading.Thread(target=lab.serve_forever, daemon=True)
        server_thread.start()
        pending_submissions = threading.Barrier(2, timeout=15)

        def synchronized_check(url, credential, **kwargs):
            rate_gate = kwargs.pop("before_submit")

            def before_submit(waiter):
                # Both real Chromium POSTs are paused here simultaneously.
                # The shared gate, rather than browser startup timing, must
                # determine the interval observed by the local HTTP server.
                pending_submissions.wait()
                rate_gate(waiter)

            return run_browser_check(url, credential, before_submit=before_submit, **kwargs)

        try:
            with tempfile.TemporaryDirectory() as directory:
                output = io.StringIO()
                with (
                    patch("authchecker.cli.run_browser_check", side_effect=synchronized_check),
                    redirect_stdout(output), redirect_stderr(io.StringIO()),
                ):
                    code = main([
                        "run", "--live", "--browser", "--headless",
                        "--url", lab.base_url + "/isolated", "--login", _USERNAME,
                        "--password", "first-wrong-password", "--password", "second-wrong-password",
                        "--threads", "2", "--rate", "1", "--max-total", "2", "--max-per-account", "2",
                        "--browser-timeout", "20", "--failure-selector", "#error",
                        "--audit", str(Path(directory, "audit.jsonl")),
                    ])
                self.assertEqual(code, 0)
                data = json.loads(output.getvalue())
                self.assertEqual(data["checked_count"], 2)
                self.assertEqual(data["attempted_count"], 2)
                self.assertEqual(data["outcomes"], {"failure": 2})
                posts = lab.posts()
                self.assertEqual(len(posts), 2)
                timestamps = sorted(post["received_at"] for post in posts)
                self.assertGreaterEqual(timestamps[1] - timestamps[0], 0.8)
                initial_gets = [request for request in lab.requests if request["path"] == "/isolated"]
                self.assertEqual(len(initial_gets), 2)
                self.assertEqual(len({request["session"] for request in initial_gets}), 2)
                self.assertTrue(all(request["cookie"] == "" for request in initial_gets))
        finally:
            lab.shutdown()
            lab.server_close()
            server_thread.join(timeout=3)

    def test_batch_checks_wrong_then_correct_in_fresh_sessions_and_stops(self) -> None:
        lab = _LabServer()
        lab.RequestHandlerClass = _SessionHandler
        server_thread = threading.Thread(target=lab.serve_forever, daemon=True)
        server_thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                audit = Path(directory, "audit.jsonl")
                report = Path(directory, "report.json")
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    code = main([
                        "run", "--live", "--browser", "--headless",
                        "--url", lab.base_url + "/isolated",
                        "--login", _USERNAME,
                        "--password", "local-wrong-password",
                        "--password", _PASSWORD,
                        "--password", "must-not-be-submitted",
                        "--max-total", "3", "--max-per-account", "3",
                        "--threads", "1", "--rate", "10", "--browser-timeout", "5",
                        "--success-selector", "#logout", "--failure-selector", "#error",
                        "--audit", str(audit), "--save-report", str(report),
                    ])
                self.assertEqual(code, 0)
                data = json.loads(output.getvalue())
                self.assertEqual(data["checked_count"], 2)
                self.assertEqual(data["attempted_count"], 2)
                self.assertEqual(data["outcomes"], {"failure": 1, "success": 1})
                self.assertEqual(data["successes"][0]["password"], _PASSWORD)

                posts = lab.posts()
                self.assertEqual(len(posts), 2)
                self.assertEqual(
                    [parse_qs(request["body"])["password"] for request in posts],
                    [["local-wrong-password"], [_PASSWORD]],
                )
                initial_gets = [request for request in lab.requests if request["path"] == "/isolated"]
                self.assertEqual(len(initial_gets), 2)
                self.assertTrue(all(request["cookie"] == "" for request in initial_gets))
                self.assertEqual(len({request["session"] for request in initial_gets}), 2)
                for initial, submitted in zip(initial_gets, posts, strict=True):
                    self.assertIn("lab_session=" + initial["session"], submitted["cookie"])
                    self.assertEqual(parse_qs(submitted["body"])["csrf_token"], ["csrf-" + initial["session"]])

                events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(sum(event["event"] == "attempt" for event in events), 2)
                artifact_text = report.read_text(encoding="utf-8") + audit.read_text(encoding="utf-8")
                for secret in (_PASSWORD, "local-wrong-password", "must-not-be-submitted", "csrf-session-", "lab_session="):
                    self.assertNotIn(secret, artifact_text)
        finally:
            lab.shutdown()
            lab.server_close()
            server_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
