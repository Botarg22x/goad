"""End-to-end batch runs against a local lab, with no external accounts."""

from __future__ import annotations

import _support  # noqa: F401

import importlib.util
import io
import json
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from goad.direct_run import direct_run_main


class _TargetLab(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _TargetHandler)
        self.requests = []

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server_port}"


class _TargetHandler(BaseHTTPRequestHandler):
    server: _TargetLab

    def log_message(self, *_args):
        pass

    def _reply(self, body, *, status=200, headers=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.requests.append(("GET", path, None, self.headers.get("Cookie", "")))
        if path in {"/a/login", "/b/login"}:
            group = path.split("/")[1]
            self._reply(
                f'<form method="post" action="/{group}/session">'
                '<input name="username" autocomplete="username">'
                '<input type="password" name="password" autocomplete="current-password">'
                '<button type="submit">Log in</button></form>',
                headers={"Set-Cookie": f"lab_session={group}; HttpOnly; SameSite=Lax; Path=/{group}"},
            )
        elif path in {"/a/account", "/b/account"}:
            self._reply('<a id="logout" href="/logout">Logout</a>')
        else:
            self._reply("Not found", status=404)

    def do_POST(self):
        path = urlsplit(self.path).path
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        self.server.requests.append(("POST", path, body, self.headers.get("Cookie", "")))
        if body.get("username") == ["student"] and body.get("password") == ["local-good-password"]:
            group = path.split("/")[1]
            self._reply("", status=303, headers={"Location": f"/{group}/account"})
        else:
            self._reply('<p id="error">Invalid username or password</p>', status=403)


@unittest.skipUnless(importlib.util.find_spec("authchecker") and importlib.util.find_spec("authpoints"), "module 3/4 unavailable")
class TargetFileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.lab = _TargetLab()
        self.thread = threading.Thread(target=self.lab.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.lab.shutdown()
        self.lab.server_close()
        self.thread.join(3)

    def require_browser(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("Playwright unavailable")
        try:
            with sync_playwright() as playwright:
                options = {"headless": True}
                executable = shutil.which("chromium") or shutil.which("chromium-browser")
                if executable:
                    options["executable_path"] = executable
                browser = playwright.chromium.launch(**options)
                browser.close()
        except Exception:
            self.skipTest("Chromium unavailable")

    def check_mode(self, mode=None):
        if mode:
            self.require_browser()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets.txt"
            targets.write_text(
                f"\ufeff# Local lab\n{self.lab.base_url}/a/login\n\n"
                f"{self.lab.base_url}/b/login?next=private-token#form\n"
                f"{self.lab.base_url}/a/login\n", encoding="utf-8",
            )
            output, errors = io.StringIO(), io.StringIO()
            args = [
                "--targets-file", str(targets), "--login", "student",
                "--password", "local-wrong-password", "--password", "local-good-password",
                "--max-total", "2", "--max-per-account", "2", "--rate", "10", "--threads", "1",
                "--artifacts", str(root / "artifacts"), "--json",
            ]
            if mode:
                args.extend((mode, "--headless", "--browser-timeout", "5"))
            code = direct_run_main(args, run_id="local-batch", stdout=output, stderr=errors)
            self.assertEqual(code, 0, errors.getvalue())
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["targets_count"], 2)
            self.assertEqual(payload["processed_count"], 2)
            self.assertEqual(payload["limits_scope"], "per_target")
            self.assertEqual([row["result"]["attempted_count"] for row in payload["results"]], [2, 2])
            for row in payload["results"]:
                self.assertEqual(row["result"]["outcomes"], {"failure": 1, "success": 1})
                self.assertTrue(Path(row["report"]).is_file())
                self.assertTrue(Path(row["audit"]).is_file())
            saved = root / "artifacts" / "local-batch" / "report.json"
            saved_text = saved.read_text()
            for secret in ("local-good-password", "local-wrong-password", "lab_session"):
                self.assertNotIn(secret, saved_text)
            self.assertIn("private-token", saved_text)
            posts = [request for request in self.lab.requests if request[0] == "POST"]
            self.assertEqual([request[1] for request in posts], ["/a/session", "/a/session", "/b/session", "/b/session"])
            self.assertEqual([request[2]["password"][0] for request in posts], ["local-wrong-password", "local-good-password"] * 2)
            if mode:
                self.assertEqual([request[3] for request in posts], ["lab_session=a", "lab_session=a", "lab_session=b", "lab_session=b"])
            for method, path, *_ in self.lab.requests:
                if method == "GET":
                    self.assertIn(path, {"/a/login", "/b/login", "/a/account", "/b/account", "/favicon.ico"})

    def test_exact_http_batch_two_targets(self):
        self.check_mode()

    def test_native_browser_batch_two_targets(self):
        self.check_mode("--browser")

    def test_browser_http_batch_two_targets(self):
        self.check_mode("--browser-http")


if __name__ == "__main__":
    unittest.main()
