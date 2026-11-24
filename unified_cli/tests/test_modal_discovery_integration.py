"""Discover a root-page login modal through the real unified CLI and browser."""

from __future__ import annotations

import _support  # noqa: F401

import importlib.util
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from goad.direct_run import direct_run_main


_ROOT_HTML = """<!doctype html><html><body>
<button type="button" id="open-dialog">Вход</button>
<div id="dialog"></div>
<script>
document.getElementById('open-dialog').onclick = async () => {
    const html = await (await fetch('/dialog-data')).text();
    setTimeout(() => { document.getElementById('dialog').innerHTML = html; }, 150);
};
</script></body></html>"""
_DIALOG_HTML = """<form method="post" action="/session">
<input name="username" autocomplete="username">
<input name="password" type="password" autocomplete="current-password">
<button type="submit">Войти</button>
</form>"""


class _ModalLab(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ModalHandler)
        self.requests: list[tuple[str, str]] = []

    @property
    def root_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/"


class _ModalHandler(BaseHTTPRequestHandler):
    server: _ModalLab

    def log_message(self, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self.server.requests.append(("GET", path))
        if path == "/":
            body, status = _ROOT_HTML, 200
        elif path == "/dialog-data":
            body, status = _DIALOG_HTML, 200
        else:
            body, status = "Not found", 404
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        self.server.requests.append(("POST", urlsplit(self.path).path))
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _NoPromptInput(io.StringIO):
    def isatty(self) -> bool:
        return True

    def readline(self, *_args: object, **_kwargs: object) -> str:
        raise AssertionError("discover-only must not ask to select auth targets")


@unittest.skipUnless(
    importlib.util.find_spec("authpoints") and importlib.util.find_spec("playwright"),
    "module 3 or Playwright unavailable",
)
class ModalDiscoveryIntegrationTests(unittest.TestCase):
    def test_discover_only_finds_lazy_login_modal_without_a_login_url(self) -> None:
        from authpoints.runners.katana import resolve_system_chromium
        from playwright.sync_api import sync_playwright

        if resolve_system_chromium() is None:
            with sync_playwright() as playwright:
                if not Path(playwright.chromium.executable_path).is_file():
                    self.skipTest("Chromium unavailable")

        server = _ModalLab()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            initial_output = json.dumps({
                "request": {"method": "GET", "endpoint": server.root_url},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": _ROOT_HTML,
                },
            })
            output, errors = io.StringIO(), io.StringIO()
            with (
                tempfile.TemporaryDirectory() as directory,
                patch("authpoints.pipeline.run_katana", side_effect=[initial_output, ""]) as katana,
                patch("builtins.input", side_effect=AssertionError("unexpected auth prompt")),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                code = direct_run_main(
                    [
                        "-u", server.root_url, "--discover-only", "--no-standard-paths",
                        "--katana-max-total-pages", "3", "--artifacts", directory,
                    ],
                    stdin=_NoPromptInput(),
                    stdout=output,
                    stderr=errors,
                    run_id="lazy-root-modal",
                )

                self.assertEqual(code, 0, errors.getvalue())
                self.assertEqual(katana.call_count, 2)
                report_dir = Path(directory, "lazy-root-modal")
                report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
                findings = [item for item in report["findings"] if item["auth_type"] == "password_form"]
                self.assertEqual([item["endpoint"] for item in findings], [server.root_url])
                diagnostics = report["config"]["browser_diagnostics"]
                self.assertTrue(diagnostics)
                self.assertTrue(diagnostics[-1]["password_field_found"])
                self.assertEqual(diagnostics[-1]["click_count"], 1)
                self.assertTrue(Path(diagnostics[-1]["dom_path"]).is_file())
                self.assertTrue(Path(diagnostics[-1]["diagnostics_path"]).is_file())
                self.assertTrue(list((report_dir / "discovery-debug").glob("*.html")))
                self.assertTrue(list((report_dir / "discovery-debug").glob("*.json")))
                self.assertFalse((report_dir / "audit.jsonl").exists())

            self.assertIn(("GET", "/dialog-data"), server.requests)
            self.assertTrue(all(method == "GET" for method, _path in server.requests))
            self.assertTrue(all(path in {"/", "/dialog-data", "/favicon.ico"} for _method, path in server.requests))
            self.assertNotIn("Выберите номера", output.getvalue())
            self.assertNotIn("[МОДУЛЬ 4]", errors.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
