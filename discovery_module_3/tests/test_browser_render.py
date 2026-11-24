from __future__ import annotations

import json
import shutil
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from authpoints.browser_diagnostics import diagnostic_url, sanitized_dom
from authpoints.browser_render import (
    _consume_auto_resource_budget, _fetch_with_ca, _request_block_reason, render_pages,
)
from authpoints.config import KatanaConfig
from authpoints.parsers.katana_jsonl import parse_katana_jsonl
from authpoints.runners.common import ToolError
from authpoints.runners.katana import KatanaPartialError, run_katana
from authpoints.scope import Scope


class _JsLoginHandler(BaseHTTPRequestHandler):
    post_count = 0
    otp_get_count = 0
    fragment_count = 0
    external_count = 0
    cdn_fetch_count = 0
    script_count = 0
    auto_script_count = 0

    def do_GET(self) -> None:
        if self.path == "/redirect-to-login":
            self.send_response(301)
            self.send_header("Location", "/login/")
            self.end_headers()
            return
        if self.path == "/redirect-outside":
            self.send_response(302)
            self.send_header(
                "Location", f"https://localhost:{self.server.server_port}/external-login",
            )
            self.end_headers()
            return
        if "send_email_otp" in self.path:
            self.__class__.otp_get_count += 1
        if self.path == "/ui/login-fragment":
            self.__class__.fragment_count += 1
            body = (
                b"<form action='/session?csrf=FORM_SECRET' method='post'>"
                b"<input name='username' value='PRIVATE_USER'>"
                b"<input name='password' type='password' value='PRIVATE_PASSWORD'>"
                b"<input type='hidden' name='csrf' value='TOKEN_SECRET'>"
                b"<button>Sign in</button></form>"
            )
        elif self.path == "/lazy":
            body = (
                "<html><body><button type='button' id='signin'>Войти</button>"
                "<div id='modal'></div><script>document.getElementById('signin').onclick = async () => {"
                "fetch('/signups/send_email_otp').catch(() => {});"
                "fetch('/signups/send_email_otp', {method:'POST'}).catch(() => {});"
                "const html = await (await fetch('/ui/login-fragment')).text();"
                "setTimeout(() => document.getElementById('modal').innerHTML=html, 450);"
                "};</script></body></html>"
            ).encode("utf-8")
        elif self.path == "/anchor":
            body = "<html><body><a href='/ui/login-fragment'>Вход</a></body></html>".encode()
        elif self.path == "/registration":
            body = (
                "<html><body><form method='post'>"
                "<input name='email' type='email'>"
                "<input name='password' type='password' autocomplete='new-password'>"
                "<button type='submit'>Create account</button></form>"
                "<a href='/login/'>Log in</a></body></html>"
            ).encode()
        elif self.path == "/registration-modal":
            body = (
                "<html><body><form method='post'>"
                "<input name='email' type='email'>"
                "<input name='password' type='password' autocomplete='new-password'>"
                "<button type='submit'>Create account</button></form>"
                "<button type='button' id='open-login'>Log in</button><div id='modal'></div>"
                "<script>document.getElementById('open-login').onclick=()=>setTimeout(()=>{"
                "document.getElementById('modal').innerHTML="
                "\"<form action='/session' method='post'><input name='email' type='email'>"
                "<input name='password' type='password' autocomplete='current-password'>"
                "<button type='submit'>Log in</button></form>\";},450);</script>"
                "</body></html>"
            ).encode()
        elif self.path == "/auto-cdn":
            scripts = "".join(
                f'<script src="http://localhost:{self.server.server_port}/auto-app.js?part={index}"></script>'
                for index in range(5)
            )
            body = f'<html><body><div id="app"></div>{scripts}</body></html>'.encode()
        elif self.path.startswith("/auto-app.js"):
            self.__class__.auto_script_count += 1
            body = (
                "document.getElementById('app').innerHTML="
                "'<button type=button aria-label=\"I already have an account\" id=open-login>Log in</button>'"
                "+'<div id=modal></div>';"
                "document.getElementById('open-login').onclick=()=>setTimeout(()=>{"
                "document.getElementById('modal').innerHTML="
                "\"<form aria-label='login form'><input name='email' type='email'>"
                "<input name='password' type='password' autocomplete='current-password'>"
                "<button type='submit'>Log in</button></form>\";},300);"
            ).encode() if "part=0" in self.path else b"/* secondary app chunk */"
        elif self.path == "/login/":
            body = (
                "<html><body><form action='/session' method='post'>"
                "<input name='email' type='email'>"
                "<input name='password' type='password' autocomplete='current-password'>"
                "<button type='submit'>Log in</button></form></body></html>"
            ).encode()
        elif self.path == "/external-resource":
            body = (
                "<html><body><button type='button' id='signin'>Войти</button>"
                "<div id='modal'></div>"
                f"<script src='http://localhost:{self.server.server_port}/lazy.js?key=SCRIPT_SECRET'></script>"
                "</body></html>"
            ).encode("utf-8")
        elif self.path.startswith("/lazy.js"):
            self.__class__.script_count += 1
            body = (
                f"fetch('http://localhost:{self.server.server_port}/cdn-private').catch(() => {{}});"
                "document.getElementById('signin').onclick=async()=>{"
                "document.getElementById('modal').innerHTML=await(await fetch('/ui/login-fragment')).text();};"
            ).encode()
        elif self.path == "/cdn-private":
            self.__class__.cdn_fetch_count += 1
            body = b"not an asset"
        elif self.path == "/offscope":
            body = (
                "<html><body><button type='button' id='signin'>Sign in</button>"
                f"<script>document.getElementById('signin').onclick=()=>location.href='http://localhost:{self.server.server_port}/external-login';</script>"
                "</body></html>"
            ).encode()
        elif self.path == "/external-login":
            self.__class__.external_count += 1
            body = b"<form><input type='password'></form>"
        elif self.path == "/unsafe-actions":
            body = (
                "<html><body><form action='/session' method='post'><input name='email'>"
                "<button>Sign in</button></form>"
                "<button disabled type='button'>Войти</button>"
                f"<a href='http://localhost:{self.server.server_port}/external-login'>Log in</a>"
                "</body></html>"
            ).encode("utf-8")
        elif self.path == "/toggle":
            body = (
                b"<html><body><form action='/signups/send_email_otp'>"
                b"<input name='email'><button>Continue</button></form>"
                b"<button type='button' id='signin'>Sign in</button>"
                b"<script>document.getElementById('signin').onclick = () => {"
                b"fetch('/signups/send_email_otp').catch(() => {});"
                b"document.body.innerHTML = \"<form action='/session' method='post'>"
                b"<input name='username'><input name='password' type='password'>"
                b"<button>Log in</button></form>\";};</script></body></html>"
            )
        else:
            body = (
                b"<html><body><div id='root'></div><script>"
                b"document.getElementById('root').innerHTML = "
                b"\"<form action='/session' method='post'>"
                b"<input name='username'><input name='password' type='password'>"
                b"</form>\";"
                b"</script></body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/javascript; charset=utf-8" if self.path.startswith(("/lazy.js", "/auto-app.js")) else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self.__class__.post_count += 1
        self.send_response(405)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class _ConnectProxyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline(65536)
        if not request_line.startswith(b"CONNECT 127.0.0.1:"):
            return
        while self.rfile.readline(65536) not in {b"\r\n", b"\n", b""}:
            pass
        self.server.connect_count += 1  # type: ignore[attr-defined]
        with socket.create_connection(("127.0.0.1", self.server.target_port)) as upstream:  # type: ignore[attr-defined]
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            while True:
                ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)


def _browser_available() -> bool:
    if not shutil.which("openssl") or not shutil.which("chromium"):
        return False
    try:
        from playwright._impl._driver import compute_driver_executable
    except ImportError:
        return False
    driver, cli = compute_driver_executable()
    return Path(driver).is_file() and Path(cli).is_file()


class BrowserRenderTests(unittest.TestCase):
    def test_auto_resource_budget_limits_hosts_and_redirect_hops(self) -> None:
        scope = Scope.from_inputs([], ["https://example.test/"])
        hosts: set[str] = set()
        count = [0]
        for index in range(32):
            request = SimpleNamespace(
                method="GET", url=f"https://cdn{index}.example.com/app.js",
                resource_type="script",
            )
            self.assertEqual(
                _consume_auto_resource_budget(request, scope, set(), hosts, count), "",
            )
        self.assertEqual(len(hosts), 32)
        self.assertEqual(count[0], 32)
        extra = SimpleNamespace(
            method="GET", url="https://extra.example.com/app.js", resource_type="script",
        )
        self.assertEqual(
            _consume_auto_resource_budget(extra, scope, set(), hosts, count),
            "external_asset_host_limit",
        )
        count[0] = 128
        known = SimpleNamespace(
            method="GET", url="https://cdn0.example.com/next.js", resource_type="script",
        )
        self.assertEqual(
            _consume_auto_resource_budget(known, scope, set(), hosts, count),
            "external_asset_request_limit",
        )

    def test_external_asset_fetch_drops_session_headers_and_blocks_private_redirect(self) -> None:
        class Response:
            def __init__(self, status: int, headers: dict[str, str]) -> None:
                self.code, self.headers = status, headers

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, size: int) -> bytes:
                return b"/* asset */"

        class Opener:
            def __init__(self, response: Response) -> None:
                self.response = response
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                return self.response

        scope = Scope.from_inputs([], ["https://example.test/"])
        request = SimpleNamespace(
            method="GET", url="https://cdn.example.com/app.js", resource_type="script",
            headers={
                "Cookie": "session=private", "Authorization": "Bearer private",
                "Referer": "https://example.test/account", "Accept": "*/*",
            },
        )
        opener = Opener(Response(200, {"Content-Type": "application/javascript"}))
        _fetch_with_ca(
            request, opener=opener, timeout_seconds=2, max_response_bytes=1024,
            scope=scope, resource_hosts=set(), auto_resource_hosts={"cdn.example.com"},
            auto_resource_count=[1],
        )
        sent = opener.requests[0]
        self.assertIsNone(sent.get_header("Cookie"))
        self.assertIsNone(sent.get_header("Authorization"))
        self.assertIsNone(sent.get_header("Referer"))
        self.assertEqual(sent.get_header("Accept"), "*/*")

        redirecting = Opener(Response(302, {"Location": "http://127.0.0.1/private.js"}))
        with self.assertRaisesRegex(ToolError, "outside_scope"):
            _fetch_with_ca(
                request, opener=redirecting, timeout_seconds=2,
                max_response_bytes=1024, scope=scope, resource_hosts=set(),
                auto_resource_hosts={"cdn.example.com"}, auto_resource_count=[1],
            )
        self.assertEqual(len(redirecting.requests), 1)

    def test_request_policy_allows_query_credentials_but_blocks_logout(self) -> None:
        scope = Scope.from_inputs([], ["https://example.test/"])
        logout = SimpleNamespace(
            method="GET", url="https://example.test/logout", resource_type="script",
        )
        self.assertEqual(_request_block_reason(logout, scope, set()), "logout_url")
        for url in (
            "https://example.test/assets/app.js?accessToken=secret",
            "https://example.test/login?next=https%3A%2F%2Fexample.test%2Fcb%3Fcsrfmiddlewaretoken%3Dsecret",
            "https://example.test/api?email=user%40example.test",
        ):
            with self.subTest(url=url):
                request = SimpleNamespace(method="GET", url=url, resource_type="script")
                self.assertEqual(_request_block_reason(request, scope, set()), "")
        request = SimpleNamespace(
            method="GET",
            url="https://cdn.example.test/app.js?auth[password]=secret",
            resource_type="script",
        )
        self.assertEqual(_request_block_reason(request, scope, {"cdn.example.test"}), "")
        request = SimpleNamespace(method="GET", url="https://example.test/login?next=/account", resource_type="document")
        self.assertEqual(_request_block_reason(request, scope, set()), "")
        for resource_type, allowed in (
            ("script", True), ("stylesheet", True), ("font", True),
            ("image", True), ("document", False), ("fetch", False),
        ):
            with self.subTest(resource_type=resource_type):
                request = SimpleNamespace(
                    method="GET", url="https://cdn.example.com/app.js",
                    resource_type=resource_type,
                )
                self.assertEqual(
                    _request_block_reason(request, scope, set()) == "",
                    allowed,
                )
        for host in ("localhost", "cdn.localhost", "asset.local", "127.0.0.1", "192.168.1.5"):
            with self.subTest(host=host):
                request = SimpleNamespace(
                    method="GET", url=f"http://{host}/app.js", resource_type="script",
                )
                self.assertEqual(_request_block_reason(request, scope, set()), "outside_scope")
        request = SimpleNamespace(
            method="POST", url="https://cdn.example.com/app.js", resource_type="script",
        )
        self.assertEqual(_request_block_reason(request, scope, set()), "non_read_only_method")

    def test_diagnostic_dom_keeps_url_tokens_but_drops_form_values(self) -> None:
        body = (
            "<html><body><script>window.csrf='SCRIPT_SECRET';</script>"
            "<input name='csrf' value='TOKEN_SECRET' data-session='DATA_SECRET'>"
            "<input type='password' value='PASSWORD_SECRET'>"
            "<a href='https://user:password@example.com/login?token=QUERY_SECRET#secret'>Вход</a>"
            "<iframe src='javascript:alert(1)'></iframe>"
            "<img src='https://outside.example/track?token=QUERY_SECRET'>"
            "<form action='https://outside.example/send'><button>Submit</button></form>"
            "<textarea>PRIVATE_TEXT</textarea><!-- COOKIE_SECRET --></body></html>"
        )
        safe = sanitized_dom(body)
        self.assertIn("name=\"csrf\"", safe)
        self.assertIn("https://example.com/login", safe)
        self.assertIn("data-discovery-href=", safe)
        self.assertIn("default-src 'none'", safe)
        self.assertNotRegex(safe, r"\s(?:src|href|action)\s*=")
        self.assertNotIn("javascript:", safe)
        for secret in ("SCRIPT_SECRET", "TOKEN_SECRET", "DATA_SECRET", "PASSWORD_SECRET", "PRIVATE_TEXT", "COOKIE_SECRET"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, safe)
        self.assertIn("token=QUERY_SECRET", safe)
        self.assertEqual(diagnostic_url("https://u:p@example.com:443/path?q=secret#frag"), "https://example.com:443/path?q=secret")

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_lazy_modal_get_loads_but_otp_and_post_are_never_sent(self) -> None:
        _JsLoginHandler.post_count = 0
        _JsLoginHandler.otp_get_count = 0
        _JsLoginHandler.fragment_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                url = f"http://127.0.0.1:{server.server_port}/lazy"
                output = render_pages(
                    [url],
                    config=KatanaConfig(
                        chrome_executable=shutil.which("chromium") or "",
                        timeout_seconds=10,
                        auto_headless_timeout_seconds=10,
                        dom_wait_seconds=0,
                        browser_diagnostics_dir=directory,
                    ),
                    scope=Scope.from_inputs([], [url]),
                )
                observations, errors = parse_katana_jsonl(output)
                self.assertFalse(errors)
                self.assertTrue(any(
                    field.field_type == "password"
                    for observation in observations for form in observation.forms for field in form.fields
                ))
                metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
                self.assertTrue(metadata["password_field_found"])
                self.assertEqual(metadata["final_url"], url)
                self.assertEqual(metadata["click_count"], 1)
                self.assertGreaterEqual(metadata["blocked_count"], 2)
                self.assertTrue(Path(metadata["diagnostics_path"]).is_file())
                dom = Path(metadata["dom_path"]).read_text()
                self.assertIn('type="password"', dom)
                for secret in ("PRIVATE_USER", "PRIVATE_PASSWORD", "TOKEN_SECRET"):
                    self.assertNotIn(secret, dom)
                self.assertIn("csrf=FORM_SECRET", dom)
            self.assertEqual(_JsLoginHandler.fragment_count, 1)
            self.assertEqual(_JsLoginHandler.post_count, 0)
            self.assertEqual(_JsLoginHandler.otp_get_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_page_only_browser_opens_modal_but_does_not_follow_login_link(self) -> None:
        _JsLoginHandler.fragment_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            config = KatanaConfig(
                chrome_executable=shutil.which("chromium") or "",
                dom_wait_seconds=0, timeout_seconds=10,
                auto_headless_timeout_seconds=10,
            )
            scope = Scope.from_inputs([], [base])
            modal = render_pages(
                [base + "/lazy"], config=config, scope=scope,
                same_page_only=True,
            )
            self.assertTrue(json.loads(modal.splitlines()[-1])["discovery_diagnostics"]["password_field_found"])
            _JsLoginHandler.fragment_count = 0
            linked = render_pages(
                [base + "/anchor"], config=config, scope=scope,
                same_page_only=True,
            )
            metadata = json.loads(linked.splitlines()[-1])["discovery_diagnostics"]
            self.assertEqual(metadata["final_url"], base + "/anchor")
            self.assertFalse(metadata["password_field_found"])
            self.assertEqual(_JsLoginHandler.fragment_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_login_anchor_can_follow_same_scope_get(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/anchor"
            output = render_pages(
                [url],
                config=KatanaConfig(chrome_executable=shutil.which("chromium") or "", dom_wait_seconds=0),
                scope=Scope.from_inputs([], [url]),
            )
            metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
            self.assertTrue(metadata["password_field_found"])
            self.assertTrue(metadata["final_url"].endswith("/ui/login-fragment"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_signup_password_does_not_stop_login_link_discovery(self) -> None:
        _JsLoginHandler.post_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/registration"
            output = render_pages(
                [url],
                config=KatanaConfig(
                    chrome_executable=shutil.which("chromium") or "",
                    dom_wait_seconds=0,
                    timeout_seconds=10,
                    auto_headless_timeout_seconds=10,
                ),
                scope=Scope.from_inputs([], [url]),
            )
            observations, errors = parse_katana_jsonl(output)
            self.assertFalse(errors)
            self.assertEqual(len(observations), 2)
            from authpoints.classifier import classify_web
            self.assertFalse(any(
                finding.auth_type == "password_form"
                for finding in classify_web(observations[0])
            ))
            self.assertTrue(any(
                finding.auth_type == "password_form"
                for finding in classify_web(observations[-1])
            ))
            metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
            self.assertEqual(metadata["click_count"], 1)
            self.assertTrue(metadata["login_form_found"])
            self.assertEqual(_JsLoginHandler.post_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_signup_password_does_not_hide_lazy_login_modal_on_same_url(self) -> None:
        _JsLoginHandler.post_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/registration-modal"
            output = render_pages(
                [url],
                config=KatanaConfig(
                    chrome_executable=shutil.which("chromium") or "",
                    dom_wait_seconds=0,
                    timeout_seconds=10,
                    auto_headless_timeout_seconds=10,
                ),
                scope=Scope.from_inputs([], [url]),
            )
            observations, errors = parse_katana_jsonl(output)
            self.assertFalse(errors)
            self.assertEqual(len(observations), 2)
            from authpoints.classifier import classify_web
            self.assertFalse(any(
                finding.auth_type == "password_form"
                for finding in classify_web(observations[0])
            ))
            self.assertTrue(any(
                finding.auth_type == "password_form"
                for finding in classify_web(observations[-1])
            ))
            metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
            self.assertEqual(metadata["final_url"], url)
            self.assertEqual(metadata["click_count"], 1)
            self.assertTrue(metadata["login_form_found"])
            self.assertEqual(_JsLoginHandler.post_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_auto_loads_external_js_without_manual_host_and_opens_login_modal(self) -> None:
        _JsLoginHandler.post_count = 0
        _JsLoginHandler.auto_script_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/auto-cdn"
            # The local fixture stands in for a public CDN; local names stay
            # blocked in production unless explicitly listed.
            with patch("authpoints.browser_render._auto_resource_host_allowed", side_effect=lambda host: host == "localhost"):
                output = render_pages(
                    [url],
                    config=KatanaConfig(
                        chrome_executable=shutil.which("chromium") or "",
                        dom_wait_seconds=0,
                        timeout_seconds=12,
                        auto_headless_timeout_seconds=12,
                    ),
                    scope=Scope.from_inputs([], [url]),
                )
            observations, errors = parse_katana_jsonl(output)
            self.assertFalse(errors)
            from authpoints.classifier import classify_web
            self.assertTrue(any(
                finding.auth_type == "password_form"
                for observation in observations for finding in classify_web(observation)
            ))
            metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
            self.assertEqual(metadata["auto_resource_hosts"], ["localhost"])
            self.assertEqual(metadata["final_url"], url)
            self.assertEqual(metadata["click_count"], 1)
            self.assertTrue(metadata["login_form_found"])
            self.assertGreaterEqual(_JsLoginHandler.auto_script_count, 1)
            self.assertEqual(_JsLoginHandler.post_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_declared_cdn_can_load_script_but_not_fetch_or_navigate(self) -> None:
        _JsLoginHandler.script_count = 0
        _JsLoginHandler.cdn_fetch_count = 0
        _JsLoginHandler.external_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as directory:
                blocked = render_pages(
                    [base + "/external-resource"],
                    config=KatanaConfig(
                        chrome_executable=shutil.which("chromium") or "", dom_wait_seconds=0,
                        timeout_seconds=10, auto_headless_timeout_seconds=10,
                    ),
                    scope=Scope.from_inputs([], [base]),
                )
                blocked_metadata = json.loads(blocked.splitlines()[-1])["discovery_diagnostics"]
                self.assertFalse(blocked_metadata["password_field_found"])
                self.assertIn("localhost", blocked_metadata["blocked_resource_hosts"])
                self.assertEqual(_JsLoginHandler.script_count, 0)
                config = KatanaConfig(
                    chrome_executable=shutil.which("chromium") or "", dom_wait_seconds=0,
                    browser_resource_domains=("localhost",), browser_diagnostics_dir=directory,
                    timeout_seconds=10, auto_headless_timeout_seconds=10,
                )
                output = render_pages([base + "/external-resource"], config=config, scope=Scope.from_inputs([], [base]))
                metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
                self.assertTrue(metadata["password_field_found"])
                self.assertIn("localhost", metadata["blocked_resource_hosts"])
                self.assertEqual(_JsLoginHandler.script_count, 1)
                self.assertEqual(_JsLoginHandler.cdn_fetch_count, 0)
                with self.assertRaises(ToolError):
                    render_pages([base + "/offscope"], config=config, scope=Scope.from_inputs([], [base]))
                diagnostics = [json.loads(path.read_text()) for path in Path(directory).glob("*.json")]
                failed = next(item for item in diagnostics if item["candidate_url"].endswith("/offscope"))
                self.assertGreater(failed["blocked_count"], 0)
                self.assertTrue(failed.get("failure"))
                self.assertEqual(_JsLoginHandler.external_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_page_failure_preserves_previous_result_and_continues_next_candidate(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                base = f"http://127.0.0.1:{server.server_port}"
                with self.assertRaises(KatanaPartialError) as caught:
                    render_pages(
                        [base + "/lazy", base + "/offscope", base + "/anchor"],
                        config=KatanaConfig(
                            chrome_executable=shutil.which("chromium") or "", dom_wait_seconds=0,
                            timeout_seconds=10, auto_headless_timeout_seconds=10,
                            browser_diagnostics_dir=directory,
                        ),
                        scope=Scope.from_inputs([], [base]),
                    )
                error = caught.exception
                observations, parse_errors = parse_katana_jsonl(error.output)
                self.assertFalse(parse_errors)
                self.assertEqual(len(error.issues), 1)
                self.assertEqual(error.issues[0].target, base + "/offscope")
                self.assertTrue(any(observation.url == base + "/lazy" and observation.forms for observation in observations))
                self.assertTrue(any(observation.url == base + "/ui/login-fragment" and observation.forms for observation in observations))
                self.assertEqual(len(list(Path(directory).glob("*.json"))), 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_submit_disabled_and_offscope_controls_are_skipped(self) -> None:
        _JsLoginHandler.post_count = 0
        _JsLoginHandler.external_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/unsafe-actions"
            output = render_pages(
                [url], config=KatanaConfig(chrome_executable=shutil.which("chromium") or "", dom_wait_seconds=0),
                scope=Scope.from_inputs([], [url]),
            )
            metadata = json.loads(output.splitlines()[-1])["discovery_diagnostics"]
            self.assertEqual(metadata["click_count"], 0)
            self.assertFalse(metadata["password_field_found"])
            self.assertEqual(_JsLoginHandler.post_count, 0)
            self.assertEqual(_JsLoginHandler.external_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @staticmethod
    def _make_cert(directory: str, name: str) -> tuple[Path, Path]:
        cert = Path(directory, f"{name}.pem")
        key = Path(directory, f"{name}.key")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-days", "1", "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1",
                "-keyout", str(key), "-out", str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return cert, key

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_signin_toggle_is_explored_without_submitting_form(self) -> None:
        _JsLoginHandler.post_count = 0
        _JsLoginHandler.otp_get_count = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/toggle"
            output = render_pages(
                [url],
                config=KatanaConfig(
                    chrome_executable=shutil.which("chromium") or "",
                    timeout_seconds=10,
                    auto_headless_timeout_seconds=10,
                    dom_wait_seconds=0,
                ),
                scope=Scope.from_inputs([], [url]),
            )
            observations, errors = parse_katana_jsonl(output)
            self.assertFalse(errors)
            self.assertGreaterEqual(len(observations), 2)
            self.assertTrue(any(
                field.field_type == "password"
                for observation in observations
                for form in observation.forms
                for field in form.fields
            ))
            self.assertEqual(_JsLoginHandler.post_count, 0)
            self.assertEqual(_JsLoginHandler.otp_get_count, 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_browser_available(), "browser tools absent")
    def test_ca_cert_validates_local_https_and_renders_js_dom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert, key = self._make_cert(directory, "server")
            wrong_cert, _ = self._make_cert(directory, "untrusted")
            server = ThreadingHTTPServer(("127.0.0.1", 0), _JsLoginHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"https://127.0.0.1:{server.server_port}/login"
                output = render_pages(
                    [url],
                    config=KatanaConfig(
                        chrome_executable=shutil.which("chromium") or "",
                        ca_cert=str(cert),
                        timeout_seconds=10,
                        auto_headless_timeout_seconds=10,
                        request_timeout_seconds=5,
                        dom_wait_seconds=0,
                    ),
                    scope=Scope.from_inputs([], [url]),
                )
                observations, errors = parse_katana_jsonl(output)
                self.assertFalse(errors)
                self.assertEqual(len(observations), 1)
                self.assertTrue(any(
                    field.field_type == "password"
                    for form in observations[0].forms
                    for field in form.fields
                ))
                proxy_server = socketserver.ThreadingTCPServer(
                    ("127.0.0.1", 0), _ConnectProxyHandler
                )
                proxy_server.target_port = server.server_port
                proxy_server.connect_count = 0
                proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
                proxy_thread.start()
                try:
                    # urllib normally bypasses proxies for loopback; the real
                    # use case is an external host, so force the tunnel here.
                    with patch("urllib.request.proxy_bypass", return_value=False):
                        proxied = render_pages(
                            [url],
                            config=KatanaConfig(
                                chrome_executable=shutil.which("chromium") or "",
                                proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                ca_cert=str(cert),
                                timeout_seconds=10,
                                auto_headless_timeout_seconds=10,
                                request_timeout_seconds=5,
                                dom_wait_seconds=0,
                            ),
                            scope=Scope.from_inputs([], [url]),
                        )
                    self.assertIn("password", proxied)
                    self.assertGreater(proxy_server.connect_count, 0)
                    with patch("urllib.request.proxy_bypass", return_value=False):
                        proxied_without_ca = render_pages(
                            [url],
                            config=KatanaConfig(
                                chrome_executable=shutil.which("chromium") or "",
                                proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                timeout_seconds=10,
                                auto_headless_timeout_seconds=10,
                                request_timeout_seconds=5,
                                dom_wait_seconds=0,
                            ),
                            scope=Scope.from_inputs([], [url]),
                        )
                    self.assertIn("password", proxied_without_ca)
                    if shutil.which("katana"):
                        static_without_ca = run_katana(
                            KatanaConfig(
                                proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                depth=1,
                                max_total_pages=1,
                                timeout_seconds=10,
                                request_timeout_seconds=5,
                            ),
                            [url],
                            include_subdomains=False,
                            scope_hosts={"127.0.0.1"},
                        )
                        self.assertIn("login", static_without_ca)
                        headless_without_ca = run_katana(
                            KatanaConfig(
                                headless=True,
                                proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                depth=1,
                                max_total_pages=1,
                                timeout_seconds=15,
                                request_timeout_seconds=5,
                            ),
                            [url],
                            include_subdomains=False,
                            scope_hosts={"127.0.0.1"},
                        )
                        self.assertIn("login", headless_without_ca)
                    redirect_url = f"https://127.0.0.1:{server.server_port}/redirect-to-login"
                    with patch("urllib.request.proxy_bypass", return_value=False):
                        redirected = render_pages(
                            [redirect_url],
                            config=KatanaConfig(
                                chrome_executable=shutil.which("chromium") or "",
                                proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                ca_cert=str(cert),
                                timeout_seconds=10,
                                auto_headless_timeout_seconds=10,
                                request_timeout_seconds=5,
                                dom_wait_seconds=0,
                            ),
                            scope=Scope.from_inputs([], [redirect_url]),
                        )
                    observations, errors = parse_katana_jsonl(redirected)
                    self.assertFalse(errors)
                    self.assertEqual(len(observations), 1)
                    self.assertEqual(
                        observations[0].url,
                        f"https://127.0.0.1:{server.server_port}/login/",
                    )
                    self.assertTrue(any(
                        field.field_type == "password"
                        for form in observations[0].forms for field in form.fields
                    ))
                    _JsLoginHandler.external_count = 0
                    outside_url = f"https://127.0.0.1:{server.server_port}/redirect-outside"
                    with patch("urllib.request.proxy_bypass", return_value=False):
                        with self.assertRaisesRegex(
                            ToolError, "Переход за пределы разрешённого домена остановлен"
                        ):
                            render_pages(
                                [outside_url],
                                config=KatanaConfig(
                                    chrome_executable=shutil.which("chromium") or "",
                                    proxy=f"http://127.0.0.1:{proxy_server.server_address[1]}",
                                    ca_cert=str(cert),
                                    timeout_seconds=10,
                                    auto_headless_timeout_seconds=10,
                                    request_timeout_seconds=5,
                                    dom_wait_seconds=0,
                                ),
                                scope=Scope.from_inputs([], [outside_url]),
                            )
                    self.assertEqual(_JsLoginHandler.external_count, 0)
                finally:
                    proxy_server.shutdown()
                    proxy_server.server_close()
                    proxy_thread.join(timeout=5)
                with self.assertRaisesRegex(ToolError, "CERTIFICATE_VERIFY_FAILED"):
                    render_pages(
                        [url],
                        config=KatanaConfig(
                            chrome_executable=shutil.which("chromium") or "",
                            ca_cert=str(wrong_cert),
                            timeout_seconds=10,
                            auto_headless_timeout_seconds=10,
                            request_timeout_seconds=5,
                            dom_wait_seconds=0,
                        ),
                        scope=Scope.from_inputs([], [url]),
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
