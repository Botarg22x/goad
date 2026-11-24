"""Native Chromium TLS, CONNECT proxy and same-session form integration.

All endpoints bind to loopback; the proxy refuses every other destination.
Certificates and the disposable browser session exist only for these tests.
"""

from __future__ import annotations

import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from authchecker.adapters.http import TargetScope
from authchecker.browser import BrowserCheckConfig, run_browser_check
from authchecker.models import Credential, OutcomeStatus


_USERNAME = "https-browser-student"
_PASSWORD = "local-https-test-password"
_TOKEN = "https-session-bound-csrf"


class _HttpsLab(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, certificate: Path, private_key: Path) -> None:
        super().__init__(("127.0.0.1", 0), _HttpsHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Only the leaf is served: the client's pin must also work when the
        # explicitly trusted root is absent from the transmitted chain.
        context.load_cert_chain(certificate, private_key)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.posts: list[dict[str, object]] = []
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.server_port}/login"


class _HttpsHandler(BaseHTTPRequestHandler):
    server: _HttpsLab

    def log_message(self, *_args) -> None:
        pass

    def handle(self) -> None:
        try:
            super().handle()
        except (ConnectionError, ssl.SSLError):
            # A successful TLS-only preflight intentionally disconnects before
            # sending an HTTP request; Chromium also opens speculative sockets.
            pass

    def reply(self, html: str, *, status: int = 200, cookie: bool = False) -> None:
        content = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if cookie:
            self.send_header(
                "Set-Cookie", "lab_session=https-session; Secure; HttpOnly; SameSite=Lax; Path=/",
            )
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        if self.path != "/login":
            self.reply("Not found", status=404)
            return
        self.reply(
            '<html><title>Local HTTPS login</title><form method="post" action="/session">'
            f'<input type="hidden" name="csrf_token" value="{_TOKEN}">'
            '<input name="username" autocomplete="username">'
            '<input name="password" type="password" autocomplete="current-password">'
            '<button type="submit">Log in</button></form></html>',
            cookie=True,
        )

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        fields = parse_qs(body)
        cookie = self.headers.get("Cookie", "")
        with self.server.lock:
            self.server.posts.append({"path": self.path, "fields": fields, "cookie": cookie})
        valid = (
            self.path == "/session"
            and fields.get("username") == [_USERNAME]
            and fields.get("password") == [_PASSWORD]
            and fields.get("csrf_token") == [_TOKEN]
            and "lab_session=https-session" in cookie
        )
        if valid:
            self.reply('<html><a id="logout" href="/logout">Logout</a></html>')
        else:
            self.reply('<html><p>Invalid username or password</p></html>', status=403)


class _ConnectProxy(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, target_port: int) -> None:
        super().__init__(("127.0.0.1", 0), _ConnectHandler)
        self.target_port = target_port
        self.connects = 0
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


class _ConnectHandler(BaseHTTPRequestHandler):
    server: _ConnectProxy
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        pass

    def do_CONNECT(self) -> None:
        target = urlsplit("//" + self.path)
        if target.hostname != "127.0.0.1" or target.port != self.server.target_port:
            self.send_error(403, "This test proxy permits only its local lab")
            return
        with self.server.lock:
            self.server.connects += 1
        with socket.create_connection(("127.0.0.1", self.server.target_port), timeout=5) as upstream:
            self.send_response(200, "Connection established")
            self.end_headers()
            sockets = [self.connection, upstream]
            try:
                while True:
                    readable, _, _ = select.select(sockets, [], [], 5)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is self.connection else self.connection
                        destination.sendall(data)
            except OSError:
                # The wrong-CA case deliberately closes a rejected TLS tunnel.
                return


class BrowserProxyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl is unavailable")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise unittest.SkipTest("Playwright is unavailable") from exc
        executable = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
        try:
            with sync_playwright() as playwright:
                options: dict[str, object] = {"headless": True}
                if executable:
                    options["executable_path"] = executable
                browser = playwright.chromium.launch(**options)
                browser.close()
        except Exception as exc:
            raise unittest.SkipTest(f"Chromium is unavailable: {exc}") from exc
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.ca = cls.root / "ca.pem"
        cls.wrong_ca = cls.root / "other-ca.pem"
        for name, certificate in (("ca", cls.ca), ("other-ca", cls.wrong_ca)):
            cls.openssl(
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN=Local HTTPS Browser Test {name}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(cls.root / f"{name}.key"), "-out", str(certificate),
            )
        cls.openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
            "-keyout", str(cls.root / "leaf.key"), "-out", str(cls.root / "leaf.csr"),
        )
        extensions = cls.root / "leaf.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
            "authorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n",
            encoding="ascii",
        )
        cls.openssl(
            "x509", "-req", "-in", str(cls.root / "leaf.csr"),
            "-CA", str(cls.ca), "-CAkey", str(cls.root / "ca.key"), "-CAcreateserial",
            "-days", "1", "-extfile", str(extensions), "-out", str(cls.root / "leaf.pem"),
        )
        cls.lab = _HttpsLab(cls.root / "leaf.pem", cls.root / "leaf.key")
        cls.proxy = _ConnectProxy(cls.lab.server_port)
        cls.threads = []
        for server in (cls.lab, cls.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)
        cls.addClassCleanup(cls.stop_servers)

    @staticmethod
    def openssl(*arguments: str) -> None:
        subprocess.run(["openssl", *arguments], check=True, capture_output=True, timeout=10)

    @classmethod
    def stop_servers(cls) -> None:
        for server in (cls.proxy, cls.lab):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=3)

    def setUp(self) -> None:
        with self.lab.lock:
            self.lab.posts.clear()
        with self.proxy.lock:
            self.proxy.connects = 0

    def check(self, ca_cert: Path | None):
        return run_browser_check(
            self.lab.url,
            Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(
                headless=True, timeout_seconds=8, proxy=self.proxy.url,
                ca_cert=ca_cert, success_selector="#logout",
            ),
            target_scope=TargetScope("127.0.0.1"),
        )

    def test_native_tls_through_connect_preserves_cookie_csrf_and_one_post(self) -> None:
        result = self.check(self.ca)
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result.outcome.detail)
        self.assertEqual(result.attempted_count, 1)
        with self.lab.lock:
            posts = self.lab.posts.copy()
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["fields"]["csrf_token"], [_TOKEN])
        self.assertIn("lab_session=https-session", posts[0]["cookie"])
        with self.proxy.lock:
            # One verified preflight and at least one native Chromium tunnel.
            self.assertGreaterEqual(self.proxy.connects, 2)

    def test_proxy_without_ca_allows_https_browser_login(self) -> None:
        result = self.check(None)
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result.outcome.detail)
        self.assertEqual(result.attempted_count, 1)
        with self.lab.lock:
            self.assertEqual(len(self.lab.posts), 1)
        with self.proxy.lock:
            self.assertGreaterEqual(self.proxy.connects, 1)

    def test_wrong_ca_stops_before_browser_launch_or_credential_post(self) -> None:
        with patch("playwright.sync_api.sync_playwright") as launch:
            result = self.check(self.wrong_ca)
        self.assertEqual(result.outcome.status, OutcomeStatus.NETWORK_ERROR)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(result.outcome.evidence.get("reason"), "tls")
        launch.assert_not_called()
        with self.lab.lock:
            self.assertEqual(self.lab.posts, [])
        with self.proxy.lock:
            self.assertEqual(self.proxy.connects, 1)


if __name__ == "__main__":
    unittest.main()
