from __future__ import annotations

import base64
import importlib.util
import socket
import sys
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from authpoints.config import HttpConfig, KatanaConfig, NmapConfig, ScanConfig
from authpoints.pipeline import run_active_scan


LAB_PATH = Path(__file__).parent / "fixtures" / "authlab_server.py"
SPEC = importlib.util.spec_from_file_location("authpoints_authlab", LAB_PATH)
assert SPEC is not None and SPEC.loader is not None
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


class AuthLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.state = lab.LabState()
        cls.opener = build_opener(ProxyHandler({}))
        cls.portal = lab.create_server("portal", port=0, state=cls.state)
        cls.admin = lab.create_server("admin", port=0, state=cls.state)
        cls.identity = lab.create_server("identity", port=0, state=cls.state)
        cls.api = lab.create_server("api", port=0, state=cls.state)
        cls.ftp = lab.create_tcp_server("ftp", port=0)
        cls.ssh = lab.create_tcp_server("ssh", port=0)
        cls.threads = [
            threading.Thread(target=cls.portal.serve_forever, daemon=True),
            threading.Thread(target=cls.admin.serve_forever, daemon=True),
            threading.Thread(target=cls.identity.serve_forever, daemon=True),
            threading.Thread(target=cls.api.serve_forever, daemon=True),
            threading.Thread(target=cls.ftp.serve_forever, daemon=True),
            threading.Thread(target=cls.ssh.serve_forever, daemon=True),
        ]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        for server in (cls.portal, cls.admin, cls.identity, cls.api, cls.ftp, cls.ssh):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)

    def test_portal_exposes_realistic_login_and_negative_cases(self) -> None:
        base_url = f"http://127.0.0.1:{self.portal.server_port}"
        with self.opener.open(base_url + "/login", timeout=2) as response:
            body = response.read().decode("utf-8")
        self.assertIn('type="password"', body)
        self.assertIn('action="/session"', body)

        with self.opener.open(base_url + "/register", timeout=2) as response:
            registration = response.read().decode("utf-8")
        self.assertIn('autocomplete="new-password"', registration)

        with self.opener.open(base_url + "/js-app", timeout=2) as response:
            js_app = response.read().decode("utf-8")
        self.assertIn('id="login-root"', js_app)
        self.assertIn('document.createElement("form")', js_app)

    def test_api_exposes_http_auth_and_post_only_login(self) -> None:
        base_url = f"http://127.0.0.1:{self.api.server_port}"
        with self.assertRaises(HTTPError) as context:
            self.opener.open(base_url + "/api/private", timeout=2)
        with context.exception as error:
            self.assertEqual(error.code, 401)
            self.assertIn("Bearer", error.headers["WWW-Authenticate"])

        with self.assertRaises(HTTPError) as context:
            self.opener.open(base_url + "/api/auth/login", timeout=2)
        with context.exception as error:
            self.assertEqual(error.code, 405)
            self.assertEqual(error.headers["Allow"], "POST")

    def test_admin_exposes_form_and_working_http_basic(self) -> None:
        base_url = f"http://127.0.0.1:{self.admin.server_port}"
        with self.opener.open(base_url + "/admin/login", timeout=2) as response:
            body = response.read().decode("utf-8")
        self.assertIn('type="password"', body)
        self.assertIn('action="/admin/session"', body)

        with self.assertRaises(HTTPError) as context:
            self.opener.open(base_url + "/admin/basic", timeout=2)
        with context.exception as error:
            self.assertEqual(error.code, 401)
            self.assertIn("Basic", error.headers["WWW-Authenticate"])

        invalid = Request(
            base_url + "/admin/basic",
            headers={"Authorization": self._basic_header("student", "wrong")},
        )
        with self.assertRaises(HTTPError) as context:
            self.opener.open(invalid, timeout=2)
        with context.exception as error:
            self.assertEqual(error.code, 401)

        valid = Request(
            base_url + "/admin/basic",
            headers={
                "Authorization": self._basic_header(
                    lab.DEMO_USERNAME,
                    lab.DEMO_PASSWORD,
                )
            },
        )
        with self.opener.open(valid, timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("Admin Basic dashboard", response.read().decode("utf-8"))

    def test_demo_login_records_method_without_storing_body(self) -> None:
        base_url = f"http://127.0.0.1:{self.portal.server_port}"
        request = Request(
            base_url + "/session",
            data=b"username=student&password=password123",
            method="POST",
        )
        with self.opener.open(request, timeout=2) as response:
            self.assertEqual(response.status, 200)
        snapshot = self.state.snapshot()
        self.assertGreaterEqual(snapshot["POST"], 1)
        self.assertNotIn("password123", str(snapshot))

    def test_identity_login_forms_accept_demo_credentials(self) -> None:
        base_url = f"http://127.0.0.1:{self.identity.server_port}"
        for path in ("/oauth/authorize", "/saml/login", "/adfs/ls"):
            with self.subTest(path=path):
                request = Request(
                    base_url + path,
                    data=b"username=student&password=password123",
                    method="POST",
                )
                with self.opener.open(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)

    def test_pointfinder_discovers_form_and_basic_without_external_tools(self) -> None:
        portal_url = f"http://127.0.0.1:{self.portal.server_port}/"
        admin_url = f"http://127.0.0.1:{self.admin.server_port}/"
        posts_before = self.state.snapshot().get("POST", 0)

        report = run_active_scan(
            [],
            [portal_url, admin_url],
            ScanConfig(
                standard_paths=["/login", "/admin/login", "/admin/basic"],
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(concurrency=1, timeout_seconds=2),
            ),
        )

        findings = {(item.auth_type, item.endpoint) for item in report.findings}
        self.assertIn(("password_form", portal_url + "login"), findings)
        self.assertIn(("password_form", admin_url + "admin/login"), findings)
        self.assertIn(("http_basic", admin_url + "admin/basic"), findings)
        self.assertFalse(report.partial)
        self.assertEqual(self.state.snapshot().get("POST", 0), posts_before)

    @staticmethod
    def _basic_header(username: str, password: str) -> str:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8"))
        return "Basic " + token.decode("ascii")

    def test_ssh_stub_exposes_identification_banner(self) -> None:
        with socket.create_connection(self.ssh.server_address, timeout=2) as client:
            banner = client.recv(256)
        self.assertEqual(banner, b"SSH-2.0-OpenSSH_9.6p1 AuthPointsLab\r\n")

    def test_ftp_stub_exposes_banner_and_rejects_authentication(self) -> None:
        with socket.create_connection(self.ftp.server_address, timeout=2) as client:
            self.assertIn(b"ProFTPD", client.recv(256))
            client.sendall(b"USER student\r\n")
            self.assertTrue(client.recv(256).startswith(b"331 "))
            client.sendall(b"PASS ignored\r\n")
            self.assertTrue(client.recv(256).startswith(b"530 "))


if __name__ == "__main__":
    unittest.main()
