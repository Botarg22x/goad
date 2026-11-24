from __future__ import annotations

import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from authpoints.classifier import classify_web
from authpoints.config import (
    DEFAULT_USER_AGENT,
    HttpConfig,
    KatanaConfig,
    NmapConfig,
    ScanConfig,
    validate_proxy_url,
)
from authpoints.http_probe import probe_urls
from authpoints.models import FindingKind
from authpoints.pipeline import run_active_scan
from authpoints.reporting import write_links_report
from authpoints.scope import Scope


class _Handler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    user_agents: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(("GET", self.path))
        type(self).user_agents.append(self.headers.get("User-Agent", ""))
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if self.path == "/login" or self.path.startswith("/login?"):
            body = (
                b"<html><title>Sign in</title><form method='post' action='/session'>"
                b"<input name='username'><input type='password' name='password'>"
                b"<button type='submit'>Sign in</button></form></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/external":
            self.send_response(302)
            self.send_header("Location", "https://identity.outside.test/sso")
            self.end_headers()
            return
        if self.path == "/basic":
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Negotiate")
            self.send_header("WWW-Authenticate", 'Basic realm="Lab"')
            self.end_headers()
            return
        if self.path == "/forbidden":
            body = b"<html><title>Forbidden</title></html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/challenge":
            body = b"<html><title>Just a moment...</title></html>"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("cf-mitigated", "challenge")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/token-redirect":
            self.send_response(302)
            self.send_header("Location", "/login?code=server-secret")
            self.end_headers()
            return
        if self.path == "/access-token-redirect" or self.path.startswith(
            "/access-token-redirect?access_token="
        ):
            self.send_response(302)
            self.send_header("Location", "/login?access_token=server-secret")
            self.end_headers()
            return
        if self.path.startswith("/echo?"):
            body = b"<html><title>Echo</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(500)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class _ProxyHandler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(("GET", self.path))
        body = (
            b"<html><form><input name='email'>"
            b"<input name='password' type='password'></form></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class HttpProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _Handler.requests = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        _Handler.requests.clear()
        _Handler.user_agents.clear()

    @patch("authpoints.pipeline.render_pages")
    def test_page_only_static_form_never_crawls_links_or_starts_browser(
        self, render_mock: object,
    ) -> None:
        url = self.base_url + "/login"
        report = run_active_scan(
            [], [url], ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(concurrency=1),
            ),
        )

        self.assertEqual(_Handler.requests, [("GET", "/login")])
        render_mock.assert_not_called()  # type: ignore[attr-defined]
        self.assertEqual(report.config["page_only_results"][0]["status"], "found")

    @patch("authpoints.pipeline.render_pages")
    def test_page_only_follows_redirect_to_login_path_and_reports_final_url(
        self, render_mock: object,
    ) -> None:
        report = run_active_scan(
            [], [self.base_url + "/"], ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(concurrency=1),
            ),
        )

        self.assertEqual(_Handler.requests, [("GET", "/"), ("GET", "/login")])
        render_mock.assert_not_called()  # type: ignore[attr-defined]
        self.assertEqual(report.config["page_only_results"], [{
            "url": self.base_url + "/",
            "final_url": self.base_url + "/login",
            "status": "found",
            "auth_types": ["password_form"],
        }])

    def test_follows_only_in_scope_get_and_never_submits_form(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        results = probe_urls([self.base_url], scope, HttpConfig(concurrency=1))
        self.assertEqual(len(results), 1)
        observation = results[0].observation
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(_Handler.requests, [("GET", "/"), ("GET", "/login")])
        self.assertEqual(_Handler.user_agents, [DEFAULT_USER_AGENT] * 2)
        self.assertNotIn(("GET", "/session"), _Handler.requests)
        findings = classify_web(observation)
        login = next(item for item in findings if item.kind == FindingKind.WEB_LOGIN)
        self.assertEqual(login.metadata["form_action"], self.base_url + "/session")

    def test_uses_configured_user_agent(self) -> None:
        scope = Scope.from_inputs([], [self.base_url + "/login"])
        progress: list[str] = []
        results = probe_urls(
            [self.base_url + "/login"],
            scope,
            HttpConfig(concurrency=1, user_agent="PointFinder-Test/1.0"),
            on_progress=progress.append,
        )
        self.assertIsNotNone(results[0].observation)
        self.assertEqual(_Handler.user_agents, ["PointFinder-Test/1.0"])
        self.assertTrue(any(message.startswith("[HTTP] GET ") for message in progress))
        self.assertTrue(any("[HTTP] Ответ 200 " in message for message in progress))
        self.assertTrue(progress[-1].startswith("[HTTP] Проверка завершена"))

    def test_request_delay_spaces_top_level_urls(self) -> None:
        scope = Scope.from_inputs(
            [], [self.base_url + "/login", self.base_url + "/forbidden"]
        )
        delays: list[float] = []

        results = probe_urls(
            [self.base_url + "/login", self.base_url + "/forbidden"],
            scope,
            HttpConfig(concurrency=1, request_delay_seconds=1.0),
            sleeper=delays.append,
        )

        self.assertEqual(len(results), 2)
        self.assertEqual(delays, [1.0])

    def test_page_only_fetches_and_classifies_only_supplied_url(self) -> None:
        target = self.base_url + "/login"
        report = run_active_scan(
            [],
            [target],
            ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True, concurrency=1),
            ),
        )

        self.assertEqual(_Handler.requests, [("GET", "/login")])
        self.assertTrue(
            any(
                finding.kind == FindingKind.WEB_LOGIN
                and finding.endpoint == target
                for finding in report.findings
            )
        )
        self.assertEqual(report.config["page_only"], True)

    @patch("authpoints.pipeline.render_pages")
    def test_page_only_finds_basic_without_form_or_browser(self, render_mock: object) -> None:
        target = self.base_url + "/basic"
        report = run_active_scan(
            [], [target], ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True, concurrency=1),
            ),
        )

        self.assertEqual(_Handler.requests, [("GET", "/basic")])
        render_mock.assert_not_called()  # type: ignore[attr-defined]
        self.assertIn("http_basic", [item.auth_type for item in report.findings])
        self.assertEqual(report.config["page_only_results"], [{
            "url": target, "status": "found", "auth_types": ["http_negotiate", "http_basic"],
        }])

    def test_page_only_finds_basic_after_another_challenge(self) -> None:
        target = self.base_url + "/basic"
        report = run_active_scan(
            [], [target], ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True, concurrency=1),
            ),
        )

        self.assertEqual(_Handler.requests, [("GET", "/basic")])
        self.assertEqual(
            {item.auth_type for item in report.findings},
            {"http_negotiate", "http_basic"},
        )

    def test_page_only_checks_credential_query_urls_and_keeps_output(self) -> None:
        urls = [
            self.base_url + "/login?access_token=client-secret",
            self.base_url + "/login?password=other-secret",
            self.base_url + "/login?next=%2Fcallback%3Ftoken%3Dnested-secret",
        ]
        config = ScanConfig(
            page_only=True,
            nmap=NmapConfig(enabled=False),
            katana=KatanaConfig(enabled=False),
            http=HttpConfig(enabled=True, concurrency=1),
        )
        report = run_active_scan([], urls, config)
        self.assertEqual(
            _Handler.requests,
            [("GET", url.removeprefix(self.base_url)) for url in urls],
        )
        self.assertEqual(len(report.findings), 1)
        self.assertTrue(all(finding.kind == FindingKind.WEB_LOGIN for finding in report.findings))
        self.assertEqual(len(report.findings[0].metadata["discovered_on"]), len(urls))
        serialized = json.dumps(report.to_dict())
        for secret in ("client-secret", "other-secret", "nested-secret"):
            self.assertIn(secret, serialized)
        with tempfile.TemporaryDirectory() as directory:
            links = Path(directory) / "report.txt"
            write_links_report(report, links)
            text = links.read_text(encoding="utf-8")
        self.assertIn("access_token=client-secret", text)
        self.assertEqual(len(text.splitlines()), len(urls))
        for secret in ("client-secret", "other-secret", "nested-secret"):
            self.assertIn(secret, text)

    def test_page_only_still_does_not_request_logout(self) -> None:
        report = run_active_scan(
            [],
            [self.base_url + "/logout?access_token=secret"],
            ScanConfig(
                page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True, concurrency=1),
            ),
        )
        self.assertEqual(_Handler.requests, [])
        self.assertEqual(len(report.issues), 1)
        self.assertIn("access_token=secret", json.dumps(report.to_dict()))

    def test_http_probe_allows_in_scope_credential_redirect(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        result = probe_urls(
            [self.base_url + "/access-token-redirect?access_token=client-secret"],
            scope,
            HttpConfig(concurrency=1),
        )[0]
        self.assertIsNotNone(result.observation)
        self.assertEqual(
            _Handler.requests,
            [
                ("GET", "/access-token-redirect?access_token=client-secret"),
                ("GET", "/login?access_token=server-secret"),
            ],
        )
        assert result.observation is not None
        self.assertIn("access_token=server-secret", result.observation.url)

    def test_probe_follows_in_scope_credential_redirect(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        result = probe_urls(
            [self.base_url + "/access-token-redirect"],
            scope,
            HttpConfig(concurrency=1),
        )[0]
        self.assertIsNotNone(result.observation)
        assert result.observation is not None
        self.assertEqual(
            _Handler.requests,
            [("GET", "/access-token-redirect"), ("GET", "/login?access_token=server-secret")],
        )
        self.assertEqual(result.observation.blocked_redirect, "")
        self.assertIn("access_token=server-secret", result.observation.url)

    @patch("authpoints.pipeline.render_pages", return_value="")
    def test_page_only_reports_forbidden_and_captcha_separately(self, _render_mock) -> None:
        config = ScanConfig(
            page_only=True,
            nmap=NmapConfig(enabled=False),
            katana=KatanaConfig(enabled=False),
            http=HttpConfig(enabled=True, concurrency=1),
        )

        forbidden = run_active_scan([], [self.base_url + "/forbidden"], config)
        challenge = run_active_scan([], [self.base_url + "/challenge"], config)

        self.assertTrue(any("HTTP 403" in issue.message for issue in forbidden.issues))
        self.assertFalse(any("CAPTCHA" in issue.message for issue in forbidden.issues))
        self.assertTrue(any("CAPTCHA" in issue.message for issue in challenge.issues))
        self.assertTrue(any("challenge" in issue.message for issue in challenge.issues))

    def test_routes_http_probe_through_explicit_proxy(self) -> None:
        _ProxyHandler.requests.clear()
        proxy_server = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        proxy_thread.start()
        try:
            target = "http://example.test/login"
            results = probe_urls(
                [target],
                Scope.from_inputs([], [target]),
                HttpConfig(
                    concurrency=1,
                    proxy=f"127.0.0.1:{proxy_server.server_port}",
                ),
            )
        finally:
            proxy_server.shutdown()
            proxy_server.server_close()
            proxy_thread.join(timeout=2)
        self.assertIsNotNone(results[0].observation)
        self.assertEqual(_ProxyHandler.requests, [("GET", target)])

    def test_validates_proxy_url(self) -> None:
        self.assertEqual(
            validate_proxy_url("127.0.0.1:8080"),
            "http://127.0.0.1:8080",
        )
        with self.assertRaisesRegex(ValueError, "credentials"):
            validate_proxy_url("http://user:secret@127.0.0.1:8080")
        with self.assertRaisesRegex(ValueError, "http scheme"):
            validate_proxy_url("socks5://127.0.0.1:1080")

    def test_rejects_user_agent_header_injection(self) -> None:
        scope = Scope.from_inputs([], [self.base_url + "/login"])
        results = probe_urls(
            [self.base_url + "/login"],
            scope,
            HttpConfig(concurrency=1, user_agent="safe\r\nAuthorization: secret"),
        )
        self.assertIsNone(results[0].observation)
        self.assertIsNotNone(results[0].issue)
        self.assertEqual(_Handler.requests, [])

    def test_blocks_external_redirect_but_records_sso(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        results = probe_urls([self.base_url + "/external"], scope, HttpConfig(concurrency=1))
        observation = results[0].observation
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation.blocked_redirect, "https://identity.outside.test/sso")
        self.assertEqual(_Handler.requests, [("GET", "/external")])
        self.assertTrue(any(item.kind == FindingKind.SSO for item in classify_web(observation)))

    def test_preserves_normal_query_for_transport_and_report(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        url = self.base_url + "/echo?next=%2Fhome&state=opaque&outside=ok"
        results = probe_urls([url], scope, HttpConfig(concurrency=1))
        observation = results[0].observation
        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(
            _Handler.requests,
            [("GET", "/echo?next=%2Fhome&state=opaque&outside=ok")],
        )
        self.assertIn("state=opaque", observation.url)
        self.assertIn("outside=ok", observation.url)

    def test_requests_credential_query_and_redirect(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        direct = probe_urls(
            [self.base_url + "/login?token=client-secret"],
            scope,
            HttpConfig(concurrency=1),
        )[0]
        self.assertIsNotNone(direct.observation)
        assert direct.observation is not None
        self.assertIn("client-secret", direct.observation.url)
        self.assertEqual(_Handler.requests, [("GET", "/login?token=client-secret")])

        redirected = probe_urls(
            [self.base_url + "/token-redirect"],
            scope,
            HttpConfig(concurrency=1),
        )[0]
        self.assertIsNotNone(redirected.observation)
        assert redirected.observation is not None
        self.assertEqual(
            _Handler.requests,
            [("GET", "/login?token=client-secret"), ("GET", "/token-redirect"), ("GET", "/login?code=server-secret")],
        )
        self.assertEqual(redirected.observation.blocked_redirect, "")

        _Handler.requests.clear()
        logout = probe_urls(
            [self.base_url + "/logout"], scope, HttpConfig(concurrency=1)
        )[0]
        self.assertIsNone(logout.observation)
        self.assertEqual(_Handler.requests, [])

    def test_requests_compact_credentials_but_not_encoded_logout(self) -> None:
        scope = Scope.from_inputs([], [self.base_url])
        credential_urls = [
            self.base_url + "/login?apikey=secret",
            self.base_url + "/login?outside=ok;accesskey=secret",
            self.base_url + "/login?sessionkey=secret",
            self.base_url + "/login?x-api-key=secret",
            self.base_url + "/login?clientassertion=secret",
            self.base_url + "/login?csrfmiddlewaretoken=secret",
            self.base_url + "/login?next=%2Fcallback%3Ftoken%3Dsecret",
        ]
        logout_urls = [
            self.base_url + "/log%6fut",
            self.base_url + "/logout;jsessionid=value",
            self.base_url + "/wp-login.php?action=logout",
            self.base_url + "/logout.json",
            self.base_url + "/api/logout-v2",
            self.base_url + "/end-session",
            self.base_url + "/disconnect",
        ]
        results = probe_urls(credential_urls + logout_urls, scope, HttpConfig(concurrency=1))
        self.assertTrue(all(result.observation is not None for result in results[:len(credential_urls)]))
        self.assertTrue(all(result.observation is None for result in results[len(credential_urls):]))
        self.assertEqual(
            _Handler.requests,
            [("GET", url.removeprefix(self.base_url)) for url in credential_urls],
        )


if __name__ == "__main__":
    unittest.main()
