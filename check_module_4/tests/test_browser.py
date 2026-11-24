"""Browser checks against a local lab, without external requests or accounts."""

from __future__ import annotations

import io
import json
import shutil
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import redirect_stderr
from urllib.parse import parse_qs, urlsplit

from authchecker.models import Credential, OutcomeStatus


_USERNAME = "browser-student"
_PASSWORD = "local-test-password"
_CSRF = "session-bound-local-token"


def _form(*, action: str = "/session", hidden: bool = False) -> str:
    token = f'<input type="hidden" name="csrf_token" value="{_CSRF}">' if hidden else ""
    return (
        f'<form method="post" action="{action}">{token}'
        '<label>Username<input name="username" autocomplete="username"></label>'
        '<label>Password<input name="password" type="password" '
        'autocomplete="current-password"></label>'
        '<button type="submit">Log in</button></form>'
    )


class _LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _LabHandler)
        self.requests: list[dict[str, object]] = []
        self.cross_origin = ""
        self.lock = threading.Lock()
        self.auth_started = threading.Event()
        self.background_followed = threading.Event()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def record(self, record: dict[str, object]) -> None:
        with self.lock:
            self.requests.append(record)

    def posts(self) -> list[dict[str, object]]:
        with self.lock:
            return [request.copy() for request in self.requests if request["method"] == "POST"]


class _LabHandler(BaseHTTPRequestHandler):
    server: _LabServer

    def log_message(self, *_args) -> None:
        pass

    def _reply(self, body: str, *, status: int = 200, headers=None, content_type="text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self.server.record({"method": "GET", "path": path, "body": ""})
        if path == "/template-login":
            self._reply(
                '<form method="post" action="/session-template">'
                '<input name="other_username" autocomplete="username">'
                '<input name="log"><input name="pwd" type="password">'
                '<button type="submit">Log in</button></form>'
            )
        elif path == "/delayed":
            self._reply(
                '<html><title>Log in</title><main id="app">Loading</main><script>'
                "setTimeout(() => document.querySelector('#app').innerHTML = "
                f"{json.dumps(_form())}, 250);</script></html>"
            )
        elif path == "/late-analytics-redirect":
            self._reply(
                '<main id="app">Loading</main><script>'
                "fetch('/background-redirect', {method:'POST', body:'event=page'}).catch(() => {});"
                "setTimeout(() => document.querySelector('#app').innerHTML = "
                f"{json.dumps(_form(action='/session-late'))}, 250);</script>"
            )
        elif path == "/csrf":
            self._reply(
                _form(action="/session-csrf", hidden=True),
                headers={"Set-Cookie": "lab_session=local-session; HttpOnly; SameSite=Lax; Path=/"},
            )
        elif path in {"/fetch", "/double-fetch", "/analytics", "/offsite-analytics"}:
            repeat = (
                "fetch('/session-fetch', options).catch(() => {});"
                if path == "/double-fetch" else ""
            )
            analytics = "fetch('/telemetry', {method:'POST', body:'event=submit'}).catch(() => {});" if path == "/analytics" else ""
            if path == "/offsite-analytics":
                analytics = (
                    f"fetch({json.dumps(self.server.cross_origin + '/telemetry?do-not-record=this-query')}, "
                    "{method:'POST', mode:'no-cors', body:'event=page'}).catch(() => {});"
                )
            self._reply(
                _form(action="/session-fetch", hidden=True)
                + """<script>
                document.querySelector('form').addEventListener('submit', async event => {
                    event.preventDefault();
                    const options = {method: 'POST', headers: {'X-CSRF-Token':
                        document.querySelector('[name=csrf_token]').value},
                        body: new URLSearchParams(new FormData(event.target))};
                    """ + analytics + """
                    const first = fetch('/session-fetch', options);
                    """ + repeat + """
                    const result = await first;
                    if (result.ok) document.body.innerHTML = '<a id="logout" href="/logout">Logout</a>';
                    else document.body.innerHTML = '<p id="error">Invalid username or password</p>';
                });</script>""",
                headers={"Set-Cookie": "lab_session=local-session; HttpOnly; SameSite=Lax; Path=/"},
            )
        elif path == "/identifier":
            self._reply(
                '<form method="post" action="/send_email_otp">'
                '<input name="email" type="email" autocomplete="username">'
                '<button type="submit">Send code</button></form>'
            )
        elif path == "/identifier-password":
            self._reply(
                '<form method="post" action="/identify-password">'
                '<label>Login<input name="email" type="text" autocomplete="username"></label>'
                '<button type="submit">Continue</button></form>'
            )
        elif path == "/challenge":
            self._reply(
                '<html><title>Just a moment...</title>'
                '<p>Checking your browser before continuing</p></html>',
                status=403,
                headers={"cf-mitigated": "challenge"},
            )
        elif path == "/mfa":
            self._reply(_form(action="/session-mfa"))
        elif path == "/ambiguous":
            self._reply(_form(action="/session-ambiguous"))
        elif path == "/welcome":
            self._reply("<h1>Welcome</h1><p>The request was processed.</p>")
        elif path == "/cross-origin":
            self._reply(_form(action=self.server.cross_origin + "/credential-sink"))
        elif path == "/offsite-credentials":
            self._reply(
                _form() + "<script>document.querySelector('form').onsubmit = event => {"
                "event.preventDefault();fetch("
                + json.dumps(self.server.cross_origin + "/credential-sink?do-not-record=this-query")
                + ", {method:'POST',mode:'no-cors',body:new URLSearchParams(new FormData(event.target))})"
                ".catch(() => {});};</script>"
            )
        elif path in {"/cookie-consent", "/cookie-anchored", "/cookie-blocked"}:
            reject_button = ""
            if path != "/cookie-blocked":
                identifier = ' id="onetrust-reject-all-handler"' if path == "/cookie-consent" else ""
                reject_button = (
                    f'<button type="button"{identifier} onclick="'
                    "document.querySelector('#cookie-consent').remove();"
                    "fetch('/cookie-rejected',{method:'POST',body:'optional=no'}).catch(()=>{});"
                    '">Only necessary</button>'
                )
            self._reply(
                _form()
                + '<div id="cookie-consent" role="dialog" aria-modal="true" '
                'style="position:fixed;inset:0;z-index:999;background:white">'
                '<h2>Cookie preferences</h2><p>We use cookies.</p>' + reject_button
                + '<button type="button" onclick="fetch(\'/cookie-accepted\',{method:\'POST\',body:\'all=yes\'})">Accept all</button>'
                '</div>'
            )
        elif path in {"/error-overlay", "/persistent-error-overlay"}:
            close_action = "this.parentElement.remove()" if path == "/error-overlay" else "void(0)"
            self._reply(
                _form()
                + '<div role="alertdialog" aria-modal="true" '
                'style="position:fixed;inset:0;z-index:999;background:white">'
                '<h2>Произошла неизвестная ошибка</h2>'
                '<p>Пожалуйста, повторите попытку или обновите страницу.</p>'
                f'<button type="button" onclick="{close_action}">Закрыть</button></div>'
            )
        elif path == "/login":
            self._reply(_form())
        elif path == "/login-with-logout-link":
            self._reply('<a id="preexisting" href="/logout">Выход</a>' + _form())
        elif path in {"/redirect307", "/redirect308", "/redirect302"}:
            self._reply(_form(action="/session-" + path.lstrip("/")))
        elif path == "/credential-get":
            self._reply(_form(action="/credential-sink").replace('method="post"', 'method="get"').replace('name="password"', 'name="secret"'))
        elif path == "/popup":
            self._reply(_form().replace('<form ', '<form target="_blank" '))
        elif path == "/external-script":
            self._reply(f'<html><body><script src="{self.server.cross_origin}/fields.js"></script></body></html>')
        elif path == "/fields.js":
            self._reply("document.body.innerHTML = " + json.dumps(_form()) + ";", content_type="application/javascript")
        else:
            self._reply("<h1>Not found</h1>", status=404)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        self.server.record({
            "method": "POST", "path": path, "body": body,
            "cookie": self.headers.get("Cookie", ""),
            "csrf_header": self.headers.get("X-CSRF-Token", ""),
        })
        fields = parse_qs(body)
        valid = fields.get("username") == [_USERNAME] and fields.get("password") == [_PASSWORD]
        if path == "/session-template":
            valid = fields.get("log") == [_USERNAME] and fields.get("pwd") == [_PASSWORD]
        if path in {"/session-csrf", "/session-fetch"}:
            valid = (
                valid
                and fields.get("csrf_token") == [_CSRF]
                and "lab_session=local-session" in self.headers.get("Cookie", "")
            )
        if path == "/identify-password":
            if fields.get("email") == [_USERNAME]:
                self._reply(
                    '<form method="post" action="/session-step">'
                    '<label>Password<input name="password" type="password" '
                    'autocomplete="current-password"></label>'
                    '<button type="submit">Sign in</button></form>',
                    headers={"Set-Cookie": "identifier_session=ready; HttpOnly; SameSite=Lax; Path=/"},
                )
            else:
                self._reply('<p id="error">Invalid email</p>', status=401)
        elif path == "/session-step":
            valid_step = (
                fields.get("password") == [_PASSWORD]
                and "identifier_session=ready" in self.headers.get("Cookie", "")
            )
            self._reply(
                '<a id="logout" href="/logout">Logout</a>'
                if valid_step else '<p id="error">Invalid password</p>',
                status=200,
            )
        elif path == "/background-redirect":
            if self.server.auth_started.wait(timeout=5):
                self._reply("", status=307, headers={"Location": "/telemetry-followup"})
            else:
                self._reply("auth did not start", status=503)
        elif path == "/telemetry-followup":
            self.server.background_followed.set()
            self._reply("ok")
        elif path == "/session-late":
            self.server.auth_started.set()
            self.server.background_followed.wait(timeout=2)
            self._reply('<a id="logout" href="/logout">Logout</a>')
        elif path.startswith("/session-redirect"):
            code = int(path[-3:])
            destination = "/credential-sink" if code == 308 else self.server.cross_origin + "/credential-sink"
            self._reply("", status=code, headers={"Location": destination})
        elif path == "/session-fetch":
            valid = valid and self.headers.get("X-CSRF-Token") == _CSRF
            self._reply("ok" if valid else "invalid", status=200 if valid else 403)
        elif path == "/session-mfa":
            self._reply(
                '<h1>Two-factor authentication</h1><p>Enter your verification code</p>'
                '<form method="post" action="/verify-otp">'
                '<input name="otp" autocomplete="one-time-code">'
                '<button type="submit">Verify</button></form>'
            )
        elif path == "/session-ambiguous":
            self._reply("", status=303, headers={"Location": "/welcome"})
        elif valid:
            self._reply('<h1>Account</h1><a id="logout" href="/logout">Logout</a>')
        else:
            self._reply('<p id="error">Invalid username or password</p>' + _form())


class BrowserIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise unittest.SkipTest("Playwright is not installed") from exc
        executable = shutil.which("chromium") or shutil.which("chromium-browser")
        try:
            with sync_playwright() as playwright:
                options: dict[str, object] = {"headless": True}
                if executable:
                    options["executable_path"] = executable
                browser = playwright.chromium.launch(**options)
                browser.close()
        except Exception as exc:
            raise unittest.SkipTest(f"Chromium is unavailable: {exc}") from exc
        cls.lab = _LabServer()
        cls.sink = _LabServer()
        cls.lab.cross_origin = cls.sink.base_url
        cls.threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (cls.lab, cls.sink)
        ]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        for server in (cls.lab, cls.sink):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=3)

    def setUp(self) -> None:
        for server in (self.lab, self.sink):
            with server.lock:
                server.requests.clear()
                server.auth_started.clear()
                server.background_followed.clear()

    def check(self, path: str, *, username: str = _USERNAME, password: str = _PASSWORD, on_capture=None, **options):
        from authchecker.browser import BrowserCheckConfig, run_browser_check

        config = BrowserCheckConfig(headless=True, timeout_seconds=5.0, **options)
        return run_browser_check(
            self.lab.base_url + path,
            Credential(username, password),
            config=config,
            on_capture=on_capture,
        )

    def test_waits_for_javascript_to_render_login_form(self) -> None:
        result = self.check("/delayed", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        self.assertIn("username", result.fields)
        self.assertIn("password", result.fields)
        self.assertEqual(len(self.lab.posts()), 1)

    def test_template_prefers_actual_fields_over_generic_username(self) -> None:
        result = self.check("/template-login", username_field_hint="log", password_field_hint="pwd")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(result.fields, ("log", "pwd"))
        fields = parse_qs(self.lab.posts()[0]["body"])
        self.assertEqual(fields["log"], [_USERNAME])
        self.assertEqual(fields["pwd"], [_PASSWORD])
        self.assertNotIn("other_username", fields)

    def test_submits_csrf_hidden_field_and_cookie_in_same_session(self) -> None:
        result = self.check("/csrf", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        posts = self.lab.posts()
        self.assertEqual(len(posts), 1)
        self.assertEqual(parse_qs(posts[0]["body"])["csrf_token"], [_CSRF])
        self.assertIn("lab_session=local-session", posts[0]["cookie"])

    def test_explicit_failure_selector_identifies_wrong_password(self) -> None:
        result = self.check("/login", password="wrong", failure_selector="#error")
        self.assertEqual(result.outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.lab.posts()), 1)

    def test_uses_positive_logout_marker_without_custom_selector(self) -> None:
        result = self.check("/login")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)

    def test_visible_logout_link_beside_login_form_does_not_stop_submission(self) -> None:
        from authchecker.browser import BrowserCheckConfig, run_browser_check

        progress = []
        result = run_browser_check(
            self.lab.base_url + "/login-with-logout-link",
            Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5),
            on_progress=progress.append,
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.lab.posts()), 1)
        self.assertTrue(any("ссылка «Выход/Logout»" in line and "форма входа доступна" in line for line in progress))

    def test_explicit_success_selector_visible_before_submission_still_stops(self) -> None:
        result = self.check("/login-with-logout-link", success_selector="#preexisting")
        self.assertEqual(result.outcome.status, OutcomeStatus.AMBIGUOUS, result)
        self.assertEqual(result.outcome.evidence["reason"], "preexisting_success")
        self.assertIn("--success-selector", result.outcome.detail)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])

    def test_javascript_fetch_uses_page_csrf_token_and_cookie(self) -> None:
        result = self.check("/fetch", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        posts = self.lab.posts()
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["csrf_header"], _CSRF)
        self.assertIn("lab_session=local-session", posts[0]["cookie"])

    def test_capture_holds_native_request_in_memory_without_sending_or_rate_gate(self) -> None:
        from authchecker.browser import BrowserCheckConfig, run_browser_check

        snapshots = []

        def no_rate_gate(_waiter):
            raise AssertionError("capture must not reserve an authentication attempt")

        result = run_browser_check(
            self.lab.base_url + "/csrf", Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5),
            on_capture=snapshots.append, before_submit=no_rate_gate,
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SKIPPED)
        self.assertEqual(result.outcome.evidence["reason"], "request_captured")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])
        self.assertEqual(len(snapshots), 1)
        snapshot = snapshots[0]
        self.assertEqual(snapshot.method, "POST")
        self.assertEqual(snapshot.url, self.lab.base_url + "/session-csrf")
        self.assertEqual(snapshot.username_field, "username")
        self.assertEqual(snapshot.password_field, "password")
        self.assertEqual(parse_qs(snapshot.body), {
            "username": [_USERNAME], "password": [_PASSWORD], "csrf_token": [_CSRF],
        })
        self.assertTrue(any(cookie["name"] == "lab_session" and cookie["value"] == "local-session" for cookie in snapshot.cookies))
        self.assertIn("application/x-www-form-urlencoded", snapshot.headers["content-type"])
        self.assertIn(_CSRF, snapshot.page_html)
        self.assertEqual(snapshot.page_url, self.lab.base_url + "/csrf")
        for secret in (_USERNAME, _PASSWORD, _CSRF, "local-session", "lab_session"):
            self.assertNotIn(secret, repr(snapshot))

    def test_capture_callback_validation_error_is_generic_and_sends_nothing(self) -> None:
        def reject(snapshot):
            raise ValueError(snapshot.body + snapshot.page_html + str(snapshot.cookies))

        error_output = io.StringIO()
        with redirect_stderr(error_output):
            result = self.check("/csrf", on_capture=reject)
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.outcome.evidence["reason"], "capture_error")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])
        self.assertNotIn(_PASSWORD, result.outcome.detail)
        self.assertNotIn(_CSRF, result.outcome.detail)
        self.assertNotIn("Traceback", error_output.getvalue())

    def test_cookie_overlay_rejects_only_optional_cookies_before_login(self) -> None:
        for path in ("/cookie-consent", "/cookie-anchored"):
            with self.subTest(path=path):
                self.setUp()
                result = self.check(path, success_selector="#logout")
                self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
                self.assertEqual(result.attempted_count, 1)
                self.assertEqual([post["path"] for post in self.lab.posts()], ["/cookie-rejected", "/session"])

    def test_cookie_dialog_without_clear_reject_stops_headless_before_submission(self) -> None:
        result = self.check("/cookie-blocked")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.outcome.evidence["reason"], "cookie_consent")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])

    def test_closes_site_error_overlay_once_then_captures_login_request(self) -> None:
        snapshots = []
        result = self.check("/error-overlay", on_capture=snapshots.append)
        self.assertEqual(result.outcome.status, OutcomeStatus.SKIPPED, result)
        self.assertEqual(result.outcome.evidence["reason"], "request_captured")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(self.lab.posts(), [])

    def test_adaptive_check_continues_after_closing_site_error_overlay(self) -> None:
        from authchecker.browser import BrowserCheckConfig
        from authchecker.browser_http import AdaptiveBrowserChecker

        result = AdaptiveBrowserChecker(timeout_seconds=5)(
            self.lab.base_url + "/error-overlay",
            Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5, success_selector="#logout"),
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual([post["path"] for post in self.lab.posts()], ["/session"])

    def test_persistent_site_error_overlay_stops_without_sending_password(self) -> None:
        result = self.check("/persistent-error-overlay")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED, result)
        self.assertEqual(result.outcome.evidence["reason"], "site_error")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])

    def test_identifier_otp_form_does_not_send_email(self) -> None:
        result = self.check("/identifier")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])

    def test_identifier_then_password_submits_one_bounded_password_attempt(self) -> None:
        result = self.check("/identifier-password", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result)
        self.assertEqual(result.attempted_count, 1)
        posts = self.lab.posts()
        self.assertEqual([post["path"] for post in posts], ["/identify-password", "/session-step"])
        self.assertIn(_USERNAME, posts[0]["body"])
        self.assertNotIn(_PASSWORD, posts[0]["body"])
        self.assertIn(_PASSWORD, posts[1]["body"])
        self.assertNotIn(_USERNAME, posts[1]["body"])

    def test_adaptive_checker_falls_back_to_native_browser_for_two_step_login(self) -> None:
        from authchecker.browser import BrowserCheckConfig
        from authchecker.browser_http import AdaptiveBrowserChecker

        result = AdaptiveBrowserChecker(timeout_seconds=5)(
            self.lab.base_url + "/identifier-password",
            Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(
                headless=True,
                timeout_seconds=5,
                success_selector="#logout",
            ),
        )

        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result)
        self.assertEqual(result.attempted_count, 1)
        posts = self.lab.posts()
        self.assertEqual(
            [post["path"] for post in posts],
            ["/identify-password", "/identify-password", "/session-step"],
        )
        self.assertTrue(all(_PASSWORD not in post["body"] for post in posts[:2]))

    def test_challenge_response_has_specific_reason_without_auth_attempt(self) -> None:
        result = self.check("/challenge")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.attempted_count, 0)
        reason = (result.outcome.detail + str(dict(result.outcome.evidence))).lower()
        self.assertTrue("challenge" in reason or "защит" in reason, reason)
        self.assertEqual(self.lab.posts(), [])

    def test_post_password_otp_stops_before_second_submission(self) -> None:
        result = self.check("/mfa")
        self.assertEqual(result.outcome.status, OutcomeStatus.MFA_REQUIRED)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual([post["path"] for post in self.lab.posts()], ["/session-mfa"])

    def test_redirect_without_positive_marker_is_ambiguous(self) -> None:
        result = self.check("/ambiguous")
        self.assertEqual(result.outcome.status, OutcomeStatus.AMBIGUOUS)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(result.final_url, self.lab.base_url + "/welcome")
        self.assertEqual(len(self.lab.posts()), 1)

    def test_cross_origin_form_never_receives_credentials(self) -> None:
        result = self.check("/cross-origin")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])
        self.assertEqual(self.sink.posts(), [])

    def test_page_cannot_send_two_authentication_requests(self) -> None:
        result = self.check("/double-fetch", success_selector="#logout")
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.lab.posts()), 1)

    def test_post_redirect_never_replays_credentials(self) -> None:
        for path in ("/redirect307", "/redirect308", "/redirect302"):
            with self.subTest(path=path):
                self.setUp()
                result = self.check(path)
                self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
                self.assertEqual(result.attempted_count, 1)
                self.assertEqual(len(self.lab.posts()), 1)
                self.assertEqual(self.sink.requests, [])
                self.assertFalse(any(request["path"] == "/credential-sink" for request in self.lab.requests))

    def test_delayed_background_post_redirect_is_not_a_credential_redirect(self) -> None:
        result = self.check("/late-analytics-redirect", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        self.assertTrue(self.lab.background_followed.is_set())
        posts = self.lab.posts()
        self.assertCountEqual(
            [post["path"] for post in posts],
            ["/background-redirect", "/session-late", "/telemetry-followup"],
        )
        for post in posts:
            if post["path"] != "/session-late":
                self.assertNotIn(_PASSWORD, post["body"])
                self.assertNotIn(_USERNAME, post["body"])
        self.assertEqual(self.sink.requests, [])

    def test_get_form_cannot_put_arbitrary_password_field_in_url(self) -> None:
        result = self.check("/credential-get")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertFalse(any(request["path"] == "/credential-sink" for request in self.lab.requests))

    def test_unrelated_submit_analytics_does_not_spend_authentication_attempt(self) -> None:
        result = self.check("/analytics", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual([post["path"] for post in self.lab.posts()], ["/session-fetch"])

    def test_third_party_submit_analytics_is_not_a_fatal_scope_violation(self) -> None:
        result = self.check("/offsite-analytics", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual([post["path"] for post in self.lab.posts()], ["/session-fetch"])
        self.assertEqual(self.sink.posts(), [])
        self.assertNotIn("blocked_origin", result.outcome.evidence)

    def test_short_login_is_not_matched_as_an_analytics_body_substring(self) -> None:
        result = self.check("/offsite-analytics", username="a", failure_selector="#error")
        self.assertEqual(result.outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual([post["path"] for post in self.lab.posts()], ["/session-fetch"])
        self.assertEqual(self.sink.posts(), [])
        self.assertNotIn("blocked_origin", result.outcome.evidence)

    def test_cross_origin_javascript_credentials_are_blocked_with_safe_diagnostics(self) -> None:
        result = self.check("/offsite-credentials")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.outcome.evidence["reason"], "scope")
        self.assertEqual(result.outcome.evidence["blocked_origin"], self.sink.base_url)
        self.assertEqual(result.outcome.evidence["blocked_method"], "POST")
        self.assertEqual(result.outcome.evidence["blocked_request_type"], "fetch")
        self.assertNotIn("do-not-record", str(dict(result.outcome.evidence)))
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])
        self.assertEqual(self.sink.posts(), [])

    def test_javascript_assets_load_from_another_origin(self) -> None:
        result = self.check("/external-script", success_selector="#logout")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertTrue(any(request["path"] == "/fields.js" for request in self.sink.requests))
        self.assertEqual(self.sink.posts(), [])

    def test_popup_form_is_rejected_before_credentials_are_sent(self) -> None:
        result = self.check("/popup")
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(result.outcome.evidence["reason"], "popup")
        self.assertEqual(self.lab.posts(), [])

    def test_cancellation_at_submission_gate_does_not_send_the_paused_post(self) -> None:
        from authchecker.browser import BrowserCheckCancelled, BrowserCheckConfig, run_browser_check

        def cancel(_waiter):
            raise BrowserCheckCancelled()

        result = run_browser_check(
            self.lab.base_url + "/login", Credential(_USERNAME, _PASSWORD),
            config=BrowserCheckConfig(headless=True, timeout_seconds=5), before_submit=cancel,
        )
        self.assertEqual(result.outcome.status, OutcomeStatus.SKIPPED)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.lab.posts(), [])


if __name__ == "__main__":
    unittest.main()
