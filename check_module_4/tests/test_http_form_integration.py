"""Exercise HTTP login evidence and session isolation against a local server."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from authchecker.adapters import PasswordFormAdapter, ProxyHttpClient
from authchecker.discovery import discover_login_url
from authchecker.jobs import build_jobs
from authchecker.models import AuthJob, Credential, OutcomeStatus


_FORM = (
    '<form method="post" action="/session">'
    '<input name="username" autocomplete="username">'
    '<input type="password" name="password"></form>'
)
_ACCOUNT = (
    '<script>const invalid = "Invalid username or password";</script>'
    '<div hidden>Incorrect password</div>'
    '<a href="/logout" aria-invalid="false">Logout</a>'
)


class _FormLab(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _FormHandler)
        self.requests: list[tuple[str, str]] = []
        self.csrf_sequence = 0
        self.csrf_posts: list[tuple[dict[str, list[str]], str]] = []
        self.token_login_requests: list[str] = []
        self.token_session_posts: list[str] = []

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


class _FormHandler(BaseHTTPRequestHandler):
    server: _FormLab

    def log_message(self, *_args) -> None:
        pass

    def reply(self, body: str, *, status: int = 200, headers=()) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self.server.requests.append(("GET", path))
        if path == "/token-login":
            self.server.token_login_requests.append(self.path)
            if parse_qs(urlsplit(self.path).query).get("access_token") == ["session-token"]:
                self.reply(_FORM.replace(
                    'action="/session"',
                    'action="/token-session?access_token=session-token"',
                ))
            else:
                self.reply("<p>Invalid token</p>", status=403)
        elif path in {"/session/new", "/authenticate/complete"}:
            if "lab_auth=accepted" in self.headers.get("Cookie", ""):
                self.reply(_ACCOUNT)
            else:
                self.reply('<p>Invalid username or password</p>' + _FORM)
        elif path in {"/csrf-login", "/csrf-missing"}:
            self.server.csrf_sequence += 1
            token = f"fresh-{self.server.csrf_sequence}"
            token_input = (
                f'<input type="hidden" name="authenticity_token" value="{token}">'
                if path == "/csrf-login" else ""
            )
            body = (
                '<form method="post" action="/register">'
                '<input name="email"><input type="password" name="password">'
                '<input type="hidden" name="authenticity_token" value="registration-token">'
                '</form>'
                '<form method="post" action="/csrf-session">'
                f'{token_input}'
                '<input type="hidden" name="return_to" value="/account">'
                f'<input type="text" name="required_field_{self.server.csrf_sequence}" '
                'value="" style="display:none">'
                '<input name="username" autocomplete="username">'
                '<input type="password" name="password">'
                '<input type="submit" name="commit" value="Sign in">'
                '</form>'
            )
            self.reply(body, headers=(("Set-Cookie", f"sid={token}; Path=/; HttpOnly"),))
        elif path == "/loop":
            self.reply("", status=302, headers=(("Location", "/loop"),))
        elif path == "/welcome":
            self.reply("<p>Welcome to our site</p>")
        else:
            self.reply(_FORM)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        self.server.requests.append(("POST", path))
        if path == "/token-session":
            self.server.token_session_posts.append(self.path)
        form = parse_qs(
            self.rfile.read(int(self.headers["Content-Length"])).decode(),
            keep_blank_values=True,
        )
        if path == "/csrf-session":
            cookie = self.headers.get("Cookie", "")
            self.server.csrf_posts.append((form, cookie))
            token = form.get("authenticity_token", [""])[0]
            session_valid = bool(token) and f"sid={token}" in cookie
            accepted = (
                session_valid and form.get("username") == ["student"]
                and form.get("password") == ["correct"]
            )
            headers = [("Location", "/session/new")]
            if accepted:
                headers.append(("Set-Cookie", "lab_auth=accepted; Path=/; HttpOnly"))
            self.reply("", status=303, headers=headers)
            return
        accepted = form.get("username") == ["student"] and form.get("password") == ["correct"]
        if path == "/token-session":
            accepted = accepted and parse_qs(urlsplit(self.path).query).get("access_token") == ["session-token"]
        if path == "/plain-result":
            self.reply(_ACCOUNT if accepted else "<p>Invalid username or password</p>")
            return
        if path == "/keep-post":
            self.reply("", status=307, headers=(("Location", "/session/new"),))
            return
        destination = {
            "/session": "/session/new",
            "/auth-path": "/authenticate/complete",
            "/loop-result": "/loop",
            "/neutral-result": "/welcome",
            "/outside-result": "http://localhost:1/landing",
        }.get(path, "/session/new")
        headers = [("Location", destination)]
        if accepted:
            # Multiple Set-Cookie headers must survive the HTTP transport.
            headers.extend((
                ("Set-Cookie", "lab_auth=accepted; Path=/; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "lab_preferences=compact; Path=/"),
            ))
        self.reply("", status=303, headers=headers)


class HttpFormIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = _FormLab()
        self.thread = threading.Thread(target=self.lab.serve_forever, daemon=True)
        self.thread.start()
        self.adapter = PasswordFormAdapter(ProxyHttpClient(timeout_seconds=2))

    def tearDown(self) -> None:
        self.lab.shutdown()
        self.lab.server_close()
        self.thread.join(3)

    def attempt(self, action: str, password: str):
        job = AuthJob(
            job_key="local-form",
            report_run_id="local-run",
            finding_id="local-finding",
            kind="web_login_page",
            auth_type="password_form",
            endpoint=self.lab.base_url + "/login",
            host="127.0.0.1",
            port=self.lab.server_port,
            protocol="http",
            form_action=self.lab.base_url + action,
            metadata={
                "form_method": "POST",
                "fields": [
                    {"name": "username", "autocomplete": "username"},
                    {"name": "password", "type": "password"},
                ],
            },
        )
        return self.adapter.attempt(job, Credential("student", password))

    def attempt_csrf(self, password: str, *, missing: bool = False):
        job = AuthJob(
            job_key="local-csrf-form",
            report_run_id="local-run",
            finding_id="local-finding",
            kind="web_login_page",
            auth_type="password_form",
            endpoint=self.lab.base_url + ("/csrf-missing" if missing else "/csrf-login"),
            host="127.0.0.1",
            port=self.lab.server_port,
            protocol="http",
            form_action=self.lab.base_url + "/csrf-session",
            metadata={
                "form_method": "POST",
                "fields": [
                    {"name": "authenticity_token", "type": "hidden"},
                    {"name": "return_to", "type": "hidden"},
                    {"name": "required_field_discovery", "type": "text", "hidden": True},
                    {"name": "username", "autocomplete": "username"},
                    {"name": "password", "type": "password"},
                ],
            },
        )
        return self.adapter.attempt(job, Credential("student", password))

    def test_same_redirect_requires_authenticated_page_and_keeps_cookies(self) -> None:
        rejected = self.attempt("/session", "wrong")
        accepted = self.attempt("/session", "correct")

        self.assertEqual(rejected.status, OutcomeStatus.FAILURE)
        self.assertEqual(accepted.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.lab.requests.count(("POST", "/session")), 2)
        self.assertEqual(self.lab.requests.count(("GET", "/session/new")), 2)

    def test_token_url_survives_discovery_and_live_authentication(self) -> None:
        url = self.lab.base_url + "/token-login?access_token=session-token"
        report = discover_login_url(
            url, timeout_seconds=2, browser_fallback=False,
        )
        jobs = build_jobs(report, supported_auth_types={"password_form"})
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].endpoint, url)
        outcome = self.adapter.attempt(jobs[0], Credential("student", "correct"))
        self.assertEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertGreaterEqual(self.lab.token_login_requests.count(
            "/token-login?access_token=session-token"
        ), 1)
        self.assertEqual(
            self.lab.token_session_posts,
            ["/token-session?access_token=session-token"],
        )

    def test_successful_session_is_not_reused_for_next_password(self) -> None:
        accepted = self.attempt("/session", "correct")
        rejected = self.attempt("/session", "wrong")

        self.assertEqual(accepted.status, OutcomeStatus.SUCCESS)
        self.assertEqual(rejected.status, OutcomeStatus.FAILURE)

    def test_success_does_not_depend_on_auth_substring_in_final_path(self) -> None:
        outcome = self.attempt("/auth-path", "correct")

        self.assertEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertIn(("GET", "/authenticate/complete"), self.lab.requests)

    def test_raw_html_failure_words_do_not_override_visible_logout(self) -> None:
        outcome = self.attempt("/plain-result", "correct")

        self.assertEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.lab.requests, [("POST", "/plain-result")])

    def test_redirect_to_neutral_page_is_ambiguous(self) -> None:
        outcome = self.attempt("/neutral-result", "wrong")

        self.assertEqual(outcome.status, OutcomeStatus.AMBIGUOUS)

    def test_redirect_loop_is_bounded_and_does_not_repeat_post(self) -> None:
        outcome = self.attempt("/loop-result", "wrong")

        self.assertNotEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(sum(method == "POST" for method, _ in self.lab.requests), 1)
        self.assertLessEqual(sum(method == "GET" for method, _ in self.lab.requests), 10)

    def test_cross_origin_redirect_is_not_requested(self) -> None:
        outcome = self.attempt("/outside-result", "correct")

        self.assertNotEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.lab.requests, [("POST", "/outside-result")])

    def test_307_does_not_replay_credential_post(self) -> None:
        outcome = self.attempt("/keep-post", "correct")

        self.assertNotEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.lab.requests, [("POST", "/keep-post")])

    def test_hidden_csrf_is_refreshed_for_each_attempt_in_private_cookie_session(self) -> None:
        rejected = self.attempt_csrf("wrong")
        accepted = self.attempt_csrf("correct")

        self.assertEqual(rejected.status, OutcomeStatus.FAILURE)
        self.assertEqual(accepted.status, OutcomeStatus.SUCCESS)
        self.assertEqual(len(self.lab.csrf_posts), 2)
        self.assertEqual(
            [form["authenticity_token"] for form, _ in self.lab.csrf_posts],
            [["fresh-1"], ["fresh-2"]],
        )
        for form, cookie in self.lab.csrf_posts:
            self.assertIn("sid=" + form["authenticity_token"][0], cookie)
            self.assertEqual(form["return_to"], ["/account"])
            self.assertNotEqual(form["authenticity_token"], ["registration-token"])
            self.assertEqual(form["commit"], ["Sign in"])
            self.assertIn("required_field_" + form["authenticity_token"][0].split("-")[-1], form)
            self.assertNotIn("required_field_discovery", form)
        self.assertEqual(self.lab.requests.count(("GET", "/csrf-login")), 2)

    def test_missing_csrf_stops_before_post(self) -> None:
        result = self.attempt_csrf("correct", missing=True)

        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertFalse(result.evidence["attempted"])
        self.assertEqual(self.lab.csrf_posts, [])


if __name__ == "__main__":
    unittest.main()
