"""Replay transport tests use only disposable loopback HTTP servers."""

from __future__ import annotations

import io
import json
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from authchecker.browser import BrowserCheckCancelled, BrowserCheckConfig, BrowserRequestSnapshot
from authchecker.http_replay import HttpReplayTemplate, run_http_replay
from authchecker.models import Credential, OutcomeStatus


_BOOTSTRAP = Credential("capture-user", "capture-password")
_CHECK = Credential("replay-user", "replay-password")


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.records = []
        self.sequence = 0
        self.sink_url = ""

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_port}"


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, *args):
        pass

    def reply(self, body, *, status=200, headers=None, json_body=False):
        raw = (json.dumps(body) if json_body else body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if json_body else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.records.append({"method": "GET", "path": path, "cookie": self.headers.get("Cookie", "")})
        if path == "/challenge":
            self.reply("<title>Just a moment...</title>", status=403, headers={"cf-mitigated": "challenge"})
        elif path == "/forbidden":
            self.reply("Forbidden", status=403)
        elif path == "/rate":
            self.reply("Slow down", status=429, headers={"Retry-After": "2"})
        elif path == "/otp":
            self.reply('<form action="/send_email_otp"><input type="email" name="email"><button>Send code</button></form>')
        elif path == "/already":
            self.reply('<a href="/logout">Logout</a>')
        elif path == "/account":
            self.reply('<h1>Account</h1><a id="logout" class="signed-in" data-account="active" href="/logout">Logout</a>')
        elif path == "/welcome":
            self.reply("<h1>The request was processed</h1>")
        elif path == "/loop":
            self.reply("", status=302, headers={"Location": "/loop"})
        elif path == "/missing-token":
            self.reply('<form><input name="username"><input type="password" name="password"></form>')
        elif path == "/js-shell":
            self.reply('<div id="app"></div><script src="/login.js"></script>')
        else:
            self.server.sequence += 1
            sequence = self.server.sequence
            self.reply(
                f'<meta name="csrf-token" content="fresh-{sequence}">'
                f'<form action="/session" method="post"><input name="username">'
                '<input type="password" name="password">'
                f'<input type="hidden" name="csrf_token" value="fresh-{sequence}">'
                '<input type="hidden" name="return_to" value="/fresh-destination"></form>'
                + ('<form action="/register"><input name="username"><input type="password" name="password">'
                   '<input type="hidden" name="csrf_token" value="registration-token">'
                   '<input type="hidden" name="return_to" value="/register"></form>' if path == "/many-forms" else ""),
                headers={"Set-Cookie": f"sid=session-{sequence}; HttpOnly; Path=/"},
            )

    def do_POST(self):
        path = urlsplit(self.path).path
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        self.server.records.append({"method": "POST", "path": path, "body": raw,
                                    "cookie": self.headers.get("Cookie", ""),
                                    "csrf_header": self.headers.get("X-CSRF-Token", "")})
        sequence = self.server.sequence
        if path == "/session":
            values = parse_qs(raw)
            valid = (values.get("username") == [_CHECK.username]
                     and values.get("password") == [_CHECK.password]
                     and values.get("csrf_token") == [f"fresh-{sequence}"]
                     and values.get("return_to") == ["/fresh-destination"]
                     and values.get("unchanged") == ["preserved"]
                     and f"sid=session-{sequence}" in self.headers.get("Cookie", ""))
            self.reply('<a href="/logout">Logout</a>' if valid else "CSRF token invalid", status=200 if valid else 403)
        elif path == "/session-json":
            values = json.loads(raw)
            valid = (values["account"] == {"username": _CHECK.username, "password": _CHECK.password}
                     and values["csrf"] == f"fresh-{sequence}"
                     and self.headers.get("X-CSRF-Token") == f"fresh-{sequence}"
                     and f"sid=session-{sequence}" in self.headers.get("Cookie", "")
                     and values["count"] == 7)
            self.reply({"authenticated": valid}, json_body=True)
        elif path == "/post-challenge":
            self.reply("<title>Just a moment...</title>", status=403, headers={"cf-mitigated": "challenge"})
        elif path == "/post-rate":
            self.reply("Limited", status=429)
        elif path == "/post-otp":
            self.reply({"mfa_required": True}, json_body=True)
        elif path == "/post-csrf":
            self.reply({"error": "CSRF token expired"}, status=403, json_body=True)
        elif path == "/post-forbidden":
            self.reply("Forbidden", status=403)
        elif path == "/post-failure":
            self.reply({"success": False}, status=401, json_body=True)
        elif path in {"/post307", "/post308", "/outside302", "/success303", "/ambiguous303"}:
            destinations = {
                "/post307": (307, self.server.sink_url + "/credential-sink"),
                "/post308": (308, "/credential-sink"),
                "/outside302": (302, self.server.sink_url + "/account"),
                "/success303": (303, "/account"),
                "/ambiguous303": (303, "/welcome"),
            }
            status, destination = destinations[path]
            self.reply("", status=status, headers={"Location": destination})
        elif path == "/password-remains":
            self.reply('<a href="/logout">Logout</a><form><input type="password" name="password"></form>')
        elif path == "/same-login":
            self.reply(
                '<form action="/same-login" method="post">'
                '<input name="username"><input type="password" name="password">'
                '<button type="submit">Log in</button></form>'
            )
        else:
            self.reply({"success": True}, json_body=True)


class HttpReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.sink = _Server(), _Server()
        cls.server.sink_url = cls.sink.url
        cls.threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (cls.server, cls.sink)]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.sink):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=3)

    def setUp(self):
        self.server.records.clear()
        self.sink.records.clear()
        self.server.sequence = 0

    def capture(self, *, page="/login", action="/session", json_body=False, csrf=True):
        html = ('<meta name="csrf-token" content="capture-token">'
                '<form><input name="username"><input type="password" name="password">'
                '<input type="hidden" name="csrf_token" value="capture-token">'
                '<input type="hidden" name="return_to" value="/captured-destination"></form>') if csrf else '<form><input name="username"><input type="password" name="password"></form>'
        headers = {"Content-Type": "application/json" if json_body else "application/x-www-form-urlencoded",
                   "Cookie": "must-not-copy=old", "Content-Length": "9999"}
        if json_body:
            body = json.dumps({"account": {"username": _BOOTSTRAP.username, "password": _BOOTSTRAP.password}, "csrf": "capture-token", "count": 7})
            headers["X-CSRF-Token"] = "capture-token"
        else:
            values = {"username": _BOOTSTRAP.username, "password": _BOOTSTRAP.password,
                      "return_to": "/captured-destination", "unchanged": "preserved"}
            if csrf:
                values["csrf_token"] = "capture-token"
            body = urlencode(values)
        return BrowserRequestSnapshot(
            "POST", self.server.url + action, headers, body,
            ({"name": "sid", "value": "captured-session", "domain": "127.0.0.1", "path": "/"},
             {"name": "outside", "value": "outside-cookie", "domain": "elsewhere.invalid", "path": "/"}),
            html, self.server.url + page, "username", "password",
        )

    def check(self, *, page="/login", action="/session", json_body=False, csrf=True, config=None, **options):
        template = HttpReplayTemplate.from_capture(self.capture(page=page, action=action, json_body=json_body, csrf=csrf), _BOOTSTRAP)
        return run_http_replay(template, _CHECK, config=config or BrowserCheckConfig(), **options)

    def posts(self):
        return [record for record in self.server.records if record["method"] == "POST"]

    def test_refreshes_hidden_csrf_and_cookie_and_replaces_only_credentials(self):
        result = self.check()
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(self.posts()), 1)
        self.assertIn("sid=captured-session", self.server.records[0]["cookie"])
        self.assertNotIn("outside", self.server.records[0]["cookie"])
        self.assertNotIn(_BOOTSTRAP.password, self.posts()[0]["body"])
        self.assertEqual(parse_qs(self.posts()[0]["body"])["unchanged"], ["preserved"])

    def test_reuses_template_with_independent_rotating_cookie_sessions(self):
        template = HttpReplayTemplate.from_capture(self.capture(), _BOOTSTRAP)
        for _ in range(2):
            result = run_http_replay(template, _CHECK, config=BrowserCheckConfig())
            self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        gets = [record for record in self.server.records if record["method"] == "GET"]
        self.assertEqual([record["cookie"] for record in gets], ["sid=captured-session"] * 2)
        self.assertEqual([parse_qs(record["body"])["csrf_token"] for record in self.posts()], [["fresh-1"], ["fresh-2"]])

    def test_nested_json_and_csrf_header_follow_fresh_meta_token(self):
        result = self.check(action="/session-json", json_body=True)
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.posts()[0]["csrf_header"], "fresh-1")

    def test_refresh_uses_login_form_hidden_fields_not_the_later_registration_form(self):
        result = self.check(page="/many-forms")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(parse_qs(self.posts()[0]["body"])["csrf_token"], ["fresh-1"])

    def test_refresh_challenge_forbidden_rate_otp_and_missing_csrf_send_no_password(self):
        expected = {"/challenge": (OutcomeStatus.UNSUPPORTED, "challenge"),
                    "/forbidden": (OutcomeStatus.UNSUPPORTED, "http_403"),
                    "/rate": (OutcomeStatus.RATE_LIMITED, "rate_limit"),
                    "/otp": (OutcomeStatus.UNSUPPORTED, "otp"),
                    "/missing-token": (OutcomeStatus.UNSUPPORTED, "csrf")}
        for page, (status, reason) in expected.items():
            with self.subTest(page=page):
                result = self.check(page=page)
                self.assertEqual(result.outcome.status, status)
                self.assertEqual(result.outcome.evidence["reason"], reason)
                self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.posts(), [])

    def test_javascript_only_login_page_requests_browser_before_password_post(self):
        result = self.check(page="/js-shell", csrf=False)
        self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.outcome.evidence["reason"], "browser_required")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.posts(), [])

    def test_post_challenge_csrf_rate_otp_and_forbidden_have_accurate_attempt_count(self):
        expected = {"/post-challenge": (OutcomeStatus.UNSUPPORTED, "challenge"),
                    "/post-csrf": (OutcomeStatus.UNSUPPORTED, "csrf"),
                    "/post-rate": (OutcomeStatus.RATE_LIMITED, "rate_limit"),
                    "/post-otp": (OutcomeStatus.MFA_REQUIRED, "otp"),
                    "/post-forbidden": (OutcomeStatus.UNSUPPORTED, "http_403"),
                    "/post-failure": (OutcomeStatus.FAILURE, "login_error")}
        for action, (status, reason) in expected.items():
            with self.subTest(action=action):
                result = self.check(action=action)
                self.assertEqual(result.outcome.status, status)
                self.assertEqual(result.outcome.evidence["reason"], reason)
                self.assertEqual(result.attempted_count, 1)

    def test_post_redirect_never_replays_password_or_visits_outside_origin(self):
        for action in ("/post307", "/post308", "/outside302"):
            with self.subTest(action=action):
                before = len(self.posts())
                result = self.check(action=action)
                self.assertEqual(result.outcome.status, OutcomeStatus.UNSUPPORTED)
                self.assertEqual(result.attempted_count, 1)
                self.assertEqual(len(self.posts()), before + 1)
                self.assertEqual(result.outcome.evidence["request_type"], "http_redirect")
                self.assertEqual(result.outcome.evidence["method"], "GET" if action == "/outside302" else "POST")
                self.assertEqual(result.outcome.evidence["blocked_origin"], self.server.url if action == "/post308" else self.sink.url)
                self.assertNotIn("/account", str(dict(result.outcome.evidence)))
                self.assertNotIn("/credential-sink", str(dict(result.outcome.evidence)))
        self.assertEqual(self.sink.records, [])
        self.assertNotIn("/credential-sink", [record["path"] for record in self.server.records])

    def test_redirect_alone_does_not_claim_success_but_logout_marker_does(self):
        result = self.check(action="/ambiguous303")
        self.assertEqual(result.outcome.status, OutcomeStatus.AMBIGUOUS)
        result = self.check(action="/success303")
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(result.final_url, self.server.url + "/account")

    def test_password_form_still_present_prevents_success(self):
        result = self.check(action="/password-remains")
        self.assertEqual(result.outcome.status, OutcomeStatus.AMBIGUOUS)

    def test_same_login_form_after_post_is_a_confirmed_failure(self):
        result = self.check(page="/same-login", action="/same-login", csrf=False)
        self.assertEqual(result.outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(result.outcome.evidence["reason"], "password_form_remains")

    def test_json_failure_message_is_detected_even_with_http_200(self):
        with patch("authchecker.http_replay._request") as request:
            from authchecker.http_replay import _Response

            request.side_effect = [
                _Response(
                    self.server.url + "/login",
                    200,
                    {"content-type": "text/html"},
                    '<form><input name="username"><input type="password" name="password"></form>',
                ),
                _Response(
                    self.server.url + "/session",
                    200,
                    {"content-type": "application/json"},
                    '{"message":"The username or password does not match"}',
                ),
            ]
            result = self.check(csrf=False)
        self.assertEqual(result.outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(result.outcome.evidence["reason"], "login_error")

    def test_json_auth_signals_distinguish_rejected_credentials_from_generic_errors(self):
        from authchecker.http_replay import _Response

        cases = [
            ({"result": "error", "message": "Имя пользователя или пароль указаны неверно.", "data": ""},
             OutcomeStatus.FAILURE, "login_error"),
            ({"result": "error", "message": "Внутренняя ошибка сервера", "data": ""},
             OutcomeStatus.AMBIGUOUS, "site_error_unclassified"),
            ({"success": False, "message": "Service temporarily unavailable"},
             OutcomeStatus.AMBIGUOUS, "site_error_unclassified"),
            ({"result": "success", "data": ""}, OutcomeStatus.AMBIGUOUS, "unconfirmed"),
            ({"authenticated": True}, OutcomeStatus.SUCCESS, "authenticated_marker"),
            ({"data": {"error_code": "INVALID_CREDENTIALS"}}, OutcomeStatus.FAILURE, "login_error"),
            ({"success": True, "message": "Wrong password"},
             OutcomeStatus.AMBIGUOUS, "site_error_unclassified"),
            ({"message": '<a href="/logout">Logout</a>'},
             OutcomeStatus.AMBIGUOUS, "unconfirmed"),
        ]
        for body, expected_status, expected_reason in cases:
            with self.subTest(body=body), patch("authchecker.http_replay._request") as request:
                request.side_effect = [
                    _Response(
                        self.server.url + "/login", 200, {"content-type": "text/html"},
                        '<form><input name="username"><input type="password" name="password"></form>',
                    ),
                    _Response(
                        self.server.url + "/session", 200, {"content-type": "application/json"},
                        json.dumps(body, ensure_ascii=False),
                    ),
                ]
                result = self.check(csrf=False)
                self.assertEqual(result.outcome.status, expected_status)
                self.assertEqual(result.outcome.evidence["reason"], expected_reason)
                self.assertEqual(result.attempted_count, 1)
                self.assertEqual(request.call_count, 2)

    def test_json_without_correct_content_type_and_duplicate_keys(self):
        from authchecker.http_replay import _Response

        cases = [
            ('{"result":"error","message":"Имя пользователя или пароль указаны неверно."}',
             "text/plain", OutcomeStatus.FAILURE),
            ('{"authenticated":true,"authenticated":false}',
             "application/json", OutcomeStatus.AMBIGUOUS),
        ]
        for body, content_type, expected in cases:
            with self.subTest(body=body), patch("authchecker.http_replay._request") as request:
                request.side_effect = [
                    _Response(
                        self.server.url + "/login", 200, {"content-type": "text/html"},
                        '<form><input name="username"><input type="password" name="password"></form>',
                    ),
                    _Response(
                        self.server.url + "/session", 200, {"content-type": content_type}, body,
                    ),
                ]
                result = self.check(csrf=False)
                self.assertEqual(result.outcome.status, expected)

    def test_already_authenticated_refresh_is_not_reused_as_a_success(self):
        result = self.check(page="/already")
        self.assertEqual(result.outcome.status, OutcomeStatus.AMBIGUOUS)
        self.assertEqual(result.outcome.evidence["reason"], "preexisting_success")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.posts(), [])

    def test_simple_selectors_supported_and_complex_selectors_rejected_before_network(self):
        for selector in ("#logout", ".signed-in", "a[data-account='active']"):
            with self.subTest(selector=selector):
                result = self.check(action="/success303", config=BrowserCheckConfig(success_selector=selector))
                self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        count = len(self.server.records)
        result = self.check(config=BrowserCheckConfig(success_selector="main > a.logout"))
        self.assertEqual(result.outcome.evidence["reason"], "selector")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(len(self.server.records), count)

    def test_missing_credential_mapping_and_duplicate_json_keys_are_rejected(self):
        capture = self.capture()
        for body, content_type in (("username=capture-user&token=opaque", "application/x-www-form-urlencoded"),
                                   ('{"username":"capture-user","password":"capture-password","password":"other"}', "application/json")):
            with self.subTest(body_type=content_type), self.assertRaises(ValueError):
                changed = BrowserRequestSnapshot(capture.method, capture.url, {"Content-Type": content_type}, body,
                                                 capture.cookies, capture.page_html, capture.page_url, "username", "password")
                HttpReplayTemplate.from_capture(changed, _BOOTSTRAP)

    def test_rate_callback_runs_immediately_before_the_single_post_and_can_cancel(self):
        calls = []

        def before_submit(waiter):
            calls.append((len(self.posts()), self.server.records[-1]["method"], callable(waiter)))

        result = self.check(before_submit=before_submit)
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(calls, [(0, "GET", True)])
        before = len(self.posts())

        def cancelled(waiter):
            raise BrowserCheckCancelled()

        result = self.check(before_submit=cancelled)
        self.assertEqual(result.outcome.status, OutcomeStatus.SKIPPED)
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(len(self.posts()), before)

    def test_template_and_result_do_not_log_credentials_cookies_or_token_values(self):
        capture = self.capture()
        template = HttpReplayTemplate.from_capture(capture, _BOOTSTRAP)
        output = io.StringIO()
        progress = []
        with redirect_stdout(output), redirect_stderr(output):
            result = run_http_replay(template, _CHECK, config=BrowserCheckConfig(), on_progress=progress.append)
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        combined = repr(template) + repr(result) + str(dict(result.outcome.evidence)) + output.getvalue() + str(progress)
        for secret in (_BOOTSTRAP.password, _CHECK.password, "capture-token", "fresh-1", "captured-session", "session-1"):
            self.assertNotIn(secret, combined)

    def test_environment_proxy_is_disabled_when_no_proxy_is_selected(self):
        with patch.dict("os.environ", {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "no_proxy": "", "NO_PROXY": ""}):
            result = self.check()
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)

    def test_selected_proxy_is_used_even_for_loopback_and_no_proxy_environment(self):
        with patch.dict("os.environ", {"no_proxy": "127.0.0.1,localhost,*", "NO_PROXY": "127.0.0.1,localhost,*"}):
            result = self.check(config=BrowserCheckConfig(proxy=self.sink.url))
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(self.server.records, [])
        self.assertEqual([record["method"] for record in self.sink.records], ["GET", "POST"])

    def test_capture_with_authorization_headers_is_rejected_before_http_replay(self):
        capture = self.capture()
        for name in ("Authorization", "Proxy-Authorization"):
            with self.subTest(header=name), self.assertRaises(ValueError):
                changed = BrowserRequestSnapshot(capture.method, capture.url,
                                                 {**capture.headers, name: "Bearer captured-first-account"},
                                                 capture.body, capture.cookies, capture.page_html,
                                                 capture.page_url, capture.username_field, capture.password_field)
                HttpReplayTemplate.from_capture(changed, _BOOTSTRAP)

    def test_redirect_limit_is_bounded_without_post(self):
        result = self.check(page="/loop", csrf=False)
        self.assertEqual(result.outcome.evidence["reason"], "redirect_limit")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(len(self.server.records), 6)

    def test_otp_submission_endpoint_is_blocked_before_refresh_or_password(self):
        result = self.check(action="/send_email_otp")
        self.assertEqual(result.outcome.evidence["reason"], "otp")
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(self.server.records, [])


if __name__ == "__main__":
    unittest.main()
