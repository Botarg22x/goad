from __future__ import annotations

import base64
import json
import ssl
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from authchecker.adapters import (
    HttpBasicAdapter,
    HttpResponse,
    PasswordFormAdapter,
    ProxyHttpClient,
    TargetScope,
    validate_live_job,
)
from authchecker.defaults import DEFAULT_USER_AGENT
from authchecker.models import AuthJob, Credential, OutcomeStatus
from authchecker.template_profile import html_signals, profile_outcome, validate_profile


def http_job(
    *,
    auth_type: str,
    endpoint: str,
    metadata: dict[str, object] | None = None,
) -> AuthJob:
    return AuthJob(
        job_key="job-loopback",
        report_run_id="12345678-1234-5678-9234-567812345678",
        finding_id="auth-0123456789abcdef",
        kind="http_auth_challenge" if auth_type == "http_basic" else "web_login_page",
        auth_type=auth_type,
        endpoint=endpoint,
        host="127.0.0.1",
        port=8080,
        protocol="http",
        form_action=(metadata or {}).get("form_action") if metadata else None,
        metadata=metadata or {},
    )


class FakeHttpClient:
    def __init__(self, response: HttpResponse | list[HttpResponse]) -> None:
        self.responses = list(response) if isinstance(response, list) else [response]
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append(
            {"method": method, "url": url, "headers": headers or {}, "body": body}
        )
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def password_job(*, endpoint="http://127.0.0.1:8080/login", action="http://127.0.0.1:8080/session"):
    return http_job(
        auth_type="password_form", endpoint=endpoint,
        metadata={
            "form_action": action,
            "form_method": "POST",
            "fields": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
            ],
        },
    )


class HttpAdapterTests(unittest.TestCase):
    def test_template_post_status_and_final_body_must_both_match(self) -> None:
        profile = {
            "schema": "form-check/1", "transport": "http",
            "request": {
                "method": "POST", "action": "form", "encoding": "form", "session": "fresh",
                "defaults": {}, "csrf_fields": [],
                "raw": "POST {{action}} HTTP/1.1\nHost: {{host}}\nContent-Type: application/x-www-form-urlencoded\n\nusername={{login}}&password={{password}}&{{form_fields}}",
            },
            "result": {
                "success_any": [{"in_body": 'href="/users/sign_out"'}],
                "failure_any": [{"in_body": "Invalid login or password"}],
                "captcha_any": [], "mfa_any": [], "csrf_error_any": [],
                "success_status": 302, "failure_status": 200,
            },
        }
        validate_profile(profile)
        metadata = {
            "form_action": "http://127.0.0.1:8080/session", "form_method": "POST",
            "login_template": "example",
            "credential_fields": {"username": "username", "password": "password"},
            "fields": [{"name": "username", "type": "text"},
                       {"name": "password", "type": "password"}],
            "login_verification": profile,
        }
        job = http_job(auth_type="password_form", endpoint="http://127.0.0.1:8080/login", metadata=metadata)
        page = HttpResponse(200, body='<form method="post" action="/session"><input name="username" type="text"><input name="password" type="password"></form>')
        cases = [
            ([page, HttpResponse(200, body="Invalid login or password")], OutcomeStatus.FAILURE, "login_error"),
            ([page, HttpResponse(302, {"location": "/home"}), HttpResponse(200, body='href="/users/sign_out"')], OutcomeStatus.SUCCESS, "authenticated_marker"),
            ([page, HttpResponse(302, {"location": "/home"}), HttpResponse(200, body="Account review")], OutcomeStatus.AMBIGUOUS, "template_response_differs"),
            ([page, HttpResponse(302, {"location": "/login"}), HttpResponse(200, body="Invalid login or password")], OutcomeStatus.AMBIGUOUS, "template_response_differs"),
            ([page, HttpResponse(200, body="Unexpected reply")], OutcomeStatus.AMBIGUOUS, "template_response_differs"),
        ]
        for responses, expected_status, reason in cases:
            with self.subTest(expected_status=expected_status, reason=reason):
                outcome = PasswordFormAdapter(FakeHttpClient(responses)).attempt(job, Credential("root", "secret"))
                self.assertEqual(outcome.status, expected_status, outcome.detail)
                self.assertEqual(outcome.evidence["reason"], reason)
                self.assertEqual(outcome.evidence["post_status"], responses[1].status)
        with self.assertRaises(ValueError):
            validate_profile({**profile, "result": {**profile["result"], "failure_status": True}})

    def test_template_result_can_use_only_post_response_codes(self) -> None:
        profile = {
            "schema": "form-check/1", "transport": "http",
            "request": {
                "method": "POST", "action": "form", "encoding": "form", "session": "fresh",
                "defaults": {}, "csrf_fields": [],
            },
            "result": {
                "success_any": [], "failure_any": [], "captcha_any": [],
                "mfa_any": [], "csrf_error_any": [],
                "success_status": 302, "failure_status": 200,
            },
        }
        validate_profile(profile)
        url = "http://127.0.0.1:8080/login"
        cases = (
            (200, "<p>Wrong pair</p>", 200, OutcomeStatus.FAILURE, "failure_status"),
            (302, "<h1>Account</h1>", 200, OutcomeStatus.SUCCESS, "success_status"),
            (302, '<form><input type="password"></form>', 200, None, None),
            (303, "<h1>Account</h1>", 200, None, None),
        )
        for post_status, body, final_status, expected, rule in cases:
            with self.subTest(post_status=post_status, body=body):
                outcome = profile_outcome(profile, html_signals(body), url,
                                          status=final_status, post_status=post_status,
                                          submitted=True)
                self.assertEqual(outcome.status if outcome else None, expected)
                if outcome:
                    self.assertEqual(outcome.evidence["template_rule"], rule)

        metadata = {
            "form_action": "http://127.0.0.1:8080/session", "form_method": "POST",
            "login_template": "example",
            "credential_fields": {"username": "username", "password": "password"},
            "fields": [{"name": "username", "type": "text"},
                       {"name": "password", "type": "password"}],
            "login_verification": profile,
        }
        job = http_job(auth_type="password_form", endpoint=url, metadata=metadata)
        page = HttpResponse(200, body='<form method="post" action="/session"><input name="username"><input name="password" type="password"></form>')
        for responses, expected in (
            ([page, HttpResponse(200, body="Wrong pair")], OutcomeStatus.FAILURE),
            ([page, HttpResponse(302, {"location": "/home"}),
              HttpResponse(200, body="<h1>Account</h1>")], OutcomeStatus.SUCCESS),
            ([page, HttpResponse(302, {"location": "/login"}), page], OutcomeStatus.AMBIGUOUS),
        ):
            with self.subTest(expected=expected):
                outcome = PasswordFormAdapter(FakeHttpClient(responses)).attempt(job, Credential("root", "secret"))
                self.assertEqual(outcome.status, expected, outcome.detail)

        profile["result"].pop("success_status")
        validate_profile(profile)
        self.assertIsNone(profile_outcome(profile, html_signals("<h1>Account</h1>"), url,
                                          status=200, post_status=302, submitted=True))
        profile["result"].pop("failure_status")
        with self.assertRaises(ValueError):
            validate_profile(profile)

    def test_template_field_mapping_is_used_for_wordpress(self) -> None:
        metadata = {
            "form_action": "http://127.0.0.1:8080/wp-login.php",
            "form_method": "POST", "login_template": "wordpress",
            "credential_fields": {"username": "log", "password": "pwd"},
            "fields": [{"name": "other_username", "type": "text"},
                       {"name": "log", "type": "text"},
                       {"name": "pwd", "type": "password"}],
        }
        client = FakeHttpClient(HttpResponse(401, body="Invalid username or password"))
        outcome = PasswordFormAdapter(client).attempt(
            http_job(auth_type="password_form", endpoint=metadata["form_action"], metadata=metadata),
            Credential("student", "wrong"),
        )
        self.assertEqual(outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(parse_qs(client.calls[0]["body"].decode()), {"log": ["student"], "pwd": ["wrong"]})

    def test_template_does_not_invent_missing_fields(self) -> None:
        metadata = {
            "form_action": "http://127.0.0.1:8080/wp-login.php",
            "form_method": "POST", "login_template": "wordpress",
            "credential_fields": {"username": "log", "password": "pwd"},
            "fields": [{"name": "pwd", "type": "password"}],
        }
        client = FakeHttpClient(HttpResponse(200))
        result = PasswordFormAdapter(client).attempt(
            http_job(auth_type="password_form", endpoint=metadata["form_action"], metadata=metadata),
            Credential("student", "wrong"),
        )
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(client.calls, [])

    def test_proxy_skips_tls_only_without_explicit_ca(self) -> None:
        self.assertEqual(ProxyHttpClient()._ssl_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(
            ProxyHttpClient("http://127.0.0.1:9090")._ssl_context.verify_mode,
            ssl.CERT_NONE,
        )

    def test_get_password_form_stops_before_sending_credentials(self) -> None:
        client = FakeHttpClient(HttpResponse(200))
        job = http_job(
            auth_type="password_form",
            endpoint="http://127.0.0.1:8080/login",
            metadata={
                "form_action": "http://127.0.0.1:8080/login",
                "form_method": "GET",
                "fields": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ],
            },
        )

        outcome = PasswordFormAdapter(client).attempt(
            job, Credential("student", "secret"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertIn("пароль через GET", outcome.detail)
        self.assertFalse(outcome.evidence["attempted"])
        self.assertEqual(client.calls, [])

    def test_http_basic_builds_header_and_classifies_success(self) -> None:
        client = FakeHttpClient(HttpResponse(200))
        adapter = HttpBasicAdapter(client)
        outcome = adapter.attempt(
            http_job(auth_type="http_basic", endpoint="http://127.0.0.1:8081/basic"),
            Credential("student", "Lab Password!"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.SUCCESS)
        authorization = client.calls[0]["headers"]["Authorization"]
        self.assertEqual(
            base64.b64decode(authorization.removeprefix("Basic ")).decode("utf-8"),
            "student:Lab Password!",
        )

    def test_http_basic_classifies_failure_and_rate_limit(self) -> None:
        job = http_job(
            auth_type="http_basic", endpoint="http://127.0.0.1:8081/basic"
        )
        self.assertEqual(
            HttpBasicAdapter(FakeHttpClient(HttpResponse(401))).attempt(
                job, Credential("student", "wrong")
            ).status,
            OutcomeStatus.FAILURE,
        )
        limited = HttpBasicAdapter(
            FakeHttpClient(HttpResponse(429, {"retry-after": "2"}))
        ).attempt(job, Credential("student", "wrong"))
        self.assertEqual(limited.status, OutcomeStatus.RATE_LIMITED)
        self.assertEqual(limited.retry_after_seconds, 2)

    def test_http_403_has_explicit_reason(self) -> None:
        outcome = HttpBasicAdapter(FakeHttpClient(HttpResponse(403))).attempt(
            http_job(auth_type="http_basic", endpoint="http://127.0.0.1:8081/basic"),
            Credential("student", "wrong"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(outcome.evidence["reason"], "http_403")
        self.assertIn("доступ запрещён", outcome.detail)
        self.assertIn("попытки остановлены", outcome.detail)

    def test_password_form_403_with_explicit_login_error_is_a_failure(self) -> None:
        metadata = {
            "form_action": "http://127.0.0.1:8080/session",
            "form_method": "POST",
            "fields": [
                {"name": "username", "type": "text", "hidden": False, "disabled": False},
                {"name": "password", "type": "password", "hidden": False, "disabled": False},
            ],
        }
        adapter = PasswordFormAdapter(
            FakeHttpClient(HttpResponse(403, body="Invalid username or password"))
        )

        outcome = adapter.attempt(
            http_job(
                auth_type="password_form",
                endpoint="http://127.0.0.1:8080/login",
                metadata=metadata,
            ),
            Credential("student", "wrong"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(outcome.evidence["reason"], "login_error")

    def test_password_form_json_rejection_with_http_200_is_a_failure(self) -> None:
        response = HttpResponse(
            200,
            {"content-type": "application/json"},
            '{"result":"error","message":"Имя пользователя или пароль указаны неверно.","data":""}',
        )
        outcome = PasswordFormAdapter(FakeHttpClient(response)).attempt(
            password_job(), Credential("student", "wrong"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.FAILURE)
        self.assertEqual(outcome.evidence["reason"], "login_error")

    def test_captcha_challenge_is_not_reported_as_wrong_password(self) -> None:
        job = http_job(
            auth_type="http_basic", endpoint="http://127.0.0.1:8081/basic"
        )
        by_header = HttpBasicAdapter(
            FakeHttpClient(HttpResponse(403, {"cf-mitigated": "challenge"}))
        ).attempt(job, Credential("student", "wrong"))
        by_html = HttpBasicAdapter(
            FakeHttpClient(HttpResponse(200, body="<title>Just a moment...</title>"))
        ).attempt(job, Credential("student", "wrong"))

        for outcome in (by_header, by_html):
            self.assertEqual(outcome.status, OutcomeStatus.UNSUPPORTED)
            self.assertEqual(outcome.evidence["reason"], "challenge")
            self.assertIn("CAPTCHA", outcome.detail)

    def test_password_form_uses_discovered_field_names(self) -> None:
        metadata = {
            "form_action": "http://127.0.0.1:8080/session",
            "form_method": "POST",
            "fields": [
                {
                    "name": "email",
                    "type": "text",
                    "autocomplete": "username",
                    "disabled": False,
                    "hidden": False,
                },
                {
                    "name": "secret",
                    "type": "password",
                    "autocomplete": "current-password",
                    "disabled": False,
                    "hidden": False,
                },
            ],
        }
        client = FakeHttpClient([
            HttpResponse(302, {"location": "/dashboard"}),
            HttpResponse(200, body='<a href="/logout">Log out</a>'),
        ])
        outcome = PasswordFormAdapter(client).attempt(
            http_job(
                auth_type="password_form",
                endpoint="http://127.0.0.1:8080/login",
                metadata=metadata,
            ),
            Credential("student", "Lab Password!"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.SUCCESS)
        self.assertEqual(client.calls[0]["url"], metadata["form_action"])
        self.assertEqual(
            parse_qs(client.calls[0]["body"].decode("utf-8")),
            {"email": ["student"], "secret": ["Lab Password!"]},
        )
        self.assertEqual(client.calls[1]["method"], "GET")
        self.assertIsNone(client.calls[1]["body"])

    def test_redirect_path_alone_never_establishes_success_or_failure(self) -> None:
        for path in ("/dashboard", "/session/new", "/login", "/auth/success"):
            with self.subTest(path=path):
                client = FakeHttpClient([
                    HttpResponse(303, {"location": path}),
                    HttpResponse(200, body="<h1>Welcome</h1>"),
                ])
                result = PasswordFormAdapter(client).attempt(
                    password_job(), Credential("student", "wrong"),
                )
                self.assertEqual(result.status, OutcomeStatus.AMBIGUOUS)
                self.assertEqual(result.evidence["reason"], "unconfirmed")

    def test_same_login_form_after_post_is_failure(self) -> None:
        form = '<form method="post"><input name="username"><input type="password" name="password"></form>'
        for action, responses in (
            ("http://127.0.0.1:8080/login", [HttpResponse(200, body=form)]),
            ("http://127.0.0.1:8080/session", [
                HttpResponse(303, {"location": "/login"}),
                HttpResponse(200, body=form),
            ]),
        ):
            with self.subTest(action=action):
                result = PasswordFormAdapter(FakeHttpClient(responses)).attempt(
                    password_job(action=action), Credential("student", "wrong"),
                )
                self.assertEqual(result.status, OutcomeStatus.FAILURE)
                self.assertEqual(result.evidence["reason"], "password_form_remains")

    def test_json_auth_evidence_is_used_without_another_credential_request(self) -> None:
        cases = (
            ({"authenticated": True}, OutcomeStatus.SUCCESS, "authenticated_marker"),
            ({"result": "error", "message": "Имя пользователя или пароль указаны неверно."},
             OutcomeStatus.FAILURE, "login_error"),
            ({"success": False, "message": "Service temporarily unavailable"},
             OutcomeStatus.AMBIGUOUS, "site_error_unclassified"),
            ({"result": "success"}, OutcomeStatus.AMBIGUOUS, "unconfirmed"),
            ({"success": True, "message": "Wrong password"},
             OutcomeStatus.AMBIGUOUS, "site_error_unclassified"),
        )
        for body, expected_status, reason in cases:
            with self.subTest(body=body):
                client = FakeHttpClient(HttpResponse(
                    200, {"content-type": "application/json"},
                    json.dumps(body, ensure_ascii=False),
                ))
                result = PasswordFormAdapter(client).attempt(
                    password_job(), Credential("student", "secret"),
                )
                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.evidence["reason"], reason)
                self.assertEqual([call["method"] for call in client.calls], ["POST"])

    def test_csrf_error_is_not_reported_as_wrong_password(self) -> None:
        form = '<form><input type="password" name="password"></form>'
        result = PasswordFormAdapter(FakeHttpClient(HttpResponse(
            200, body=form + '<p>Invalid CSRF token</p>',
        ))).attempt(
            password_job(action="http://127.0.0.1:8080/login"),
            Credential("student", "secret"),
        )
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.evidence["reason"], "csrf")

    def test_otp_step_is_not_reported_as_success_or_wrong_password(self) -> None:
        responses = (
            HttpResponse(200, body='<form><input autocomplete="one-time-code" name="otp"></form>'),
            HttpResponse(200, {"content-type": "application/json"}, '{"mfa_required":true}'),
        )
        for response in responses:
            with self.subTest(body=response.body):
                result = PasswordFormAdapter(FakeHttpClient(response)).attempt(
                    password_job(), Credential("student", "secret"),
                )
                self.assertEqual(result.status, OutcomeStatus.MFA_REQUIRED)
                self.assertEqual(result.evidence["reason"], "otp")

    def test_failure_markers_only_come_from_visible_credential_errors(self) -> None:
        for ignored in (
            '<input aria-invalid="false">',
            '<script>const error = "Invalid username or password";</script>',
            '<style>.invalid-password {display:none}</style>',
            '<div hidden>Invalid username or password</div>',
            '<div style="display: none">Invalid username or password</div>',
            '<div aria-hidden="true">Invalid username or password</div>',
            '<template>Invalid username or password</template>',
            '<title>Invalid username or password</title>',
        ):
            with self.subTest(ignored=ignored):
                result = PasswordFormAdapter(FakeHttpClient(HttpResponse(
                    200, body=ignored + '<a href="/logout">Logout</a>',
                ))).attempt(password_job(), Credential("student", "valid"))
                self.assertEqual(result.status, OutcomeStatus.SUCCESS)
        failure = PasswordFormAdapter(FakeHttpClient(HttpResponse(
            200, body='<div role="alert">Invalid <b>username or password</b></div>',
        ))).attempt(password_job(), Credential("student", "wrong"))
        self.assertEqual(failure.status, OutcomeStatus.FAILURE)

    def test_incidental_invalid_text_does_not_claim_wrong_password(self) -> None:
        result = PasswordFormAdapter(FakeHttpClient(HttpResponse(
            200, body="<p>Invalid date format in your profile</p>",
        ))).attempt(password_job(), Credential("student", "unknown"))
        self.assertEqual(result.status, OutcomeStatus.AMBIGUOUS)

    def test_password_form_or_hidden_logout_does_not_prove_success(self) -> None:
        for body in (
            '<a href="/logout" hidden>Logout</a>',
            '<script>"<a href=\'/logout\'>Logout</a>"</script>',
            '<a href="/logout">Logout</a><form><input type="password"></form>',
        ):
            with self.subTest(body=body):
                result = PasswordFormAdapter(FakeHttpClient(HttpResponse(
                    200, body=body,
                ))).attempt(password_job(), Credential("student", "unknown"))
                self.assertEqual(result.status, OutcomeStatus.AMBIGUOUS)

    def test_logout_marker_requires_enabled_control_and_meaningful_local_link(self) -> None:
        for body, expected in (
            ('<button disabled>Logout</button>', OutcomeStatus.AMBIGUOUS),
            ('<button aria-disabled="true">Logout</button>', OutcomeStatus.AMBIGUOUS),
            ('<a href="/logout" aria-disabled="true">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="https://outside.example/logout">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="#">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="#logout">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="javascript:logout()">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a>Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<a href="http://[broken/logout">Logout</a>', OutcomeStatus.AMBIGUOUS),
            ('<button>Logout</button>', OutcomeStatus.SUCCESS),
            ('<a href="/session/end">Logout</a>', OutcomeStatus.SUCCESS),
        ):
            with self.subTest(body=body):
                result = PasswordFormAdapter(FakeHttpClient(HttpResponse(
                    200, body=body,
                ))).attempt(password_job(), Credential("student", "unknown"))
                self.assertEqual(result.status, expected)

    def test_cookie_session_is_private_to_each_credential_attempt(self) -> None:
        client = FakeHttpClient([
            HttpResponse(303, {"location": "/account"}, set_cookie_headers=(
                "session=authenticated; Path=/; HttpOnly", "preference=light; Path=/",
            )),
            HttpResponse(200, body='<a href="/logout">Logout</a>'),
            HttpResponse(303, {"location": "/session/new"}),
            HttpResponse(200, body="Invalid username or password"),
        ])
        adapter = PasswordFormAdapter(client)
        first = adapter.attempt(password_job(), Credential("student", "correct"))
        second = adapter.attempt(password_job(), Credential("student", "wrong"))
        self.assertEqual(first.status, OutcomeStatus.SUCCESS)
        self.assertEqual(second.status, OutcomeStatus.FAILURE)
        self.assertIn("session=authenticated", client.calls[1]["headers"]["Cookie"])
        self.assertIn("preference=light", client.calls[1]["headers"]["Cookie"])
        self.assertNotIn("Cookie", client.calls[2]["headers"])
        self.assertNotIn("Cookie", client.calls[3]["headers"])

    def test_cross_origin_redirect_never_receives_cookies_or_credentials(self) -> None:
        client = FakeHttpClient(HttpResponse(303, {"location": "http://127.0.0.1:8081/account"}))
        result = PasswordFormAdapter(client).attempt(
            password_job(), Credential("student", "password"),
        )
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.evidence["reason"], "scope")
        self.assertTrue(result.evidence["attempted"])
        self.assertEqual(len(client.calls), 1)

    def test_post_redirect_307_or_308_is_not_replayed(self) -> None:
        for status in (307, 308):
            with self.subTest(status=status):
                client = FakeHttpClient(HttpResponse(status, {"location": "/next"}))
                result = PasswordFormAdapter(client).attempt(
                    password_job(), Credential("student", "password"),
                )
                self.assertEqual(result.status, OutcomeStatus.AMBIGUOUS)
                self.assertEqual(result.evidence["reason"], "credential_redirect")
                self.assertEqual(len(client.calls), 1)

    def test_redirect_loop_has_bounded_get_budget(self) -> None:
        client = FakeHttpClient(HttpResponse(303, {"location": "/loop"}))
        result = PasswordFormAdapter(client).attempt(
            password_job(), Credential("student", "password"),
        )
        self.assertEqual(result.status, OutcomeStatus.AMBIGUOUS)
        self.assertEqual(result.evidence["reason"], "redirect_limit")
        self.assertEqual(len(client.calls), 5)
        self.assertEqual([call["method"] for call in client.calls], ["POST"] + ["GET"] * 4)

    def test_https_default_port_and_explicit_443_are_same_origin(self) -> None:
        scope = TargetScope.from_domain("example.test")
        client = FakeHttpClient([
            HttpResponse(303, {"location": "https://example.test:443/account"}),
            HttpResponse(200, body='<a href="/logout">Logout</a>'),
        ])
        result = PasswordFormAdapter(client, scope).attempt(
            password_job(
                endpoint="https://example.test:443/sign-in",
                action="https://example.test/session",
            ),
            Credential("student", "password"),
        )
        self.assertEqual(result.status, OutcomeStatus.SUCCESS)
        self.assertEqual(len(client.calls), 2)

    def test_password_reflected_into_redirect_query_is_not_sent(self) -> None:
        client = FakeHttpClient(HttpResponse(303, {"location": "/account?password=secret123"}))
        result = PasswordFormAdapter(client).attempt(
            password_job(), Credential("student", "secret123"),
        )
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.evidence["reason"], "credential_url")
        self.assertEqual(len(client.calls), 1)

    def test_password_form_does_not_send_credentials_without_fresh_hidden_fields(self) -> None:
        metadata = {
            "form_action": "http://127.0.0.1:8080/session",
            "form_method": "POST",
            "fields": [
                {"name": "csrf", "type": "hidden", "hidden": True},
                {"name": "username", "type": "text", "hidden": False},
                {"name": "password", "type": "password", "hidden": False},
            ],
        }
        client = FakeHttpClient(HttpResponse(200))
        outcome = PasswordFormAdapter(client).attempt(
            http_job(
                auth_type="password_form",
                endpoint="http://127.0.0.1:8080/login",
                metadata=metadata,
            ),
            Credential("student", "password"),
        )

        self.assertEqual(outcome.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual([call["method"] for call in client.calls], ["GET"])

    def test_live_job_requires_scope_and_proxy_requires_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "scope-domain"):
            validate_live_job(
                http_job(auth_type="http_basic", endpoint="http://example.test/basic")
            )
        ProxyHttpClient("http://192.0.2.10:8080")
        with self.assertRaisesRegex(ValueError, "http://"):
            ProxyHttpClient("https://127.0.0.1:8080")

    def test_direct_http_connects_to_target_with_origin_form(self) -> None:
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b"ok"
        connection = Mock()
        connection.getresponse.return_value = response

        with patch(
            "authchecker.adapters.http.http.client.HTTPConnection",
            return_value=connection,
        ) as connection_class:
            result = ProxyHttpClient().request(
                "GET", "http://127.0.0.1:8081/admin/basic?view=short"
            )

        connection_class.assert_called_once_with(
            "127.0.0.1", 8081, timeout=10.0
        )
        self.assertEqual(
            connection.request.call_args.args[:2],
            ("GET", "/admin/basic?view=short"),
        )
        self.assertEqual(result.status, 200)

    def test_external_domain_scope_allows_root_and_subdomains_only(self) -> None:
        scope = TargetScope.from_domain("Example.Test", include_subdomains=True)
        self.assertIsNotNone(scope)
        validate_live_job(
            http_job(auth_type="http_basic", endpoint="https://auth.example.test/basic"),
            scope,
        )
        with self.assertRaisesRegex(ValueError, "outside scope"):
            validate_live_job(
                http_job(auth_type="http_basic", endpoint="https://example.test.evil/basic"),
                scope,
            )

    def test_proxy_client_never_connects_directly_to_target(self) -> None:
        response = Mock()
        response.status = 200
        response.getheaders.return_value = [("Content-Type", "text/plain")]
        response.read.return_value = b"ok"
        connection = Mock()
        connection.getresponse.return_value = response

        with patch(
            "authchecker.adapters.http.http.client.HTTPConnection",
            return_value=connection,
        ) as connection_class:
            result = ProxyHttpClient("http://127.0.0.1:9090").request(
                "GET", "http://127.0.0.1:8081/admin/basic"
            )

        connection_class.assert_called_once_with(
            "127.0.0.1", 9090, timeout=10.0
        )
        self.assertEqual(
            connection.request.call_args.args[:2],
            ("GET", "http://127.0.0.1:8081/admin/basic"),
        )
        self.assertEqual(result.status, 200)

    def test_proxy_client_sends_configured_user_agent(self) -> None:
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b"ok"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch(
            "authchecker.adapters.http.http.client.HTTPConnection",
            return_value=connection,
        ):
            ProxyHttpClient(
                "http://127.0.0.1:9090", user_agent="Custom Audit UA"
            ).request("GET", "http://127.0.0.1:8080/login")

        self.assertEqual(
            connection.request.call_args.kwargs["headers"]["User-Agent"],
            "Custom Audit UA",
        )

    def test_proxy_client_uses_browser_user_agent_by_default(self) -> None:
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b"ok"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch(
            "authchecker.adapters.http.http.client.HTTPConnection",
            return_value=connection,
        ):
            ProxyHttpClient("http://127.0.0.1:9090").request(
                "GET", "http://127.0.0.1:8080/login"
            )

        self.assertEqual(
            connection.request.call_args.kwargs["headers"]["User-Agent"],
            DEFAULT_USER_AGENT,
        )

    def test_https_target_uses_connect_tunnel_through_local_proxy(self) -> None:
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.read.return_value = b"ok"
        connection = Mock()
        connection.getresponse.return_value = response
        scope = TargetScope.from_domain("example.test", include_subdomains=True)
        with patch(
            "authchecker.adapters.http.http.client.HTTPSConnection",
            return_value=connection,
        ) as connection_class:
            result = ProxyHttpClient(
                "http://127.0.0.1:9090", target_scope=scope
            ).request("GET", "https://auth.example.test/login?view=compact")

        connection_class.assert_called_once()
        connection.set_tunnel.assert_called_once_with(
            "auth.example.test", 443, headers={"Host": "auth.example.test"}
        )
        self.assertEqual(connection.request.call_args.args[:2], ("GET", "/login?view=compact"))
        self.assertEqual(result.status, 200)


if __name__ == "__main__":
    unittest.main()
