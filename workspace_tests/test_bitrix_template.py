"""Legacy Bitrix site-form contract remains compatible; no external traffic."""
from __future__ import annotations

import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "discovery_module_3" / "src", ROOT / "check_module_4" / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from authpoints.classifier import classify_web
from authpoints.cli import main as discover
from authpoints.login_templates import load_login_templates
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authpoints.template_verification import validate_verification
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter
from authchecker.browser import BrowserCheckConfig, BrowserCheckResult
from authchecker.browser_adapter import BrowserAdapter, TemplateFormAdapter
from authchecker.importer import parse_report, ReportValidationError
from authchecker.jobs import build_jobs
from authchecker.models import Credential, Outcome, OutcomeStatus
from authchecker.template_profile import html_signals, profile_outcome, validate_profile


URL = "http://127.0.0.1:8080/company/enter"
FORM = '''<title>1С-Битрикс</title><form method="post" action="/custom/session?lang=ru">
<input name="USER_LOGIN"><input type="password" name="USER_PASSWORD">
<input type="hidden" name="AUTH_FORM" value="Y"><input type="hidden" name="TYPE" value="AUTH">
<input type="hidden" name="sessid" value="fresh-token"><input type="submit" name="Login" value="Войти">
</form>'''
SUCCESS = '<a href="/company/?logout=yes&amp;sessid=fresh">Завершить сеанс</a>'
SUCCESS_FORM = '<form action="/company/"><input type="hidden" name="logout" value="yes"><input type="submit" name="logout_butt" value="Выход"></form>'
FAILURE = '<div class="errortext">Неверный логин или пароль.</div>'


def report_for(body=FORM, url=URL):
    title, text, forms, links = parse_html(body, url)
    # Keep these existing form/action regression fixtures on the old contract.
    # Admin page-based matching has its own end-to-end tests.
    with patch("authpoints.classifier.match_page_template", return_value=None):
        findings = classify_web(WebObservation(url=url, source="http_probe", status_code=200,
            title=title, text=text, forms=forms, links=links))
    report = Report(scope=["127.0.0.1"], findings=findings)
    report.finish()
    return report


def job_for(body=FORM, url=URL):
    return build_jobs(parse_report(report_for(body, url).to_dict()))[0]


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        if not self.responses:
            raise AssertionError("Unexpected request")
        return self.responses.pop(0)


class BitrixTemplateTests(unittest.TestCase):
    def setUp(self):
        load_login_templates.cache_clear()
        self.addCleanup(load_login_templates.cache_clear)
        self.profile = next(t.verification for t in load_login_templates() if t.id == "bitrix-site")

    def test_complete_profile_survives_json_roundtrip_without_secrets(self):
        report = report_for().to_dict()
        serialized = json.dumps(report)
        self.assertNotIn("fresh-token", serialized)
        job = build_jobs(parse_report(serialized))[0]
        self.assertEqual(job.metadata["login_verification"], self.profile)
        self.assertEqual(job.form_action, "http://127.0.0.1:8080/custom/session?lang=ru")
        self.assertEqual(job.metadata["credential_fields"], {"username": "USER_LOGIN", "password": "USER_PASSWORD"})

    def test_fresh_session_hidden_fields_submit_and_actual_action(self):
        client = Client(HttpResponse(200, body=FORM, set_cookie_headers=("sid=isolated; Path=/",)),
                        HttpResponse(303, headers={"location": "/company/home"}),
                        HttpResponse(200, body=SUCCESS))
        result = PasswordFormAdapter(client).attempt(job_for(), Credential("student", "secret"))
        self.assertEqual(result.status, OutcomeStatus.SUCCESS)
        self.assertEqual([c[0] for c in client.calls], ["GET", "POST", "GET"])
        self.assertEqual(client.calls[1][1], "http://127.0.0.1:8080/custom/session?lang=ru")
        self.assertEqual(parse_qs(client.calls[1][3].decode()), {
            "USER_LOGIN": ["student"], "USER_PASSWORD": ["secret"], "AUTH_FORM": ["Y"],
            "TYPE": ["AUTH"], "sessid": ["fresh-token"], "Login": ["Войти"],
        })
        self.assertIn("sid=isolated", client.calls[1][2]["Cookie"])
        self.assertEqual(result.evidence["template_rule"], "success_any")

    def test_defaults_added_when_missing_and_session_refreshed_without_hidden_fields(self):
        form = '<title>Битрикс</title><form method="post"><input name="USER_LOGIN"><input type="password" name="USER_PASSWORD"></form>'
        client = Client(HttpResponse(200, body=form), HttpResponse(200, body=FAILURE))
        result = PasswordFormAdapter(client).attempt(job_for(form), Credential("student", "wrong"))
        self.assertEqual(result.status, OutcomeStatus.FAILURE)
        self.assertEqual(client.calls[0][0], "GET")
        self.assertEqual(parse_qs(client.calls[1][3].decode())["TYPE"], ["AUTH"])

    def test_no_post_on_changed_action_conflicting_fields_missing_token_or_protection(self):
        for body, status, reason in (
            (FORM.replace('value="AUTH"', 'value="REGISTRATION"'), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM.replace('value="fresh-token"', 'value=""'), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM.replace('name="USER_PASSWORD"', 'name="USER_PASSWORD" disabled'), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM.replace('type="password"', 'type="text"'), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM.replace('<input type="hidden" name="sessid" value="fresh-token">', ''), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM.replace('/custom/session?lang=ru', 'https://outside.test/session'), OutcomeStatus.UNSUPPORTED, "preflight"),
            (FORM + '<input name="captcha_word">', OutcomeStatus.UNSUPPORTED, "challenge"),
            ('<input name="USER_OTP">', OutcomeStatus.MFA_REQUIRED, "otp"),
            (FORM + SUCCESS, OutcomeStatus.AMBIGUOUS, "preexisting_success"),
        ):
            with self.subTest(reason=reason, body=body):
                client = Client(HttpResponse(200, body=body))
                result = PasswordFormAdapter(client).attempt(job_for(), Credential("student", "wrong"))
                self.assertEqual(result.status, status)
                self.assertEqual(result.evidence["reason"], reason)
                self.assertFalse(result.evidence["attempted"])
                self.assertEqual(len(client.calls), 1)

    def test_response_rules_and_no_success_from_status_redirect_or_remaining_form(self):
        for body, expected in (
            (FAILURE, OutcomeStatus.FAILURE), (SUCCESS, OutcomeStatus.SUCCESS),
            (SUCCESS_FORM, OutcomeStatus.SUCCESS),
            (SUCCESS_FORM.replace('type="submit"', 'type="hidden"'), OutcomeStatus.AMBIGUOUS),
            (SUCCESS_FORM.replace('/company/', 'https://outside.test/'), OutcomeStatus.AMBIGUOUS),
            ('<div hidden>' + SUCCESS_FORM + '</div>', OutcomeStatus.AMBIGUOUS),
            ('<input name="USER_OTP">', OutcomeStatus.MFA_REQUIRED),
            ('<input name="captcha_word">', OutcomeStatus.UNSUPPORTED),
            ('Ваша сессия истекла', OutcomeStatus.UNSUPPORTED),
            (SUCCESS + FAILURE, OutcomeStatus.AMBIGUOUS),
            (FORM, OutcomeStatus.AMBIGUOUS), ('', OutcomeStatus.AMBIGUOUS),
            ('<script>"Неверный логин или пароль"</script>', OutcomeStatus.AMBIGUOUS),
            ('<div hidden>' + SUCCESS + '</div>', OutcomeStatus.AMBIGUOUS),
            (SUCCESS.replace('/company/?', 'https://outside.test/?'), OutcomeStatus.AMBIGUOUS),
            (SUCCESS.replace('logout=yes', 'logout=yesplease'), OutcomeStatus.AMBIGUOUS),
        ):
            with self.subTest(body=body):
                client = Client(HttpResponse(200, body=FORM), HttpResponse(303, headers={"location": "/company/enter"}), HttpResponse(200, body=body))
                result = PasswordFormAdapter(client).attempt(job_for(), Credential("student", "wrong"))
                self.assertEqual(result.status, expected)
                self.assertEqual(sum(c[0] == "POST" for c in client.calls), 1)

    def test_author_and_consumer_reject_invalid_profiles(self):
        mutations = [
            lambda p: p.update(schema="form-check/9"),
            lambda p: p.update(transport=[]),
            lambda p: p["request"].update(action="https://outside.test/post"),
            lambda p: p["request"].update(method="GET"),
            lambda p: p["request"]["defaults"].update(sessid="fixed"),
            lambda p: p["result"].update(success_any=[{"status": 200}]),
            lambda p: p["result"].update(failure_any=[{"regex": ".*"}]),
            lambda p: p["result"].update(success_any=[], failure_any=[]),
        ]
        for mutation in mutations:
            value = copy.deepcopy(self.profile)
            mutation(value)
            with self.subTest(profile=value):
                with self.assertRaises(ValueError):
                    validate_verification(value, "bitrix.yaml")
                with self.assertRaises(ValueError):
                    validate_profile(value)

    def test_report_validation_rejects_credential_override_before_network(self):
        report = report_for().to_dict()
        report["findings"][0]["metadata"]["login_verification"]["request"]["defaults"]["USER_PASSWORD"] = "constant"
        with self.assertRaises(ReportValidationError):
            parse_report(report)

    def test_browser_receives_identical_rules_and_field_names(self):
        checked = Mock(return_value=BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), 1))
        adapter = BrowserAdapter(BrowserCheckConfig(headless=True), checker=checked)
        adapter.attempt(job_for(), Credential("student", "wrong"))
        config = checked.call_args.kwargs["config"]
        self.assertEqual(json.loads(config.verification_json), self.profile)
        self.assertEqual(config.username_field_hint, "USER_LOGIN")
        self.assertEqual(config.password_field_hint, "USER_PASSWORD")
        self.assertEqual(config.required_csrf_fields, ("sessid",))

    def test_auto_transport_only_before_post_and_not_on_captcha(self):
        cases = [
            (Outcome(OutcomeStatus.UNSUPPORTED, evidence={"reason": "preflight", "attempted": False}), True),
            (Outcome(OutcomeStatus.NETWORK_ERROR, evidence={"attempted": False}), True),
            (Outcome(OutcomeStatus.UNSUPPORTED, evidence={"reason": "challenge", "attempted": False}), False),
            (Outcome(OutcomeStatus.UNSUPPORTED, evidence={"reason": "http_403", "attempted": True}), False),
            (Outcome(OutcomeStatus.NETWORK_ERROR, evidence={"attempted": True}), False),
            (Outcome(OutcomeStatus.AMBIGUOUS, evidence={"attempted": True}), False),
        ]
        for outcome, fallback in cases:
            with self.subTest(outcome=outcome):
                adapter = TemplateFormAdapter(Client(), None, BrowserCheckConfig(headless=True))
                adapter.http = Mock()
                adapter.http.attempt.return_value = outcome
                adapter.browser = Mock()
                adapter.attempt(job_for(), Credential("student", "wrong"))
                self.assertEqual(adapter.browser.attempt.called, fallback)

    def test_short_product_filter_and_long_tools_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp, patch("authpoints.cli.run_active_scan", return_value=Report(scope=[])) as scan:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = discover(["-u", URL, "-t", "bitrix", "--output", str(Path(tmp) / "report.json")])
            self.assertEqual(code, 0)
            config = scan.call_args.args[2]
            self.assertEqual(config.login_templates, ("bitrix",))
            self.assertTrue(config.katana.enabled)
            self.assertFalse(config.nmap.enabled)
            self.assertEqual(config.standard_paths, ["/bitrix/admin/", "/bitrix/admin/index.php"])

    def test_page_only_accepts_product_filter_without_tools(self):
        with tempfile.TemporaryDirectory() as tmp, patch("authpoints.cli.run_active_scan", return_value=Report(scope=[])) as scan:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = discover(["-u", URL, "--page-only", "-t", "bitrix", "--output", str(Path(tmp) / "report.json")])
            self.assertEqual(code, 0)
            self.assertFalse(scan.call_args.args[2].katana.enabled)
            self.assertEqual(scan.call_args.args[2].standard_paths, [])

    def test_unknown_product_fails_without_network(self):
        with patch("authpoints.cli.run_active_scan") as scan, redirect_stderr(io.StringIO()):
            self.assertEqual(discover(["-u", URL, "-t", "made-up"]), 2)
        scan.assert_not_called()

    def test_product_list_repeat_and_explicit_tools(self):
        with tempfile.TemporaryDirectory() as tmp, patch("authpoints.cli.run_active_scan", return_value=Report(scope=[])) as scan:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = discover(["-u", URL, "-t", "bitrix,wordpress", "-t", "bitrix",
                                 "--tools", "katana", "--output", str(Path(tmp) / "report.json")])
            self.assertEqual(code, 0)
            self.assertEqual(scan.call_args.args[2].login_templates, ("bitrix", "wordpress"))
            self.assertEqual(scan.call_args.args[2].standard_paths, [])

    def test_snapshot_does_not_mutate_cached_template(self):
        metadata = report_for().findings[0].metadata
        metadata["login_verification"]["request"]["defaults"]["TYPE"] = "changed"
        self.assertEqual(self.profile["request"]["defaults"]["TYPE"], "AUTH")

    def test_same_form_requirement_for_logout_marker(self):
        body = '<form><input type="hidden" name="logout" value="yes"></form><form><button>Выход</button></form>'
        self.assertIsNone(profile_outcome(self.profile, html_signals(body), URL, submitted=True))
