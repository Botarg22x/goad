"""Primary template mode: real admin YAML -> page finding -> declared request."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs

from test_bitrix_template import Client, FAILURE
from authpoints.classifier import classify_web
from authpoints.login_templates import load_login_templates
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter
from authchecker.importer import parse_report, ReportValidationError
from authchecker.jobs import build_jobs
from authchecker.models import Credential, OutcomeStatus
from authchecker.page_detection import validate_detection


URL = "http://127.0.0.1:8080/bitrix/admin/index.php?lang=ru"
POST_URL = "http://127.0.0.1:8080/bitrix/admin/?login=yes"
ADMIN = '''<title>Авторизация</title><link rel="stylesheet" href="/bitrix/panel/main/auth.css">
<div>Логин Пароль Битрикс<input name="USER_LOGIN" disabled><input name="USER_PASSWORD" type="text" hidden>
<input name="AUTH_FORM" type="hidden" value="Y"><input name="TYPE" type="hidden" value="AUTH">
<input name="sessid" type="hidden" value="fresh-token"></div>'''
ADMIN_SUCCESS = '<script>(window.BX || window.parent.BX).AUTHAGENT.setAuthResult(false);</script>'


def findings(body=ADMIN, url=URL, status=200):
    title, text, forms, links = parse_html(body, url)
    return classify_web(WebObservation(url=url, source="http_probe", status_code=status,
                                       title=title, text=text, body=body, forms=forms, links=links))


def report_for(body=ADMIN, url=URL):
    report = Report(scope=["127.0.0.1"], findings=findings(body, url))
    report.finish()
    return report.to_dict()


def job_for(body=ADMIN, url=URL):
    return build_jobs(parse_report(report_for(body, url)))[0]


class BitrixAdminPageTests(unittest.TestCase):
    def test_recognizes_page_without_form_or_usable_unique_fields(self):
        variants = [ADMIN, ADMIN + ADMIN, ADMIN.replace('type="text" hidden', 'type="password"'),
                    ADMIN.replace('<div>', '<section>').replace('</div>', '</section>')]
        for body in variants:
            with self.subTest(body=body):
                result = findings(body)
                self.assertEqual(len(result), 1)
                item = result[0]
                self.assertEqual(item.metadata["login_template"], "bitrix")
                self.assertEqual(item.metadata["credential_fields_source"], "template")
                self.assertEqual(item.metadata["form_action"], POST_URL)
                self.assertEqual(item.metadata["login_verification"]["request"]["action"], "fixed")

    def test_product_name_url_or_resources_alone_are_not_login(self):
        cases = [("<title>Битрикс</title>", URL, 200),
                 ('<link href="/bitrix/panel/main/auth.css"><title>Новости</title>', URL, 200),
                 (ADMIN, URL, 404), (ADMIN, URL, 403), (ADMIN, URL, 500),
                 ('<title>Авторизация</title>', URL, 200),
                 (ADMIN.replace("Авторизация", "Регистрация"), URL, 200),
                 (ADMIN.replace("Логин", "Имя"), URL, 200),
                 (ADMIN.replace("Битрикс", "Продукт"), URL, 200)]
        for body, url, status in cases:
            with self.subTest(url=url, status=status, body=body):
                self.assertFalse(any(f.metadata.get("login_template") == "bitrix" for f in findings(body, url, status)))

    def test_original_body_markers_are_kept_as_a_complete_branch(self):
        body = ('<title>Другое</title><div>Авторизация Логин Пароль Битрикс</div>'
                '<input name="USER_LOGIN"><input name="USER_PASSWORD">')
        self.assertEqual(findings(body)[0].metadata["login_template"], "bitrix")
        self.assertFalse(findings(body.replace("Логин", "Имя")))

    def test_complete_body_markers_can_match_a_custom_path(self):
        self.assertEqual(findings(ADMIN, "http://127.0.0.1:8080/custom/admin")[0]
                         .metadata["login_template"], "bitrix")

    def test_no_generic_form_requirements_in_report_import_or_http_submit(self):
        body = ADMIN + '<form action="/elsewhere" method="get"><input name="unrelated" value="not-copied"></form>'
        client = Client(HttpResponse(200, body=body, set_cookie_headers=("sid=current; Path=/",)),
                        HttpResponse(200, body=FAILURE))
        result = PasswordFormAdapter(client).attempt(job_for(body), Credential("user+&=я", "p&+?#="))
        self.assertEqual(result.status, OutcomeStatus.FAILURE, result.detail)
        method, target, headers, payload = client.calls[-1]
        self.assertEqual((method, target), ("POST", POST_URL))
        self.assertEqual(parse_qs(payload.decode(), keep_blank_values=True), {
            "USER_LOGIN": ["user+&=я"], "USER_PASSWORD": ["p&+?#="],
            "AUTH_FORM": ["Y"], "TYPE": ["AUTH"], "Login": [""],
            "captcha_sid": [""], "captcha_word": [""], "sessid": ["fresh-token"],
        })
        self.assertIn("sid=current", headers["Cookie"])
        self.assertEqual(headers["Origin"], "http://127.0.0.1:8080")
        self.assertEqual(headers["Referer"], URL)
        self.assertEqual(headers["Sec-Fetch-Dest"], "iframe")

    def test_fresh_page_rechecked_without_stale_report_tokens(self):
        for body, expected in ((ADMIN.replace("fresh-token", "new-token"), OutcomeStatus.SUCCESS),
                               (ADMIN + ADMIN, OutcomeStatus.SUCCESS),
                               (ADMIN + ADMIN.replace("fresh-token", "other"), OutcomeStatus.UNSUPPORTED),
                               (ADMIN.replace('name="sessid"', 'name="removed"'), OutcomeStatus.UNSUPPORTED),
                               ("<title>Another site</title>", OutcomeStatus.UNSUPPORTED)):
            with self.subTest(body=body):
                client = Client(HttpResponse(200, body=body), HttpResponse(200, body=ADMIN_SUCCESS))
                result = PasswordFormAdapter(client).attempt(job_for(), Credential("student", "wrong"))
                self.assertEqual(result.status, expected, result.detail)
                self.assertEqual(len(client.calls), 2 if expected == OutcomeStatus.SUCCESS else 1)

    def test_protection_before_post_stops_without_spending_attempt(self):
        for suffix, expected in (('<script>{"CAPTCHA":true}</script>', OutcomeStatus.UNSUPPORTED),
                                 ("<input name='USER_OTP'>", OutcomeStatus.MFA_REQUIRED)):
            client = Client(HttpResponse(200, body=ADMIN + suffix))
            result = PasswordFormAdapter(client).attempt(job_for(), Credential("student", "wrong"))
            self.assertEqual(result.status, expected)
            self.assertFalse(result.evidence["attempted"])
            self.assertEqual(len(client.calls), 1)

    def test_contract_requires_detection_and_matching_credential_binding(self):
        for mutation in (lambda p: p.pop("detection"),
                         lambda p: p["detection"].update(match={"regex": ".*"}),
                         lambda p: p["request"].update(raw=p["request"]["raw"].replace("USER_LOGIN=", "other="))):
            report = report_for()
            mutation(report["findings"][0]["metadata"]["login_verification"])
            with self.assertRaises(ReportValidationError):
                parse_report(report)
        self.assertNotIn("fresh-token", json.dumps(report_for()))

    def test_page_grammar_standalone_copies_and_validation(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "check_module_4/src/authchecker/page_detection.py").read_bytes(),
                         (root / "discovery_module_3/src/authpoints/page_detection.py").read_bytes())
        for rule in ({"any": []}, {"unknown": "x"}, {"all": ["bad"]}, {"not": {}}, {"field_names_all": []}):
            with self.assertRaises(ValueError):
                validate_detection({"status_codes": [200], "match": rule})
        profile = next(t for t in load_login_templates() if t.id == "bitrix")
        self.assertEqual(profile.paths, ("/bitrix/admin/", "/bitrix/admin/index.php"))
        self.assertIsNotNone(profile.detection)
