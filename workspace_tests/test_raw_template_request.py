"""Raw YAML recipes remain portable, encoded, and bound to observed forms."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs

from test_bitrix_template import Client, FORM, FAILURE, URL, job_for, report_for
from authpoints.template_verification import validate_verification
from authpoints.login_templates import load_login_templates
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter
from authchecker.importer import parse_report, ReportValidationError
from authchecker.models import Credential, OutcomeStatus
from authchecker.template_profile import validate_profile


class RawTemplateRequestTests(unittest.TestCase):
    def setUp(self):
        self.profile = copy.deepcopy(next(t.verification for t in load_login_templates() if t.id == "bitrix-site"))
        self.raw = self.profile["request"]["raw"]

    def with_raw(self, raw):
        value = copy.deepcopy(self.profile)
        value["request"] = {"raw": raw, "session": "fresh", "csrf_fields": ["sessid"]}
        return value

    def job(self, raw):
        job = job_for()
        return replace(job, metadata={**job.metadata, "login_verification": self.with_raw(raw)})

    def test_independent_packages_share_identical_grammar(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "check_module_4/src/authchecker/template_request.py").read_bytes(),
                         (root / "discovery_module_3/src/authpoints/template_request.py").read_bytes())

    def test_concise_and_expanded_contracts_roundtrip(self):
        value = self.with_raw(self.raw)
        before = copy.deepcopy(value)
        self.assertEqual(validate_verification(value, "test.yaml"), self.profile)
        self.assertEqual(validate_profile(value), self.profile)
        self.assertEqual(value, before)
        self.assertEqual(validate_profile(self.profile), self.profile)
        report = report_for().to_dict()
        self.assertEqual(parse_report(json.dumps(report)).findings[0].metadata["login_verification"]["request"]["raw"], self.raw)

    def test_special_characters_encoded_once_and_extra_header_reaches_request(self):
        raw = self.raw.replace("Referer:", "X-Requested-With: XMLHttpRequest\nReferer:")
        raw = raw.replace("&{{form_fields}}", "&extra=%D1%82%D0%B5%D1%81%D1%82&empty=&{{form_fields}}")
        for credential in (Credential("a+b&c=ю", "p+&=%?# пробел"), Credential("{{password}}", "{{login}}")):
            with self.subTest(credential="special characters"):
                client = Client(HttpResponse(200, body=FORM), HttpResponse(200, body=FAILURE))
                result = PasswordFormAdapter(client).attempt(self.job(raw), credential)
                self.assertEqual(result.status, OutcomeStatus.FAILURE, result.detail)
                method, url, headers, body = client.calls[1]
                pairs = parse_qs(body.decode(), keep_blank_values=True)
                self.assertEqual(pairs["USER_LOGIN"], [credential.username])
                self.assertEqual(pairs["USER_PASSWORD"], [credential.password])
                self.assertEqual(pairs["extra"], ["тест"])
                self.assertEqual(pairs["empty"], [""])
                self.assertEqual(pairs["sessid"], ["fresh-token"])
                self.assertEqual(headers["X-Requested-With"], "XMLHttpRequest")
                self.assertEqual(headers["Host"], "127.0.0.1:8080")
                self.assertEqual(headers["Content-Length"], str(len(body)))
                self.assertTrue(body.startswith(b"AUTH_FORM=Y&TYPE=AUTH&USER_LOGIN="))

    def test_literal_target_must_equal_observed_action(self):
        for path, expected_calls in (("/custom/session?lang=ru", 2), ("/another/endpoint", 1)):
            with self.subTest(path=path):
                client = Client(HttpResponse(200, body=FORM), HttpResponse(200, body=FAILURE))
                result = PasswordFormAdapter(client).attempt(self.job(self.raw.replace("{{action}}", path)), Credential("a", "b"))
                self.assertEqual(len(client.calls), expected_calls)
                self.assertEqual(result.status, OutcomeStatus.FAILURE if expected_calls == 2 else OutcomeStatus.UNSUPPORTED)

    def test_old_structured_profile_still_sends_form(self):
        profile = copy.deepcopy(self.profile)
        del profile["request"]["raw"]
        self.assertEqual(validate_profile(profile), profile)
        job = job_for()
        job = replace(job, metadata={**job.metadata, "login_verification": profile})
        client = Client(HttpResponse(200, body=FORM), HttpResponse(200, body=FAILURE))
        self.assertEqual(PasswordFormAdapter(client).attempt(job, Credential("a", "b")).status, OutcomeStatus.FAILURE)
        self.assertEqual(parse_qs(client.calls[1][3].decode())["TYPE"], ["AUTH"])

    def test_invalid_raw_rejected_by_author_and_report_consumer(self):
        mutations = [
            lambda r: r.replace("POST ", "GET "),
            lambda r: r.replace("{{host}}", "outside.test"),
            lambda r: r.replace("{{action}}", "https://outside.test/post"),
            lambda r: r.replace("{{action}}", "//outside.test/post"),
            lambda r: r.replace("{{login}}", "{{unknown}}"),
            lambda r: r.replace("{{password}}", "prefix{{password}}"),
            lambda r: r.replace("{{password}}", "secret"),
            lambda r: r.replace("&{{form_fields}}", ""),
            lambda r: r + "&{{form_fields}}",
            lambda r: r.replace("AUTH_FORM=Y", "AUTH_FORM=Y&AUTH_FORM=Y"),
            lambda r: r.replace("AUTH_FORM=Y", "AUTH_FORM=%GG"),
            lambda r: r.replace("TYPE=AUTH", "TYPE=AUTH&other={{password}}"),
            lambda r: r.replace("TYPE=AUTH", "TYPE=AUTH&sessid=old-token"),
            lambda r: r.replace("USER_LOGIN=", "{{bad}}="),
            lambda r: r.replace("\n\n", "\n"),
            lambda r: r.replace("Content-Type:", "Cookie: sid=fixed\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "Content-Length: 123\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "Transfer-Encoding: chunked\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "Authorization: Bearer fixed\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "User-Agent: ignored\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "X-Secret: {{password}}\nContent-Type:"),
            lambda r: r.replace("Content-Type:", "Host: {{host}}\nContent-Type:"),
            lambda r: r.replace("application/x-www-form-urlencoded", "application/json"),
            lambda r: r.replace("Referer: {{page_url}}", "Referer: https://fixed.test/"),
            lambda r: r.replace("Referer: {{page_url}}", "Origin: https://fixed.test/\nReferer: {{page_url}}"),
            lambda r: r.replace("AUTH_FORM=Y", "AUTH_FORM=%00"),
            lambda r: r.replace("\nHost:", "\rHost:"),
            lambda r: r + "\nsecond-body-line",
            lambda r: 123,
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                value = self.with_raw(mutate(self.raw))
                with self.assertRaises(ValueError):
                    validate_verification(value, "test.yaml")
                with self.assertRaises(ValueError):
                    validate_profile(value)

    def test_report_cannot_bind_credentials_to_other_fields(self):
        report = report_for().to_dict()
        report["findings"][0]["metadata"]["login_verification"] = self.with_raw(self.raw.replace("USER_LOGIN=", "another_login="))
        with self.assertRaises(ReportValidationError):
            parse_report(report)

    def test_crlf_http_capture_supported(self):
        value = self.with_raw(self.raw.replace("\n", "\r\n"))
        self.assertEqual(validate_profile(value), validate_verification(value, "test.yaml"))
