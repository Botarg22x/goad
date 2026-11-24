"""HTTP/Chromium integration against a loopback-only Bitrix-shaped fixture."""
from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from test_bitrix_template import FORM, SUCCESS, SUCCESS_FORM, FAILURE, job_for, report_for
from authchecker.adapters.http import PasswordFormAdapter, ProxyHttpClient
from authchecker.browser import BrowserCheckConfig, BrowserRequestSnapshot
from authchecker.browser_adapter import BrowserAdapter, TemplateFormAdapter
from authchecker.cli import main as check
from authchecker.http_replay import HttpReplayTemplate, run_http_replay
from authchecker.models import Credential, OutcomeStatus


def form_for(case, token):
    return FORM.replace('/custom/session?lang=ru', '/submit?case=' + case).replace('fresh-token', token)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, body, status=200, **headers):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in headers.items():
            self.send_header(key.replace('_', '-'), value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlsplit(self.path)
        case = parse_qs(parsed.query).get("case", ["success"])[0]
        if parsed.path == "/result":
            bodies = {"success": SUCCESS, "success-form": SUCCESS_FORM, "js": SUCCESS, "failure": FAILURE,
                      "mfa": '<input name="USER_OTP">', "captcha": '<input name="captcha_word">',
                      "unknown": '<p>Обработка завершена</p>'}
            self.send(bodies[case])
            return
        if parsed.path != "/bitrix/admin/":
            self.send("not found", 404)
            return
        self.server.tokens += 1
        token = "token-" + str(self.server.tokens)
        body = form_for(case, token)
        if case == "js":
            body = '<title>Битрикс</title><body><script>document.body.innerHTML=' + json.dumps(body) + '</script></body>'
        if case == "pre-captcha":
            body += '<input name="captcha_word">'
        self.send(body, Set_Cookie=f"sid={token}; Path=/")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        data = parse_qs(body)
        self.server.posts.append(data)
        self.server.raw_posts.append((body, {key.lower(): value for key, value in self.headers.items()}))
        case = parse_qs(urlsplit(self.path).query).get("case", [None])[0]
        if case is None:
            case = parse_qs(urlsplit(self.headers.get("Referer", "")).query).get("case", ["success"])[0]
        token = data.get("sessid", [""])[0]
        correct = (data.get("AUTH_FORM") == ["Y"] and data.get("TYPE") == ["AUTH"]
                   and data.get("USER_LOGIN") == ["student"] and data.get("USER_PASSWORD") == ["test-password"]
                   and token.startswith("token-") and f"sid={token}" in self.headers.get("Cookie", ""))
        if not correct:
            self.send("Your session has expired", 400)
            return
        self.send("", 303, Location="/result?case=" + case)


class BitrixLocalFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.tokens = 0
        cls.server.posts = []
        cls.server.raw_posts = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.posts.clear()
        self.server.raw_posts.clear()

    def job(self, case):
        url = self.base + "/bitrix/admin/?case=" + case
        return job_for(form_for(case, "report-token-not-used"), url)

    def test_standalone_cli_consumes_report_and_limits_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            url = self.base + "/bitrix/admin/?case=failure"
            report = root / "report.json"
            report.write_text(json.dumps(report_for(form_for("failure", "old"), url).to_dict()), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = check(["run", "--live", "--report", str(report), "--login", "student",
                              "--password", "test-password", "--max-total", "1", "--audit", str(root / "audit.jsonl")])
            self.assertEqual(code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["outcomes"], {"failure": 1})
            self.assertEqual(result["attempted_count"], 1)
            self.assertEqual(len(self.server.posts), 1)

    def test_real_browser_uses_template_rules_for_success_rejection_and_protection(self):
        for case, expected in (("success", OutcomeStatus.SUCCESS), ("success-form", OutcomeStatus.SUCCESS), ("failure", OutcomeStatus.FAILURE),
                               ("mfa", OutcomeStatus.MFA_REQUIRED), ("captcha", OutcomeStatus.UNSUPPORTED)):
            with self.subTest(case=case):
                before = len(self.server.posts)
                adapter = BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5, stop_on_challenge=True))
                result = adapter.attempt(self.job(case), Credential("student", "test-password"))
                self.assertEqual(result.status, expected, result.detail)
                self.assertEqual(len(self.server.posts) - before, 1)

    def test_preflight_captcha_sends_no_post_or_browser_fallback(self):
        adapter = TemplateFormAdapter(ProxyHttpClient(), None, BrowserCheckConfig(headless=True, timeout_seconds=5))
        result = adapter.attempt(self.job("pre-captcha"), Credential("student", "test-password"))
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)
        self.assertEqual(result.evidence["reason"], "challenge")
        self.assertEqual(self.server.posts, [])

    def test_auto_fallback_for_js_form_submits_once(self):
        adapter = TemplateFormAdapter(ProxyHttpClient(), None, BrowserCheckConfig(headless=True, timeout_seconds=5))
        result = adapter.attempt(self.job("js"), Credential("student", "test-password"))
        self.assertEqual(result.status, OutcomeStatus.SUCCESS, result.detail)
        self.assertEqual(len(self.server.posts), 1)

    def test_browser_http_refreshes_bitrix_sessid_and_uses_result_rules(self):
        for case, expected in (("success", OutcomeStatus.SUCCESS), ("success-form", OutcomeStatus.SUCCESS), ("failure", OutcomeStatus.FAILURE),
                               ("mfa", OutcomeStatus.MFA_REQUIRED), ("captcha", OutcomeStatus.UNSUPPORTED),
                               ("unknown", OutcomeStatus.AMBIGUOUS)):
            with self.subTest(case=case):
                job = self.job(case)
                credential = Credential("student", "test-password")
                snapshot = BrowserRequestSnapshot(
                    method="POST", url=job.form_action,
                    headers={"content-type": "application/x-www-form-urlencoded"},
                    body="USER_LOGIN=student&USER_PASSWORD=test-password&AUTH_FORM=Y&TYPE=AUTH&sessid=old-token",
                    cookies=(), page_html=form_for(case, "old-token"), page_url=job.endpoint,
                    username_field="USER_LOGIN", password_field="USER_PASSWORD",
                )
                template = HttpReplayTemplate.from_capture(snapshot, credential)
                before = len(self.server.posts)
                result = run_http_replay(template, credential, config=BrowserCheckConfig(
                    headless=True, verification_json=json.dumps(job.metadata["login_verification"])))
                self.assertEqual(result.outcome.status, expected, result.outcome.detail)
                self.assertEqual(len(self.server.posts) - before, 1)
                self.assertNotEqual(self.server.posts[-1]["sessid"], ["old-token"])

    def raw_job(self, case="success", target="{{action}}"):
        job = self.job(case)
        profile = json.loads(json.dumps(job.metadata["login_verification"]))
        raw = profile["request"]["raw"].replace("{{action}}", target)
        raw = raw.replace("Referer:", "X-Template-Test: raw-recipe\nReferer:")
        raw = raw.replace("&{{form_fields}}", "&source=edited-yaml&{{form_fields}}")
        profile["request"] = {"raw": raw, "session": "fresh", "csrf_fields": ["sessid"]}
        return replace(job, metadata={**job.metadata, "login_verification": profile})

    def test_http_and_browser_send_edited_raw_request_with_live_session(self):
        adapters = [PasswordFormAdapter(ProxyHttpClient()),
                    BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5))]
        for adapter in adapters:
            with self.subTest(adapter=type(adapter).__name__):
                before = len(self.server.posts)
                result = adapter.attempt(self.raw_job(), Credential("student", "test-password"))
                self.assertEqual(result.status, OutcomeStatus.SUCCESS, result.detail)
                self.assertEqual(len(self.server.posts) - before, 1)
                self.assertEqual(self.server.posts[-1]["source"], ["edited-yaml"])
                body, headers = self.server.raw_posts[-1]
                self.assertTrue(body.startswith("AUTH_FORM=Y&TYPE=AUTH&USER_LOGIN=student&USER_PASSWORD=test-password&source=edited-yaml&"))
                self.assertEqual(headers["x-template-test"], "raw-recipe")

    def test_browser_rejects_mismatched_literal_target_without_post(self):
        adapter = BrowserAdapter(BrowserCheckConfig(headless=True, timeout_seconds=5))
        result = adapter.attempt(self.raw_job(target="/other"), Credential("student", "test-password"))
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED, result.detail)
        self.assertEqual(result.evidence["reason"], "template_request")
        self.assertEqual(self.server.posts, [])

    def test_http_replay_honors_edited_raw_recipe_not_stale_capture(self):
        job = self.raw_job()
        credential = Credential("student", "test-password")
        snapshot = BrowserRequestSnapshot(
            method="POST", url=job.form_action,
            headers={"content-type": "application/x-www-form-urlencoded"},
            body="USER_LOGIN=student&USER_PASSWORD=test-password&AUTH_FORM=Y&TYPE=AUTH&sessid=old",
            cookies=(), page_html=form_for("success", "old"), page_url=job.endpoint,
            username_field="USER_LOGIN", password_field="USER_PASSWORD",
        )
        result = run_http_replay(HttpReplayTemplate.from_capture(snapshot, credential), credential,
                                config=BrowserCheckConfig(verification_json=json.dumps(job.metadata["login_verification"])))
        self.assertEqual(result.outcome.status, OutcomeStatus.SUCCESS, result.outcome.detail)
        self.assertEqual(len(self.server.posts), 1)
        self.assertEqual(self.server.posts[-1]["source"], ["edited-yaml"])
        self.assertEqual(self.server.raw_posts[-1][1]["x-template-test"], "raw-recipe")
