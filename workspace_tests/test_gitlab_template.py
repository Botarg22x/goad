"""Offline GitLab template regression: discovery, request binding and outcomes."""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "discovery_module_3" / "src", ROOT / "check_module_4" / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from authpoints.classifier import classify_web
from authpoints.login_templates import load_login_templates
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter, TargetScope
from authchecker.importer import parse_report
from authchecker.jobs import build_jobs
from authchecker.models import Credential, OutcomeStatus


URL = "https://gitlab.example.test/users/sign_in"
SCOPE = TargetScope.from_domain("gitlab.example.test")
PAGE = '''<html><title>Sign in · GitLab</title>
<div id="js-sign-in-form"><form method="post" action="/users/sign_in">
<input type="hidden" name="authenticity_token" value="fresh-token">
<input type="hidden" name="user[login]" value="">
<input type="hidden" name="user[password]" value="">
</form></div></html>'''


def _findings(body=PAGE, url=URL):
    title, text, forms, links = parse_html(body, url)
    return classify_web(WebObservation(url=url, source="http_probe", status_code=200,
                                       title=title, text=text, body=body, forms=forms, links=links))


def _job():
    report = Report(scope=["gitlab.example.test"], findings=_findings())
    report.finish()
    return build_jobs(parse_report(report.to_dict()))[0]


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers or {}, body))
        return self.responses.pop(0)


def test_gitlab_hidden_js_fields_are_detected_and_bound_to_template():
    findings = _findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.metadata["login_template"] == "gitlab"
    assert finding.metadata["credential_fields"] == {
        "username": "user[login]", "password": "user[password]",
    }
    assert finding.metadata["detection_mode"] == "page_template"
    assert finding.metadata["form_action"] == URL
    assert finding.metadata["login_verification"]["request"]["csrf_fields"] == ["authenticity_token"]
    assert finding.metadata["login_verification"]["request"]["action"] == "fixed"


def test_gitlab_detection_does_not_depend_on_input_attribute_order():
    body = PAGE.replace('name="user[login]" value=""',
                        'value="" name="user[login]" id="user_login"')
    body = body.replace('name="user[password]" value=""',
                        'value="" name="user[password]" id="user_password"')
    findings = _findings(body)
    assert len(findings) == 1
    assert findings[0].metadata["login_template"] == "gitlab"


def test_gitlab_post_destination_is_explicit_even_with_page_query():
    findings = _findings(url=URL + "?redirect_to=%2Fdashboard")
    assert len(findings) == 1
    assert findings[0].metadata["form_action"] == URL


def test_gitlab_template_requires_fields_and_sign_in_path():
    for body, url in (
        (PAGE.replace('name="user[password]"', 'name="not_password"'), URL),
        (PAGE, "https://gitlab.example.test/users/sign_up"),
        ('<html><title>GitLab</title><p>Sign in</p></html>', URL),
    ):
        assert not any(f.metadata.get("login_template") == "gitlab" for f in _findings(body, url))


def test_gitlab_template_refreshes_csrf_and_posts_exact_fields():
    client = Client(HttpResponse(200, body=PAGE, set_cookie_headers=("sid=new; Path=/",)),
                    HttpResponse(200, body="Invalid login or password"))
    outcome = PasswordFormAdapter(client, SCOPE).attempt(_job(), Credential("student", "wrong"))
    assert outcome.status == OutcomeStatus.FAILURE
    assert [call[0] for call in client.calls] == ["GET", "POST"]
    assert client.calls[1][1] == URL
    assert parse_qs(client.calls[1][3].decode()) == {
        "user[login]": ["student"], "user[password]": ["wrong"],
        "authenticity_token": ["fresh-token"],
        "user[remember_me]": ["0"],
    }
    assert "sid=new" in client.calls[1][2]["Cookie"]


def test_gitlab_template_does_not_guess_success_from_http_200():
    for body, expected in (
        ("<div>Unknown response</div>", OutcomeStatus.AMBIGUOUS),
        ('<script>gon.current_user_id=42;</script>', OutcomeStatus.AMBIGUOUS),
        # The configured GitLab rule requires POST 302; a 200 response is not
        # promoted to success merely because a sign-out link appears in HTML.
        ('<a href="/users/sign_out">Sign out</a>', OutcomeStatus.AMBIGUOUS),
        ('<input name="user[otp_attempt]">', OutcomeStatus.MFA_REQUIRED),
        ("There was an error with the reCAPTCHA", OutcomeStatus.UNSUPPORTED),
    ):
        client = Client(HttpResponse(200, body=PAGE), HttpResponse(200, body=body))
        outcome = PasswordFormAdapter(client, SCOPE).attempt(_job(), Credential("student", "secret"))
        assert outcome.status == expected
        assert len([call for call in client.calls if call[0] == "POST"]) == 1


def test_gitlab_template_accepts_declared_302_after_following_same_origin_redirect():
    client = Client(HttpResponse(200, body=PAGE),
                    HttpResponse(302, headers={"location": "/dashboard"}),
                    HttpResponse(200, body="<main>Dashboard</main>"))
    outcome = PasswordFormAdapter(client, SCOPE).attempt(_job(), Credential("student", "secret"))
    assert outcome.status == OutcomeStatus.SUCCESS
    assert [call[0] for call in client.calls] == ["GET", "POST", "GET"]
    assert client.calls[-1][1] == "https://gitlab.example.test/dashboard"


def test_gitlab_template_is_loaded_and_selected_by_product_id():
    template = next(t for t in load_login_templates() if t.id == "gitlab")
    assert template.paths == ("/users/sign_in",)
    assert template.verification["request"]["action"] == "fixed"
