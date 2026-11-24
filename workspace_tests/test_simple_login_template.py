"""The legacy short YAML format remains compatible with the 3→4 contract."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

import pytest

from authpoints.classifier import classify_web
from authpoints.login_templates import _validate_template
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authchecker.adapters.http import HttpResponse, PasswordFormAdapter
from authchecker.importer import parse_report
from authchecker.jobs import build_jobs
from authchecker.models import Credential, OutcomeStatus


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "discovery_module_3/src/authpoints/data/login_templates/PRODUCT_TEMPLATE.yaml.example"
SHORT_TEMPLATE = {
    "id": "myproduct",
    "paths": ["/login/"],
    "in_body": 'data-product="myproduct"',
    "post": "username={{login}}&password={{password}}",
    "success": 'data-authenticated="true"',
    "failure": "Неверный логин или пароль",
}
URL = "http://127.0.0.1:8080/login/"
FORM = ('<html><div data-product="myproduct"></div><form method="post" action="/session">'
        '<input name="username"><input name="password" type="password">'
        '<input type="hidden" name="csrf_token" value="fresh-token"></form></html>')
PAGE = ('<html><div data-product="myproduct"></div>'
        '<input type="hidden" name="csrf_token" value="fresh-token"></html>')


def _template(**changes):
    item = dict(SHORT_TEMPLATE)
    item.update(changes)
    return _validate_template(item, str(EXAMPLE))


def _job(body, template):
    title, text, forms, links = parse_html(body, URL)
    observation = WebObservation(url=URL, source="http_probe", status_code=200,
                                 title=title, text=text, body=body, forms=forms, links=links)
    with patch("authpoints.login_templates.load_login_templates", return_value=(template,)):
        findings = classify_web(observation)
    assert len(findings) == 1
    assert findings[0].metadata["login_template"] == "myproduct"
    report = Report(scope=["127.0.0.1"], findings=findings)
    report.finish()
    return build_jobs(parse_report(report.to_dict()))[0]


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        return self.responses.pop(0)


def test_short_template_posts_to_discovered_form_and_checks_literal_result():
    template = _template()
    job = _job(FORM, template)
    client = Client(HttpResponse(200, body=FORM),
                    HttpResponse(200, body='<div data-authenticated="true"></div>'))
    outcome = PasswordFormAdapter(client).attempt(job, Credential("student", "secret"))
    assert outcome.status == OutcomeStatus.SUCCESS, outcome.detail
    assert [call[0] for call in client.calls] == ["GET", "POST"]
    assert client.calls[1][1] == "http://127.0.0.1:8080/session"
    assert parse_qs(client.calls[1][3].decode()) == {
        "username": ["student"], "password": ["secret"], "csrf_token": ["fresh-token"],
    }


def test_short_template_can_post_to_current_page_without_html_form():
    template = _template(post_to="page", path_contains="/login/", csrf_fields=["csrf_token"])
    job = _job(PAGE, template)
    client = Client(HttpResponse(200, body=PAGE),
                    HttpResponse(200, body="Неверный логин или пароль"))
    outcome = PasswordFormAdapter(client).attempt(job, Credential("student", "wrong"))
    assert outcome.status == OutcomeStatus.FAILURE, outcome.detail
    assert [call[0] for call in client.calls] == ["GET", "POST"]
    assert client.calls[1][1] == URL
    assert parse_qs(client.calls[1][3].decode())["csrf_token"] == ["fresh-token"]


def test_short_template_rejects_typos_and_ambiguous_post():
    for changes, message in [
        ({"post_to": ["page"]}, "post_to"),
        ({"post": "username={{login}}"}, "post"),
        ({"post": "username={{login}}&password={{password}}&{{form_fields}}"}, "form_fields"),
        ({"path_contains": "/login/"}, "path_contains"),
        ({"success": ""}, "success"),
        ({"unrecognized": True}, "неизвестные поля"),
    ]:
        with pytest.raises(ValueError, match=message):
            _template(**changes)


def test_short_template_accepts_multiple_result_markers():
    template = _template(failure=["Неверный логин или пароль", "Invalid credentials"])
    assert template.verification["result"]["failure_any"] == [
        {"in_body": "Неверный логин или пароль"}, {"in_body": "Invalid credentials"},
    ]
