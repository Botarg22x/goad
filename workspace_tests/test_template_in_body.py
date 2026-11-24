"""Literal response-body matchers in both product-template modules."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from authpoints.login_templates import load_login_templates, match_page_template
from authpoints.models import WebObservation
from authpoints.page_detection import PageProbe, validate_detection
from authpoints.parsers.katana_jsonl import parse_katana_jsonl
from authpoints.template_verification import validate_verification
from authchecker.models import OutcomeStatus
from authchecker.template_profile import browser_signals, html_signals, profile_outcome, validate_profile


URL = "https://example.test/bitrix/admin/"


def _rule(fragment: str) -> dict:
    return {"status_codes": [200], "match": {"in_body": fragment}}


def test_page_probe_matches_literal_markup_not_visible_text():
    body = '<div hidden data-login-product="test">Other text</div>'
    probe = PageProbe(body)
    assert probe.matches(validate_detection(_rule('data-login-product="test"')), URL, 200)
    assert not probe.matches(validate_detection(_rule('data-login-product="TEST"')), URL, 200)
    assert not probe.matches(validate_detection(_rule('data-login-product="test"')), URL, 403)


def test_katana_body_reaches_template_matcher():
    body = '<html><body><span data-product="sample">Login</span></body></html>'
    data = json.dumps({"request": {"endpoint": URL}, "response": {
        "status_code": 200, "headers": {"content-type": "text/html"}, "body": body,
    }})
    observations, errors = parse_katana_jsonl(data)
    assert not errors
    assert observations[0].body == body
    template = next(t for t in load_login_templates() if t.id == "bitrix")
    custom = replace(template, detection=_rule('data-product="sample"'))
    with patch("authpoints.login_templates.load_login_templates", return_value=(custom,)):
        assert match_page_template(observations[0]).template.id == "bitrix"
        assert match_page_template(replace(observations[0], body="")) is None


def test_in_body_result_survives_module_boundary_and_preflight():
    template = next(t for t in load_login_templates() if t.id == "bitrix")
    profile = deepcopy(template.verification)
    profile["result"]["success_any"] = [{"in_body": '"authenticated":true'}]
    profile["result"]["failure_any"] = [{"in_body": '"result":"error"'}]
    profile = validate_profile(validate_verification(profile, "sample"))
    assert profile_outcome(profile, html_signals('{"authenticated":true}'), URL, submitted=False).status == OutcomeStatus.AMBIGUOUS
    assert profile_outcome(profile, html_signals('{"authenticated":true}'), URL, submitted=True).status == OutcomeStatus.SUCCESS
    assert profile_outcome(profile, html_signals('{"result":"error"}'), URL, submitted=True).status == OutcomeStatus.FAILURE
    assert profile_outcome(profile, html_signals('{"result":"ERROR"}'), URL, submitted=True) is None


def test_browser_signals_include_rendered_dom_for_in_body():
    class Page:
        def evaluate(self, script):
            assert "document.documentElement?.outerHTML" in script
            return {"text": "", "body": '<div data-login-state="failed" hidden></div>',
                    "inputs": [], "links": [], "password": False, "forms": []}

    signals = browser_signals(Page())
    assert signals.matches([{"in_body": 'data-login-state="failed"'}], URL)
    assert not signals.matches([{"in_body": 'data-login-state="FAILED"'}], URL)


@pytest.mark.parametrize("fragment", ["", "a\nb", "x" * 4097])
def test_invalid_in_body_values_are_rejected(fragment):
    with pytest.raises(ValueError):
        validate_detection(_rule(fragment))
    profile = deepcopy(next(t for t in load_login_templates() if t.id == "bitrix").verification)
    profile["result"]["failure_any"] = [{"in_body": fragment}]
    with pytest.raises(ValueError):
        validate_verification(profile, "sample")
    with pytest.raises(ValueError):
        validate_profile(profile)


def test_page_detection_module_copies_remain_identical():
    root = Path(__file__).resolve().parents[1]
    assert (root / "discovery_module_3/src/authpoints/page_detection.py").read_bytes() == (
        root / "check_module_4/src/authchecker/page_detection.py").read_bytes()
