"""Validate the portable, declarative module-4 contract before discovery."""
from __future__ import annotations

from copy import deepcopy

from .template_request import normalize_request, parse_raw_request
from .page_detection import validate_detection


RESULT_GROUPS = {"success_any", "failure_any", "captcha_any", "mfa_any", "csrf_error_any"}


def validate_verification(value: object, label: str) -> dict:
    def fail(message: str) -> None:
        raise ValueError(f"{label}: verification: {message}")

    if not isinstance(value, dict) or set(value) - {"detection"} != {"schema", "transport", "request", "result"}:
        fail("нужны schema, transport, request и result")
    if value["schema"] != "form-check/1" or value["transport"] not in ("http", "auto"):
        fail("schema: form-check/1; transport: http или auto")
    value = deepcopy(value)
    if "detection" in value:
        try:
            validate_detection(value["detection"])
        except ValueError as exc:
            fail(str(exc))
    try:
        request = value["request"] = normalize_request(value["request"])
    except ValueError as exc:
        fail(str(exc))
    expected = {"method": "POST", "action": "form", "encoding": "form", "session": "fresh"}
    if request.get("action") in {"page", "fixed"}:
        expected["action"] = request["action"]
        if "detection" not in value or "raw" not in request:
            fail("action: page/fixed требует detection и raw-запрос")
    if set(request) - {"raw"} != set(expected) | {"defaults", "csrf_fields"}:
        fail("request: нужны method, action, encoding, session, defaults, csrf_fields")
    if any(request[key] != setting for key, setting in expected.items()):
        fail("поддерживается POST текущей формы, encoding: form, session: fresh")
    defaults, csrf = request["defaults"], request["csrf_fields"]
    if not isinstance(defaults, dict) or not all(_string(k) and (v == "" or _string(v)) for k, v in defaults.items()):
        fail("defaults: имена и значения должны быть непустыми строками")
    if not isinstance(csrf, list) or not all(_string(name) for name in csrf) or len(csrf) != len(set(csrf)):
        fail("csrf_fields: список уникальных имён полей")
    if set(defaults) & set(csrf):
        fail("CSRF-токены нельзя задавать константами в defaults")
    if "raw" in request:
        recipe = parse_raw_request(request["raw"])
        if {recipe.username_field, recipe.password_field} & set(csrf):
            fail("поля учётных данных нельзя задавать как CSRF")
    result = value["result"]
    status_keys = {"success_status", "failure_status"}
    if not isinstance(result, dict) or not RESULT_GROUPS <= set(result) or set(result) - RESULT_GROUPS - status_keys:
        fail("result: нужны success_any, failure_any, captcha_any, mfa_any, csrf_error_any")
    for key in status_keys & set(result):
        if type(result[key]) is not int or not 200 <= result[key] <= 599:
            fail(f"{key}: нужен HTTP-код ответа POST от 200 до 599")
    for group in RESULT_GROUPS:
        rules = result[group]
        if not isinstance(rules, list):
            fail(f"{group}: нужен список правил")
        for rule in rules:
            if not isinstance(rule, dict) or len(rule) != 1:
                fail(f"{group}: в правиле должен быть ровно один ключ")
            key, item = next(iter(rule.items()))
            if key in {"text_contains", "input_name", "in_body"}:
                valid = (_body_string(item) if key == "in_body" else _string(item))
                valid = valid and (key != "input_name" or group in {"captcha_any", "mfa_any"})
            elif key in {"link_query", "form_fields"}:
                valid = isinstance(item, dict) and bool(item) and all(_string(k) and _string(v) for k, v in item.items())
            else:
                valid = False
            if not valid:
                fail(f"{group}: неверный признак {key}")
    if not (result["success_any"] or result["failure_any"] or status_keys & set(result)):
        fail("result: нужен хотя бы один признак результата или HTTP-код ответа")
    return deepcopy(value)


def _string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512 and not any(ord(c) < 32 for c in value)


def _body_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096 and not any(ord(c) < 32 for c in value)
