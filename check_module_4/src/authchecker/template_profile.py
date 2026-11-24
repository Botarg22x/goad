"""Portable form-check/1 rules. No dependency on PointFinder or YAML at runtime."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from .form_fields import template_credential_fields
from .models import AuthJob, Outcome, OutcomeStatus
from .template_request import normalize_request, parse_raw_request
from .page_detection import validate_detection, PageProbe


GROUPS = {"success_any", "failure_any", "captcha_any", "mfa_any", "csrf_error_any"}


def validate_profile(value: object) -> dict:
    """Revalidate untrusted report data; never execute code from a template."""
    def require(condition, message):
        if not condition:
            raise ValueError("login_verification: " + message)

    def string(item):
        return isinstance(item, str) and bool(item.strip()) and len(item) <= 512 and not any(ord(c) < 32 for c in item)

    def body_string(item):
        return isinstance(item, str) and bool(item.strip()) and len(item) <= 4096 and not any(ord(c) < 32 for c in item)

    require(isinstance(value, dict) and set(value) - {"detection"} == {"schema", "transport", "request", "result"}, "неверная структура")
    require(value["schema"] == "form-check/1", "неподдерживаемая версия")
    require(value["transport"] in ("http", "auto"), "неверный transport")
    if "detection" in value:
        validate_detection(value["detection"])
    try:
        request = normalize_request(value["request"])
    except ValueError as exc:
        raise ValueError("login_verification: " + str(exc)) from exc
    value = {**value, "request": request}
    expected = {"method": "POST", "action": "form", "encoding": "form", "session": "fresh"}
    if request.get("action") in {"page", "fixed"}:
        expected["action"] = request["action"]
        require("detection" in value and "raw" in request, "action: page/fixed требует detection и raw")
    require(set(request) - {"raw"} == set(expected) | {"defaults", "csrf_fields"}, "неверный request")
    require(all(request[k] == v for k, v in expected.items()), "нужен POST текущей формы в свежей сессии")
    defaults, csrf = request["defaults"], request["csrf_fields"]
    require(isinstance(defaults, dict) and all(string(k) and (v == "" or string(v)) for k, v in defaults.items()), "неверные defaults")
    require(isinstance(csrf, list) and all(string(k) for k in csrf), "неверные csrf_fields")
    require(len(csrf) == len(set(csrf)) and not set(defaults) & set(csrf), "CSRF нельзя задавать константой")
    if "raw" in request:
        recipe = parse_raw_request(request["raw"])
        require(not {recipe.username_field, recipe.password_field} & set(csrf), "учётные данные нельзя задавать как CSRF")
    groups = value["result"]
    status_keys = {"success_status", "failure_status"}
    require(isinstance(groups, dict) and GROUPS <= set(groups) and not set(groups) - GROUPS - status_keys, "неверный result")
    for key in status_keys & set(groups):
        require(type(groups[key]) is int and 200 <= groups[key] <= 599, f"{key}: нужен HTTP-код ответа POST")
    for group in GROUPS:
        rules = groups[group]
        require(isinstance(rules, list), "нужны списки признаков")
        for rule in rules:
            require(isinstance(rule, dict) and len(rule) == 1, "неверный признак")
            kind, item = next(iter(rule.items()))
            if kind in {"link_query", "form_fields"}:
                require(isinstance(item, dict) and bool(item) and all(string(k) and string(v) for k, v in item.items()), "неверный link_query/form_fields")
            else:
                require(kind in {"text_contains", "in_body"} or (kind == "input_name" and group in {"captcha_any", "mfa_any"}), "неизвестный признак")
                require(body_string(item) if kind == "in_body" else string(item), "пустой или некорректный признак")
    require(bool(groups["success_any"] or groups["failure_any"] or status_keys & set(groups)),
            "нужен хотя бы один признак результата или HTTP-код ответа")
    return value


def profile_from_metadata(metadata: Mapping) -> dict | None:
    if "login_verification" not in metadata:
        return None
    profile = validate_profile(metadata["login_verification"])
    username, password = template_credential_fields(metadata)
    if not username or not password:
        raise ValueError("login_verification: нет однозначной привязки логина и пароля к запросу")
    request = profile["request"]
    if {username, password} & (set(request["defaults"]) | set(request["csrf_fields"])):
        raise ValueError("login_verification: учётные данные нельзя подменять defaults/CSRF")
    if "raw" in request:
        recipe = parse_raw_request(request["raw"])
        if (recipe.username_field, recipe.password_field) != (username, password):
            raise ValueError("login_verification: поля HTTP-запроса не совпадают с найденной формой")
    return profile


def profile_from_json(value: str) -> dict | None:
    return validate_profile(json.loads(value)) if value else None


def apply_defaults(profile: dict, fields: list[tuple[str, str]]) -> list[tuple[str, str]]:
    result = list(fields)
    for name, value in profile["request"]["defaults"].items():
        actual = [item for key, item in result if key == name]
        if actual and actual != [value]:
            raise ValueError(f"Поле {name} не соответствует шаблону; пароль не отправлялся")
        if not actual:
            result.append((name, value))
    return result


def page_request_fields(profile: dict, body: str, url: str, status: int,
                        required_csrf: set[str]) -> list[tuple[str, str]]:
    """Only declared dynamic tokens come from HTML; constants come from raw."""
    page = PageProbe(body)
    if not page.matches(profile["detection"], url, status):
        raise ValueError("Страница больше не соответствует признакам шаблона; пароль не отправлялся")
    fields = []
    for name in profile["request"]["csrf_fields"]:
        values = {value for key, _, value in page.inputs if key == name}
        if len(values) > 1 or "" in values or (name in required_csrf and not values):
            raise ValueError("Не удалось однозначно обновить CSRF-токен шаблона; пароль не отправлялся")
        if values:
            fields.append((name, next(iter(values))))
    return fields


def page_template_job(url: str, profile: dict, required_csrf: tuple[str, ...] = ()) -> AuthJob:
    recipe = parse_raw_request(profile["request"]["raw"])
    parts = urlsplit(url)
    action = urljoin(url, recipe.target) if profile["request"]["action"] == "fixed" else url
    return AuthJob(job_key="template-page", report_run_id="", finding_id="", kind="web_login_page",
                   auth_type="password_form", endpoint=url, host=parts.hostname or "",
                   port=parts.port or (443 if parts.scheme == "https" else 80), protocol=parts.scheme,
                   form_action=action, metadata={"login_template": "page-template", "login_verification": profile,
                       "credential_fields": {"username": recipe.username_field, "password": recipe.password_field},
                       "fields": [{"name": name, "type": "hidden"} for name in required_csrf]})


def render_raw_request(profile: dict, *, action: str, page_url: str,
                       fields: list[tuple[str, str]], username_field: str,
                       password_field: str, login: str, password: str) -> tuple[dict[str, str], bytes]:
    """Build a fresh form POST, encoding values rather than substituting bytes."""
    recipe = parse_raw_request(profile["request"]["raw"])
    if (recipe.username_field, recipe.password_field) != (username_field, password_field):
        raise ValueError("Поля HTTP-шаблона не совпадают с формой; пароль не отправлялся")
    parts = urlsplit(action)
    target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if recipe.target != "{{action}}" and recipe.target != target:
        raise ValueError("Адрес HTTP-шаблона не совпадает с action формы; пароль не отправлялся")
    if not _same_origin_url(action, page_url):
        raise ValueError("HTTP-шаблон не может отправлять данные на другой origin")
    fields = apply_defaults(profile, fields)
    explicit = {pair[0] for pair in recipe.fields if pair is not None}
    values = {"{{login}}": login, "{{password}}": password}
    output = []
    for pair in recipe.fields:
        if pair is None:
            output.extend((name, value) for name, value in fields if name not in explicit)
        else:
            name, value = pair
            output.append((name, values.get(value, value)))
    substitutions = {"{{host}}": parts.netloc, "{{page_url}}": page_url,
                     "{{origin}}": f"{parts.scheme}://{parts.netloc}"}
    headers = {name.title(): substitutions.get(value, value) for name, value in recipe.headers}
    return headers, urlencode(output).encode("utf-8")


@dataclass
class PageSignals:
    text: str = ""
    inputs: set[str] = field(default_factory=set)
    links: list[str] = field(default_factory=list)
    password: bool = False
    forms: list[dict] = field(default_factory=list)
    body: str = ""

    def matches(self, rules: list[dict], url: str) -> bool:
        text = " ".join(self.text.split()).casefold()
        for rule in rules:
            if "text_contains" in rule and " ".join(rule["text_contains"].split()).casefold() in text:
                return True
            if "in_body" in rule and rule["in_body"] in self.body:
                return True
            if "input_name" in rule and rule["input_name"] in self.inputs:
                return True
            if "form_fields" in rule:
                for form in self.forms:
                    if (form["submit"] and _same_origin_url(form["action"] or url, url)
                            and all(form["fields"].get(k) == [v] for k, v in rule["form_fields"].items())):
                        return True
            if "link_query" in rule:
                for href in self.links:
                    try:
                        target = urlsplit(urljoin(url, href))
                        if not _same_origin_url(href, url):
                            continue
                        query = parse_qs(target.query, keep_blank_values=True)
                        if all(query.get(k) == [v] for k, v in rule["link_query"].items()):
                            return True
                    except ValueError:
                        continue
        return False


def _same_origin_url(href: str, url: str) -> bool:
    try:
        target, base = urlsplit(urljoin(url, href)), urlsplit(url)
        def origin(parts):
            return (parts.scheme.lower(), parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
        return target.scheme in {"http", "https"} and not target.username and not target.password and origin(target) == origin(base)
    except ValueError:
        return False


def profile_outcome(profile: dict | None, signals: PageSignals, url: str, *, status: int = 200,
                    post_status: int | None = None, submitted: bool) -> Outcome | None:
    if profile is None:
        return None
    groups = profile["result"]
    evidence = {"attempted": submitted, "http_status": status, "template_rule": ""}
    if post_status is not None:
        evidence["post_status"] = post_status
    for group, outcome, detail, reason in (
        ("captcha_any", OutcomeStatus.UNSUPPORTED, "Шаблон: обнаружена CAPTCHA; проверка остановлена", "challenge"),
        ("csrf_error_any", OutcomeStatus.UNSUPPORTED, "Шаблон: ошибка session/CSRF; результат входа не установлен", "csrf"),
        ("mfa_any", OutcomeStatus.MFA_REQUIRED, "Шаблон: требуется OTP/второй фактор; вход не завершён", "otp"),
    ):
        if signals.matches(groups[group], url):
            return Outcome(outcome, detail, evidence={**evidence, "reason": reason, "template_rule": group})
    success_signal = signals.matches(groups["success_any"], url)
    failure_signal = signals.matches(groups["failure_any"], url)
    if not submitted:
        if success_signal:
            return Outcome(OutcomeStatus.AMBIGUOUS, "Признак успеха уже есть до отправки пароля", evidence={**evidence, "reason": "preexisting_success"})
        return None
    success = ((bool(groups["success_any"]) or "success_status" in groups)
               and (not groups["success_any"] or success_signal)
               and ("success_status" not in groups or post_status == groups["success_status"]))
    failure = ((bool(groups["failure_any"]) or "failure_status" in groups)
               and (not groups["failure_any"] or failure_signal)
               and ("failure_status" not in groups or post_status == groups["failure_status"]))
    if ((success_signal and failure_signal) or (success and failure)
            or (success and failure_signal) or (failure and success_signal)):
        return Outcome(OutcomeStatus.AMBIGUOUS, "Шаблон: противоречивые признаки успеха и отказа", evidence={**evidence, "reason": "conflicting_signals"})
    if failure or (status == 401 and "failure_status" not in groups):
        return Outcome(OutcomeStatus.FAILURE, "Шаблон: сайт отклонил учётные данные", evidence={**evidence, "reason": "login_error", "template_rule": "failure_any" if groups["failure_any"] else "failure_status"})
    if success and 200 <= status < 300 and not signals.password:
        detail = ("Шаблон: совпал код ответа POST; на итоговой странице нет формы пароля"
                  if not groups["success_any"] else "Шаблон: обнаружен явный признак успешного входа")
        return Outcome(OutcomeStatus.SUCCESS, detail, evidence={**evidence, "reason": "authenticated_marker" if groups["success_any"] else "status_and_no_password_form", "template_rule": "success_any" if groups["success_any"] else "success_status"})
    # Do not turn an arbitrary 200/redirect, cookie or remaining form into proof.
    return None


def profile_unconfirmed(profile: dict, *, status: int, post_status: int | None = None) -> Outcome:
    """Report a response outside the declared rejection baseline, never as success."""
    baseline = "failure_status" in profile["result"]
    if baseline:
        actual = f"POST {post_status}" if post_status is not None else "код POST неизвестен"
        expected = profile["result"]["failure_status"]
        marker = " и заданный текст" if profile["result"]["failure_any"] else ""
        detail = (f"Ответ отличается от отказа из шаблона: {actual}, итоговый HTTP {status}; "
                  f"для отказа ожидался POST {expected}{marker}. Успешный вход не подтверждён")
    else:
        detail = "Ответ получен, но признаки результата из шаблона не совпали"
    evidence = {"reason": "template_response_differs" if baseline else "template_unconfirmed",
                "attempted": True, "http_status": status}
    if post_status is not None:
        evidence["post_status"] = post_status
    return Outcome(OutcomeStatus.AMBIGUOUS, detail, evidence=evidence)


class _SignalsParser(HTMLParser):
    def __init__(self, body: str):
        super().__init__(convert_charrefs=True)
        self.signals = PageSignals()
        self.stack: list[tuple[str, bool]] = []
        self.form_stack: list[dict] = []
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        hidden = (bool(self.stack and self.stack[-1][1]) or tag in {"head", "script", "style", "template", "noscript"}
                  or "hidden" in values or values.get("aria-hidden") == "true"
                  or bool(re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", values.get("style") or "", re.I)))
        if tag == "form":
            form = {"action": values.get("action") or "", "fields": {}, "submit": False}
            self.signals.forms.append(form)
            self.form_stack.append(form)
        if self.form_stack and tag in {"input", "button"} and "disabled" not in values:
            form = self.form_stack[-1]
            kind = (values.get("type") or ("submit" if tag == "button" else "text")).lower()
            if values.get("name") and kind not in {"checkbox", "radio", "submit", "button", "reset", "image"}:
                form["fields"].setdefault(values["name"], []).append(values.get("value") or "")
            if not hidden and kind == "submit" and values.get("aria-disabled") != "true":
                # A differing submit override cannot prove this form's action.
                if not values.get("formaction") or values["formaction"] == form["action"]:
                    form["submit"] = True
        if not hidden and "disabled" not in values:
            if tag == "input" and (values.get("type") or "text").lower() != "hidden":
                self.signals.inputs.add(values.get("name") or "")
                self.signals.password |= (values.get("type") or "").lower() == "password"
            if tag == "a" and values.get("href") and values.get("aria-disabled") != "true":
                self.signals.links.append(values["href"])
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, hidden))

    def handle_endtag(self, tag):
        if tag == "form" and self.form_stack:
            self.form_stack.pop()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if not self.stack or not self.stack[-1][1]:
            self.signals.text += data + " "


def html_signals(body: str) -> PageSignals:
    signals = _SignalsParser(body).signals
    signals.body = body
    return signals


def browser_signals(page) -> PageSignals:
    # Use computed visibility in Chromium, not raw HTML/CSS guesses.
    data = page.evaluate("""() => {
      const visible = e => !e.disabled && e.getAttribute('aria-hidden') !== 'true' &&
        !e.closest('[hidden], [aria-hidden="true"]') && e.getClientRects().length > 0 &&
        getComputedStyle(e).visibility !== 'hidden';
      const inputs = [...document.querySelectorAll('input')].filter(visible);
      return {text: document.body?.innerText || '', body: document.documentElement?.outerHTML || '',
        inputs: inputs.map(e => e.name),
        password: inputs.some(e => e.type === 'password'),
        links: [...document.querySelectorAll('a[href]')].filter(visible)
          .filter(e => e.getAttribute('aria-disabled') !== 'true').map(e => e.href),
        forms: [...document.forms].map(form => {
          const fields = {};
          for (const e of form.elements) {
            if (!e.disabled && e.name && e.tagName === 'INPUT' &&
                !['checkbox','radio','submit','button','reset','image'].includes(e.type))
              (fields[e.name] ||= []).push(e.value);
          }
          const submit = [...form.elements].some(e => e.type === 'submit' && visible(e) &&
            e.getAttribute('aria-disabled') !== 'true' &&
            (!e.getAttribute('formaction') || e.formAction === form.action));
          return {action: form.action, fields, submit};
        })};
    }""")
    return PageSignals(data["text"], set(data["inputs"]), data["links"], data["password"],
                       data["forms"], data["body"])


def prepare_browser_form(password, profile: dict, required_csrf: tuple[str, ...] = ()) -> None:
    """Check dynamic tokens and fill only absent constant hidden parameters."""
    error = password.evaluate("""(e, request) => {
      const form = e.form;
      if (!form) return 'Шаблон требует HTML-форму';
      for (const name of request.csrf_fields) {
        const fields = [...form.elements].filter(x => x.name === name && !x.disabled);
        if (fields.length > 1 || fields.some(x => !x.value) ||
            (request.required_csrf.includes(name) && !fields.length))
          return 'Пустой, исчезнувший или неоднозначный CSRF-токен';
      }
      for (const [name, value] of Object.entries(request.defaults)) {
        const fields = [...form.elements].filter(x => x.name === name && !x.disabled);
        if (fields.length && (fields.length !== 1 || fields[0].value !== value))
          return 'Служебные поля формы не соответствуют шаблону';
        if (!fields.length) {
          const input = document.createElement('input'); input.type = 'hidden';
          input.name = name; input.value = value; form.appendChild(input);
        }
      }
      return '';
    }""", {**profile["request"], "required_csrf": list(required_csrf)})
    if error:
        raise ValueError(error + "; пароль не отправлялся")
