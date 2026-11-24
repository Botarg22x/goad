"""Primary page/request templates and compatible HTML-form product hints.

Detection and optional verification rules are carried in the discovery report.
Session secrets are obtained from the site; request binding is template-defined.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from urllib.parse import unquote, urlsplit

import yaml

from .models import FormObservation, WebObservation
from .standard_paths import expand_standard_paths
from .template_verification import validate_verification
from .template_request import parse_raw_request
from .page_detection import validate_detection, matches_detection


@dataclass(frozen=True)
class LoginTemplate:
    id: str
    label: str
    category: str
    username_fields: tuple[str, ...]
    password_fields: tuple[str, ...]
    signals_any: tuple[dict, ...]
    paths: tuple[str, ...]
    verification: dict | None = None
    detection: dict | None = None


@dataclass(frozen=True)
class TemplateMatch:
    template: LoginTemplate
    username_field: str
    password_field: str
    signal: str

    def metadata(self) -> dict[str, object]:
        metadata = {
            "login_template": self.template.id,
            "login_template_label": self.template.label,
            "tags": [self.template.id, self.template.category],
            "credential_fields": {
                "username": self.username_field,
                "password": self.password_field,
            },
        }
        if self.template.verification is not None:
            from copy import deepcopy
            metadata["login_verification"] = deepcopy(self.template.verification)
        return metadata


@lru_cache(maxsize=1)
def load_login_templates() -> tuple[LoginTemplate, ...]:
    directory = files("authpoints").joinpath("data/login_templates")
    resources = sorted(
        (entry for entry in directory.iterdir()
         if entry.is_file() and entry.name.lower().endswith((".yaml", ".yml"))),
        key=lambda entry: entry.name,
    )
    if not resources:
        raise ValueError(f"{directory}: не найдены шаблоны .yaml/.yml")
    templates: list[LoginTemplate] = []
    seen: dict[str, str] = {}
    for resource in resources:
        label = str(resource)
        try:
            item = yaml.load(resource.read_text(encoding="utf-8-sig"), Loader=_TemplateLoader)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            location = f", строка {mark.line + 1}, столбец {mark.column + 1}" if mark else ""
            problem = getattr(exc, "problem", None) or "некорректный YAML"
            raise ValueError(f"{label}{location}: {problem}") from exc
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"{label}: не удалось прочитать UTF-8 шаблон: {exc}") from exc
        template = _validate_template(item, label)
        if template.id in seen:
            raise ValueError(f"{label}: id {template.id!r} уже объявлен в {seen[template.id]}")
        seen[template.id] = label
        templates.append(template)
    return tuple(templates)


class _TemplateLoader(yaml.SafeLoader):
    """Safe YAML with explicit errors for accidental duplicate keys."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            return super().construct_mapping(node, deep=deep)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None, None, "ключ должен быть строкой", key_node.start_mark,
                )
            if key in result:
                raise yaml.constructor.ConstructorError(
                    None, None, f"повторяющийся ключ {key!r}", key_node.start_mark,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _validate_template(item: object, label: str) -> LoginTemplate:
    if isinstance(item, dict) and "post" in item:
        item = _expand_simple_template(item, label)
    if isinstance(item, dict) and isinstance(item.get("detection"), dict):
        form_keys = {"username_fields", "password_fields", "signals_any"}
        if set(item["detection"]) == form_keys:
            overlap = form_keys & set(item)
            if overlap:
                raise ValueError(f"{label}: поля формы задаются либо в detection, либо наверху: {', '.join(sorted(overlap))}")
            # Built-in and user-defined templates share one visible YAML layout.
            # The runtime still uses the original form matcher and report format.
            form_detection = item["detection"]
            item = {key: value for key, value in item.items() if key != "detection"}
            item.update(form_detection)
    required = {
        "id", "label", "category", "username_fields", "password_fields", "signals_any", "paths"
    }
    if not isinstance(item, dict):
        raise ValueError(f"{label}: нужен один объект шаблона, а не список или пустой файл")
    if "detection" in item:
        required -= {"username_fields", "password_fields", "signals_any"}
    missing, extra = required - set(item), set(item) - required - {"verification", "detection"}
    if missing:
        raise ValueError(f"{label}: отсутствуют поля: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{label}: неизвестные поля: {', '.join(sorted(extra))}")
    for key in ("id", "label", "category"):
        if not isinstance(item[key], str) or not item[key].strip():
            raise ValueError(f"{label}: {key} должен быть непустой строкой")
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", item["id"]):
        raise ValueError(f"{label}: id должен соответствовать [a-z][a-z0-9_-]*")
    for key in (("paths",) if "detection" in item else ("username_fields", "password_fields", "paths")):
        if not _string_list(item[key]):
            raise ValueError(f"{label}: {key} должен быть непустым списком строк")
    try:
        # Reuse the scan's path validator, including logout/traversal checks.
        expand_standard_paths(["https://template.invalid/"], item["paths"])
    except ValueError as exc:
        raise ValueError(f"{label}: paths: {exc}") from exc
    detection = None
    if "detection" in item:
        try:
            detection = validate_detection(item["detection"])
        except ValueError as exc:
            raise ValueError(f"{label}: {exc}") from exc
    signals = item.get("signals_any", [])
    if not isinstance(signals, list) or (not signals and detection is None):
        raise ValueError(f"{label}: нужны дополнительные признаки signals_any")
    for signal in signals:
        if not isinstance(signal, dict) or len(signal) != 1:
            raise ValueError(f"{label}: каждый признак signals_any должен содержать один ключ")
        key, value = next(iter(signal.items()))
        if key == "field_names_all":
            valid = _string_list(value)
        elif key == "in_body_all":
            valid = (isinstance(value, list) and 1 <= len(value) <= 30
                     and all(isinstance(x, str) and x.strip() and len(x) <= 4096
                             and not any(ord(c) < 32 or ord(c) == 127 for c in x) for x in value))
        else:
            valid = (
                key in {"path_contains", "asset_path_contains", "text_contains", "in_body"}
                and isinstance(value, str) and bool(value.strip())
                and (key != "in_body" or (len(value) <= 4096 and not any(ord(c) < 32 for c in value)))
            )
        if not valid:
            raise ValueError(f"{label}: неверный признак {key}")
    value = item.get("verification")
    if detection is not None:
        if not isinstance(value, dict) or "detection" in value:
            raise ValueError(f"{label}: шаблон страницы требует verification; detection задаётся только наверху")
        value = {**value, "detection": detection}
    verification = validate_verification(value, label) if "verification" in item else None
    if detection is not None:
        if verification["request"]["action"] not in {"page", "fixed"} or "raw" not in verification["request"]:
            raise ValueError(f"{label}: шаблон страницы требует action: page/fixed и raw")
        recipe = parse_raw_request(verification["request"]["raw"])
        item = {**item, "username_fields": [recipe.username_field], "password_fields": [recipe.password_field]}
    if verification and (set(verification["request"]["defaults"]) | set(verification["request"]["csrf_fields"])) & set(item["username_fields"] + item["password_fields"]):
        raise ValueError(f"{label}: verification: поля учётных данных нельзя задавать как defaults или CSRF")
    if verification and "raw" in verification["request"]:
        recipe = parse_raw_request(verification["request"]["raw"])
        if recipe.username_field not in item["username_fields"] or recipe.password_field not in item["password_fields"]:
            raise ValueError(f"{label}: verification: поля raw-запроса должны совпадать с полями детектора")
    return LoginTemplate(
        id=item["id"], label=item["label"], category=item["category"],
        username_fields=tuple(item["username_fields"]),
        password_fields=tuple(item["password_fields"]),
        signals_any=tuple(signals), paths=tuple(item["paths"]),
        verification=verification,
        detection=detection,
    )


def _expand_simple_template(item: dict, label: str) -> dict:
    """Turn the small, editable product format into the existing portable contract."""
    allowed = {"id", "label", "category", "paths", "in_body", "alternate_in_body",
               "not_in_body", "post", "post_to", "path_contains", "csrf_fields",
               "success", "success_status", "success_link_query", "success_form_fields",
               "failure", "failure_status", "captcha",
               "captcha_field", "mfa", "mfa_field", "csrf_error"}
    unknown = set(item) - allowed
    if unknown:
        raise ValueError(f"{label}: неизвестные поля простого шаблона: {', '.join(sorted(unknown))}")
    required = {"id", "paths", "in_body", "post"}
    missing = required - set(item)
    if missing:
        raise ValueError(f"{label}: в простом шаблоне нужны: {', '.join(sorted(missing))}")
    if not {"success", "success_status", "success_link_query", "success_form_fields",
            "failure", "failure_status"} & set(item):
        raise ValueError(f"{label}: нужен хотя бы один признак результата или HTTP-код ответа")

    def literal(value: object, key: str) -> str:
        if (not isinstance(value, str) or not value.strip() or len(value) > 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError(f"{label}: {key} должен быть одной непустой строкой до 4096 символов")
        return value

    def result_rules(key: str) -> list[dict]:
        values = item.get(key, [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or (key in item and not values):
            raise ValueError(f"{label}: {key} — строка или непустой список строк")
        return [{"in_body": literal(value, key)} for value in values]

    def marker_list(key: str, required: bool = False) -> list[str]:
        markers = item.get(key, [])
        if isinstance(markers, str):
            markers = [markers]
        if not isinstance(markers, list) or len(markers) > 30 or (required and not markers):
            raise ValueError(f"{label}: {key} — строка или список из 1–30 строк")
        return [literal(marker, key) for marker in markers]

    markers = marker_list("in_body", required=True)
    alternate = marker_list("alternate_in_body")
    excluded = marker_list("not_in_body")
    body = literal(item["post"], "post")
    to = item.get("post_to", "form")
    if not isinstance(to, str) or (to not in {"form", "page"} and not to.startswith("/")):
        raise ValueError(f"{label}: post_to должен быть form, page или путём /... на том же сайте")
    action = to if to in {"form", "page"} else "fixed"
    if action == "fixed":
        try:
            expand_standard_paths(["https://template.invalid/"], [to])
        except ValueError as exc:
            raise ValueError(f"{label}: post_to: {exc}") from exc
    csrf = item.get("csrf_fields", [])
    if not isinstance(csrf, list):
        raise ValueError(f"{label}: csrf_fields должен быть списком имён полей")
    if "{{form_fields}}" in body:
        raise ValueError(f"{label}: {{form_fields}} добавляется автоматически; уберите его из post")
    raw_target = "{{action}}" if action != "fixed" else to
    raw = (f"POST {raw_target} HTTP/1.1\n"
           "Host: {{host}}\n"
           "Content-Type: application/x-www-form-urlencoded\n\n"
           + body + "&{{form_fields}}")
    try:
        recipe = parse_raw_request(raw)
    except ValueError as exc:
        raise ValueError(f"{label}: post: {exc}") from exc
    result = {
        "success_any": result_rules("success"),
        "failure_any": result_rules("failure"),
        "captcha_any": result_rules("captcha"),
        "mfa_any": result_rules("mfa"),
        "csrf_error_any": result_rules("csrf_error"),
    }
    for key in ("success_status", "failure_status"):
        if key in item:
            status = item[key]
            if type(status) is not int or not 200 <= status <= 599:
                raise ValueError(f"{label}: {key} должен быть HTTP-кодом от 200 до 599")
            result[key] = status
    for key, rule in (("success_link_query", "link_query"),
                      ("success_form_fields", "form_fields")):
        if key in item:
            result["success_any"].append({rule: item[key]})
    for key, group in (("captcha_field", "captcha_any"), ("mfa_field", "mfa_any")):
        if key in item:
            result[group].append({"input_name": literal(item[key], key)})
    expanded = {
        "id": item["id"],
        "label": item.get("label", item["id"]),
        "category": item.get("category", "webapp"),
        "paths": item["paths"],
    }
    path = item.get("path_contains")
    if path is not None:
        path = literal(path, "path_contains")
    if action in {"page", "fixed"}:
        primary = [{"in_body": marker} for marker in markers]
        conditions = ([{"any": [{"all": primary},
                                {"all": [{"in_body": marker} for marker in alternate]}]}]
                      if alternate else primary)
        conditions.extend({"not": {"in_body": marker}} for marker in excluded)
        if path is not None:
            conditions.append({"path_contains": path})
        expanded["detection"] = {"status_codes": [200],
                                  "match": conditions[0] if len(conditions) == 1 else {"all": conditions}}
    else:
        if excluded or alternate:
            raise ValueError(f"{label}: alternate_in_body/not_in_body доступны с post_to: page или /путь")
        expanded["username_fields"] = [recipe.username_field]
        expanded["password_fields"] = [recipe.password_field]
        expanded["signals_any"] = ([{"in_body": markers[0]}] if len(markers) == 1
                                   else [{"in_body_all": markers}])
        if path is not None:
            # The compatible form matcher uses OR. A path guard requires the
            # page-template mode so it cannot silently broaden recognition.
            raise ValueError(f"{label}: path_contains доступен с post_to: page или /путь; для формы оставьте только in_body")
    expanded["verification"] = {
        "schema": "form-check/1",
        "transport": "auto",
        "request": {"action": action, "session": "fresh", "csrf_fields": csrf, "raw": raw},
        "result": result,
    }
    return expanded


def _string_list(value: object) -> bool:
    return (
        isinstance(value, list) and bool(value)
        and all(isinstance(x, str) and x.strip() for x in value)
    )


def parse_template_selection(values: list[str]) -> tuple[str, ...]:
    selected = tuple(dict.fromkeys(part.strip().lower() for value in values for part in value.split(",")))
    known = {template.id for template in load_login_templates()}
    if any(value not in known for value in selected):
        raise ValueError("Неизвестный шаблон входа; доступны: " + ", ".join(sorted(known)))
    return selected


def template_paths(selected: tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(
        path for template in load_login_templates()
        if not selected or template.id in selected
        for path in template.paths
    ))


def match_login_template(observation: WebObservation, form: FormObservation) -> TemplateMatch | None:
    if form.is_orphan:
        return None
    visible = [field for field in form.fields if not field.disabled and not field.hidden]
    names = {field.name for field in form.fields if not field.disabled}
    matches = []
    for template in load_login_templates():
        if template.detection is not None:
            continue
        users = [f.name for f in visible if f.name in template.username_fields and f.field_type in {"text", "email", "tel"}]
        passwords = [f.name for f in visible if f.name in template.password_fields and f.field_type == "password"]
        # Do not resolve an ambiguous form by picking the first credential field.
        if len(users) != 1 or len(passwords) != 1:
            continue
        if template.verification and "raw" in template.verification["request"]:
            recipe = parse_raw_request(template.verification["request"]["raw"])
            if (users[0], passwords[0]) != (recipe.username_field, recipe.password_field):
                continue
        for signal in template.signals_any:
            key, value = next(iter(signal.items()))
            matched = False
            if key == "field_names_all":
                matched = set(value) <= names
            elif key == "text_contains":
                matched = value.casefold() in (observation.title + " " + form.text).casefold()
            elif key == "in_body":
                matched = value in observation.body
            elif key == "in_body_all":
                matched = all(fragment in observation.body for fragment in value)
            elif key in {"path_contains", "asset_path_contains"}:
                urls = observation.links if key == "asset_path_contains" else [observation.url, form.action]
                matched = any(value.casefold() in unquote(urlsplit(url).path).casefold() for url in urls)
            if matched:
                matches.append(TemplateMatch(template, users[0], passwords[0], f"{key}={value}"))
                break
    # Contradictory product signatures are kept generic rather than guessed.
    return matches[0] if len(matches) == 1 else None


def match_page_template(observation: WebObservation) -> TemplateMatch | None:
    matches = []
    for template in load_login_templates():
        if template.detection is None:
            continue
        if matches_detection(template.detection, url=observation.url, status=observation.status_code,
                             title=observation.title, text=observation.text, links=observation.links,
                             field_names={field.name for form in observation.forms for field in form.fields},
                             body=observation.body):
            matches.append(TemplateMatch(template, template.username_fields[0], template.password_fields[0],
                                         "Совпали правила detection страницы; параметры запроса заданы шаблоном"))
    return matches[0] if len(matches) == 1 else None
