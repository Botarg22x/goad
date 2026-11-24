"""Portable raw form-request grammar, packaged with each standalone module.

Keep the authpoints and authchecker copies identical (covered by a parity test).
No templating engine or executable expressions are accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True)
class RawFormRequest:
    target: str
    headers: tuple[tuple[str, str], ...]
    # A None entry means "insert current form fields not explicitly listed".
    fields: tuple[tuple[str, str] | None, ...]
    username_field: str
    password_field: str

    @property
    def defaults(self) -> dict[str, str]:
        return {name: value for pair in self.fields if pair is not None
                for name, value in [pair] if value not in {"{{login}}", "{{password}}"}}


def _fail(message: str) -> None:
    raise ValueError("request.raw: " + message)


def parse_raw_request(raw: object) -> RawFormRequest:
    if not isinstance(raw, str) or not raw or len(raw) > 32768:
        _fail("нужен HTTP-запрос длиной до 32768 символов")
    text = raw.replace("\r\n", "\n").removesuffix("\n")
    if any((ord(c) < 32 and c != "\n") or ord(c) == 127 for c in text):
        _fail("управляющие символы недопустимы")
    head, separator, body = text.partition("\n\n")
    if not separator or not body or "\n" in body:
        _fail("после заголовков нужна пустая строка и одна строка тела формы")
    lines = head.split("\n")
    start = lines[0].split(" ")
    if len(start) != 3 or start[0] != "POST" or start[2] != "HTTP/1.1":
        _fail("первая строка: POST {{action}} HTTP/1.1 (или путь найденной формы)")
    target = start[1]
    if target != "{{action}}":
        parts = urlsplit(target)
        if (not target.startswith("/") or target.startswith("//") or parts.scheme
                or parts.netloc or parts.fragment or any(c in target for c in "{}\\")
                or any(c.isspace() for c in target)):
            _fail("адрес: {{action}} или путь текущей формы без другого хоста")
    headers = {}
    forbidden = {"cookie", "authorization", "proxy-authorization", "content-length",
                 "transfer-encoding", "connection", "proxy-connection", "trailer",
                 "upgrade", "expect", "accept-encoding", "user-agent"}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            _fail("некорректный HTTP-заголовок")
        key, value = name.lower(), value.strip()
        if key in headers or key in forbidden:
            _fail("повторяющийся либо управляемый сессией/транспортом заголовок")
        if not value or not value.isascii():
            _fail("значения заголовков должны быть непустыми ASCII-строками")
        if key == "host":
            if value != "{{host}}":
                _fail("Host должен быть {{host}}")
        elif key == "referer":
            if value != "{{page_url}}":
                _fail("Referer должен быть {{page_url}}")
        elif key == "origin":
            if value != "{{origin}}":
                _fail("Origin должен быть {{origin}}")
        elif "{{" in value or "}}" in value:
            _fail("подстановки логина/пароля допустимы только в теле")
        headers[key] = value
    if headers.get("host") != "{{host}}":
        _fail("нужен Host: {{host}}")
    if headers.get("content-type", "").lower() != "application/x-www-form-urlencoded":
        _fail("пока поддерживается Content-Type: application/x-www-form-urlencoded")
    fields = []
    names = set()
    slots = {}
    dynamic_count = 0
    for part in body.split("&"):
        if part == "{{form_fields}}":
            dynamic_count += 1
            fields.append(None)
            continue
        if not part or re.search(r"%(?![0-9a-fA-F]{2})", part):
            _fail("некорректное URL-кодирование поля")
        try:
            pairs = parse_qsl(part, keep_blank_values=True, strict_parsing=True,
                              encoding="utf-8", errors="strict", max_num_fields=1)
        except (ValueError, UnicodeError):
            _fail("тело должно состоять из пар имя=значение через &")
        if len(pairs) != 1:
            _fail("пустое поле")
        name, value = pairs[0]
        if (not name.strip() or len(name) > 512 or name in names or len(value) > 512
                or any(ord(c) < 32 or ord(c) == 127 for c in name + value)
                or any(c in name for c in "{}")):
            _fail("пустое, повторяющееся или некорректное имя/значение поля")
        names.add(name)
        if value in {"{{login}}", "{{password}}"}:
            if value in slots:
                _fail("логин и пароль должны встречаться ровно по одному разу")
            slots[value] = name
        elif "{{" in value or "}}" in value:
            _fail("неизвестная подстановка; используйте {{login}}, {{password}}, {{form_fields}}")
        fields.append((name, value))
    if set(slots) != {"{{login}}", "{{password}}"} or dynamic_count != 1:
        _fail("нужны ровно по одной подстановке {{login}}, {{password}} и {{form_fields}}")
    return RawFormRequest(target, tuple(headers.items()), tuple(fields),
                          slots["{{login}}"], slots["{{password}}"])


def normalize_request(request: object) -> dict:
    """Expand concise raw YAML to the legacy portable request contract."""
    if not isinstance(request, dict):
        raise ValueError("request: нужен объект")
    result = dict(request)
    if "raw" not in result:
        return result
    allowed = {"raw", "session", "csrf_fields", "method", "action", "encoding", "defaults"}
    if set(result) - allowed or not {"raw", "session", "csrf_fields"} <= set(result):
        _fail("нужны raw, session, csrf_fields; неизвестные настройки недопустимы")
    recipe = parse_raw_request(result["raw"])
    action = result.get("action", "form")
    if not isinstance(action, str) or action not in {"form", "page", "fixed"}:
        _fail("action должен быть form, page или fixed")
    expected = {"method": "POST", "action": action, "encoding": "form", "defaults": recipe.defaults}
    if action == "page" and recipe.target != "{{action}}":
        _fail("action: page использует POST {{action}} — URL распознанной страницы")
    if action == "fixed" and recipe.target == "{{action}}":
        _fail("action: fixed требует конкретный путь POST на текущем сайте")
    for key, value in expected.items():
        if key in result and result[key] != value:
            _fail("структурированные настройки противоречат HTTP-запросу")
        result[key] = value
    return result
