"""Declarative page fingerprints shared by independently installed modules."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit


def validate_detection(value: object) -> dict:
    def fail():
        raise ValueError("detection: нужны status_codes и match с all/any/not и признаками страницы")

    if not isinstance(value, dict) or set(value) != {"status_codes", "match"}:
        fail()
    statuses = value["status_codes"]
    if (not isinstance(statuses, list) or not statuses
            or any(type(code) is not int or not 200 <= code < 300 for code in statuses)
            or len(statuses) != len(set(statuses))):
        fail()

    def check(rule, depth=0):
        if depth > 6 or not isinstance(rule, dict) or len(rule) != 1:
            fail()
        key, item = next(iter(rule.items()))
        if key in {"all", "any"}:
            if not isinstance(item, list) or not 1 <= len(item) <= 30:
                fail()
            for child in item:
                check(child, depth + 1)
        elif key == "not":
            check(item, depth + 1)
        elif key == "field_names_all":
            if (not isinstance(item, list) or not item
                    or not all(isinstance(x, str) and x.strip() and len(x) <= 200 for x in item)):
                fail()
        elif key in {"path_contains", "title_contains", "text_contains", "asset_path_contains", "in_body"}:
            limit = 4096 if key == "in_body" else 512
            if (not isinstance(item, str) or not item.strip() or len(item) > limit
                    or (key == "in_body" and any(ord(char) < 32 for char in item))):
                fail()
        else:
            fail()
    check(value["match"])
    return value


def matches_detection(detection: dict, *, url: str, status: int | None,
                      title: str, text: str, field_names: set[str], links: list[str], body: str = "") -> bool:
    if status not in detection["status_codes"]:
        return False

    def match(rule):
        key, value = next(iter(rule.items()))
        if key == "all":
            return all(match(child) for child in value)
        if key == "any":
            return any(match(child) for child in value)
        if key == "not":
            return not match(value)
        if key == "field_names_all":
            return set(value) <= field_names
        if key == "title_contains":
            return value.casefold() in title.casefold()
        if key == "text_contains":
            return value.casefold() in text.casefold()
        if key == "in_body":
            return value in body
        urls = links if key == "asset_path_contains" else [url]
        return any(value.casefold() in unquote(urlsplit(item).path).casefold() for item in urls)

    return match(detection["match"])


class PageProbe(HTMLParser):
    """Inspect a rendered or static page without assuming an HTML form."""
    def __init__(self, body: str):
        super().__init__(convert_charrefs=True)
        self.body = body
        self.title = ""
        self.text = ""
        self.links = []
        self.field_names = set()
        self.inputs = []
        self._title = False
        self._skip = 0
        self.feed(body)
        self.close()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self._title = True
        if tag in {"script", "style"}:
            self._skip += 1
        if tag in {"input", "select", "textarea", "button"}:
            name = values.get("name") or ""
            if name:
                self.field_names.add(name)
                self.inputs.append((name, values.get("type") or "text", values.get("value") or ""))
        if tag in {"script", "link", "img", "iframe", "a"}:
            resource = values.get("src") or values.get("href")
            if resource:
                self.links.append(resource)

    def handle_endtag(self, tag):
        if tag == "title":
            self._title = False
        if tag in {"script", "style"}:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data):
        if self._title:
            self.title += data
        if not self._skip:
            self.text += data + " "

    def matches(self, detection: dict, url: str, status: int) -> bool:
        return matches_detection(detection, url=url, status=status, title=self.title,
                                 text=self.text, field_names=self.field_names, links=self.links,
                                 body=self.body)
