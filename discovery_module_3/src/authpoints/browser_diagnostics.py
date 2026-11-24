"""Save a reduced DOM for debugging discovery, retaining full URL attributes."""

from __future__ import annotations

import hashlib
import html
import json
import re
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


_LONG_LITERAL = re.compile(r"[A-Za-z0-9_+/-]{32,}={0,2}")
_SECRET_ASSIGNMENT = re.compile(
    r"\b(password|passwd|csrf|xsrf|token|secret|cookie|authorization|session)"
    r"\s*[:=]\s*[^\s<,;]+",
    re.IGNORECASE,
)
_ATTRIBUTES = {
    "id", "class", "type", "name", "role", "autocomplete", "disabled",
    "hidden", "for", "method", "action", "href", "src", "aria-label",
    "aria-hidden", "aria-disabled", "aria-haspopup", "aria-controls", "placeholder",
}
_URL_ATTRIBUTES = {"href", "src", "action"}


def diagnostic_url(value: str) -> str:
    """Keep URL paths and queries for diagnostics, omitting userinfo and fragments."""

    try:
        parts = urlsplit(value)
        if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
            return "[non-HTTP URL]"
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        authority = f"{host}:{parts.port}" if parts.port else host
        return urlunsplit((parts.scheme, authority, parts.path, parts.query, ""))
    except (TypeError, ValueError):
        return "[invalid URL]"


def _redact_text(value: str) -> str:
    return _LONG_LITERAL.sub("[redacted]", _SECRET_ASSIGNMENT.sub(r"\1=[redacted]", value))


class _DiagnosticDOM(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_content: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.hidden_content:
            if tag in {"script", "style", "textarea"}:
                self.hidden_content.append(tag)
            return
        if tag in {"script", "style", "textarea"}:
            self.hidden_content.append(tag)
            return
        rendered: list[str] = []
        for name, value in attrs:
            if name not in _ATTRIBUTES:
                continue
            if value is None:
                rendered.append(name)
                continue
            if name in _URL_ATTRIBUTES:
                value = diagnostic_url(value)
                name = "data-discovery-" + name
                rendered.append(f'{name}="{html.escape(value, quote=True)}"')
            else:
                rendered.append(f'{name}="{html.escape(_redact_text(value), quote=True)}"')
        if tag in {"input", "button", "select"} and not any(name == "disabled" for name, _ in attrs):
            rendered.append("disabled")
        if tag == "iframe":
            rendered.append('sandbox=""')
        suffix = " " + " ".join(rendered) if rendered else ""
        self.parts.append(f"<{tag}{suffix}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.hidden_content:
            if tag == self.hidden_content[-1]:
                self.hidden_content.pop()
            return
        self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self.hidden_content:
            self.parts.append(html.escape(_redact_text(data)))


def sanitized_dom(body: str) -> str:
    parser = _DiagnosticDOM()
    parser.feed(body)
    parser.close()
    # A user may open a snapshot in a normal browser. Keep every saved
    # resource/navigation URL as text, and prohibit loading or submitting.
    return (
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; form-action \'none\'; sandbox">\n'
        + "".join(parser.parts)
    )


def save_browser_diagnostics(
    directory: str,
    *,
    candidate_url: str,
    snapshots: list[str],
    metadata: dict[str, object],
) -> dict[str, object]:
    """Write a non-executable DOM snapshot and JSON explanation."""

    result = dict(metadata)
    if not directory:
        return result
    destination = Path(directory).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(candidate_url.encode("utf-8")).hexdigest()[:16] + "-" + uuid.uuid4().hex[:8]
    paths: list[str] = []
    for index, snapshot in enumerate(snapshots):
        path = destination / f"browser-{key}-{index + 1}.html"
        path.write_text(sanitized_dom(snapshot), encoding="utf-8")
        paths.append(str(path))
    details_path = destination / f"browser-{key}.json"
    result.update({
        "dom_paths": paths,
        "dom_path": paths[-1] if paths else "",
        "diagnostics_path": str(details_path),
    })
    details_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result
