from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from ..models import FormField, FormObservation
from ..normalize import normalize_url


class _PageParser(HTMLParser):
    def __init__(self, base_url: str, *, redact_urls: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.redact_urls = redact_urls
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.forms: list[FormObservation] = []
        self.links: list[str] = []
        self._in_title = False
        self._current_form: FormObservation | None = None
        self._orphan_fields: list[FormField] = []
        self._text_size = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            action = _safe_absolute_url(
                self.base_url,
                attributes.get("action", ""),
                redact_urls=self.redact_urls,
            )
            self._current_form = FormObservation(
                action=action,
                method=(attributes.get("method") or "get").lower()[:20],
            )
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select", "button"}:
            field_type = attributes.get("type") or (
                "textarea"
                if tag == "textarea"
                else "select"
                if tag == "select"
                else "submit"
                if tag == "button"
                else "text"
            )
            field = FormField(
                name=(attributes.get("name") or attributes.get("id") or "")[:200],
                field_type=field_type.lower()[:50],
                autocomplete=attributes.get("autocomplete", "").lower()[:100],
                disabled="disabled" in attributes,
                hidden=(
                    "hidden" in attributes
                    or attributes.get("aria-hidden", "").lower() == "true"
                    or "display:none" in attributes.get("style", "").lower().replace(" ", "")
                    or "visibility:hidden" in attributes.get("style", "").lower().replace(" ", "")
                ),
            )
            if self._current_form is not None:
                self._current_form.fields.append(field)
            elif tag in {"input", "textarea", "select"}:
                self._orphan_fields.append(field)
        elif tag in {"a", "area", "link", "iframe"} and len(self.links) < 500:
            attribute = "src" if tag == "iframe" else "href"
            candidate = attributes.get(attribute, "")
            absolute = _safe_absolute_url(
                self.base_url,
                candidate,
                redact_urls=self.redact_urls,
            )
            if absolute:
                self.links.append(absolute)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        collapsed = " ".join(data.split())
        if not collapsed:
            return
        if self._in_title and sum(map(len, self.title_parts)) < 500:
            self.title_parts.append(collapsed)
        if self._text_size < 32_000:
            remaining = 32_000 - self._text_size
            value = collapsed[:remaining]
            self.text_parts.append(value)
            self._text_size += len(value)
        if self._current_form is not None and len(self._current_form.text) < 2_000:
            self._current_form.text = (self._current_form.text + " " + collapsed).strip()[:2_000]

    def result(self) -> tuple[str, str, list[FormObservation], list[str]]:
        if self._orphan_fields:
            self.forms.append(FormObservation(fields=self._orphan_fields, is_orphan=True))
        return (
            " ".join(self.title_parts)[:500],
            " ".join(self.text_parts)[:32_000],
            self.forms,
            list(dict.fromkeys(self.links)),
        )


def parse_html(
    body: str,
    base_url: str,
    *,
    redact_urls: bool = False,
) -> tuple[str, str, list[FormObservation], list[str]]:
    parser = _PageParser(base_url, redact_urls=redact_urls)
    try:
        parser.feed(body)
        parser.close()
    except (ValueError, AssertionError):
        # HTMLParser is intentionally tolerant, but a malformed page should never
        # abort the whole scan.
        pass
    return parser.result()


def _safe_absolute_url(
    base_url: str,
    candidate: str,
    *,
    redact_urls: bool,
) -> str:
    value = candidate.strip()
    if not value or value.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return ""
    try:
        return normalize_url(urljoin(base_url, value), redact_query=redact_urls)
    except ValueError:
        return ""
