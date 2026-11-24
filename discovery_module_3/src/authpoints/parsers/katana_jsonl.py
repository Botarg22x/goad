from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

from ..models import FormField, FormObservation, Source, WebObservation
from ..normalize import normalize_url
from .html import parse_html


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SAFE_HEADERS = {
    "content-type",
    "location",
    "www-authenticate",
    "proxy-authenticate",
}
MAX_JSONL_LINE = 4 * 1024 * 1024


def parse_katana_jsonl(
    data: str,
    *,
    redact_urls: bool = False,
) -> tuple[list[WebObservation], list[str]]:
    observations: list[WebObservation] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(data.splitlines(), start=1):
        line = _ANSI.sub("", raw_line).strip()
        if not line:
            continue
        if len(line.encode("utf-8", errors="ignore")) > MAX_JSONL_LINE:
            errors.append(f"line {line_number}: JSONL record is too large")
            continue
        if line.startswith(("http://", "https://")):
            try:
                observations.append(
                    WebObservation(
                        url=normalize_url(line, redact_query=redact_urls),
                        source=Source.KATANA,
                    )
                )
            except ValueError as exc:
                errors.append(f"line {line_number}: {exc}")
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON: {exc.msg}")
            continue
        except (ValueError, RecursionError):
            errors.append(f"line {line_number}: JSON value exceeds parser limits")
            continue
        if not isinstance(item, dict):
            errors.append(f"line {line_number}: expected a JSON object")
            continue
        try:
            observation = _parse_item(item, redact_urls=redact_urls)
        except ValueError as exc:
            errors.append(f"line {line_number}: {exc}")
            continue
        observations.append(observation)
    return observations, errors


def _parse_item(item: dict[str, Any], *, redact_urls: bool) -> WebObservation:
    request = item.get("request") if isinstance(item.get("request"), dict) else {}
    response = item.get("response") if isinstance(item.get("response"), dict) else {}
    endpoint = (
        request.get("endpoint")
        or request.get("url")
        or item.get("url")
        or item.get("endpoint")
    )
    if not isinstance(endpoint, str):
        raise ValueError("Katana record has no URL endpoint")
    url = normalize_url(endpoint, redact_query=redact_urls)

    request_error = item.get("error")
    if isinstance(request_error, str) and request_error.strip():
        detail = " ".join(request_error.split())[:500]
        raise ValueError(f"Katana request failed for {url}: {detail}")

    status_code: int | None = None
    raw_status = response.get("status_code", item.get("status_code"))
    try:
        if raw_status is not None:
            status_code = int(raw_status)
    except (TypeError, ValueError):
        pass

    headers = _safe_headers(response.get("headers"))
    redirect_target = ""
    if headers.get("location"):
        try:
            redirect_target = normalize_url(
                urljoin(url, headers["location"]), redact_query=False
            )
            headers["location"] = normalize_url(redirect_target)
        except ValueError:
            headers.pop("location", None)
    body = response.get("body") if isinstance(response.get("body"), str) else ""
    title = ""
    text = ""
    forms: list[FormObservation] = []
    links: list[str] = []
    content_type = headers.get("content-type", "").lower()
    html_marker = "<html" in body[:2000].lower() or "<form" in body[:2000].lower()
    should_parse_html = bool(
        body
        and (
            "text/html" in content_type
            or "application/xhtml+xml" in content_type
            or (not content_type and html_marker)
        )
    )
    if should_parse_html:
        title, text, forms, links = parse_html(
            body,
            url,
            redact_urls=redact_urls,
        )
    if not forms:
        forms = _structured_forms(response.get("forms") or item.get("forms"), url)

    page_type = ""
    knowledgebase = response.get("knowledgebase")
    if isinstance(knowledgebase, dict):
        page_type = str(
            knowledgebase.get("PageType") or knowledgebase.get("page_type") or ""
        ).lower()
        if not forms:
            forms = _knowledgebase_forms(knowledgebase.get("Forms"), url)

    return WebObservation(
        url=url,
        source=Source.KATANA,
        status_code=status_code,
        method=str(request.get("method") or "GET").upper(),
        headers=headers,
        title=title,
        text=text,
        body=body,
        forms=forms,
        links=links,
        redirect_target=redirect_target,
        knowledgebase_page_type=page_type,
        discovery_diagnostics=(
            item["discovery_diagnostics"]
            if isinstance(item.get("discovery_diagnostics"), dict)
            else {}
        ),
    )


def _safe_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, header_value in value.items():
        normalized_key = str(key).lower().replace("_", "-")
        if normalized_key not in _SAFE_HEADERS or header_value is None:
            continue
        if isinstance(header_value, str):
            normalized_value = header_value
        elif isinstance(header_value, list) and all(
            isinstance(item, str) for item in header_value
        ):
            normalized_value = ", ".join(header_value)
        else:
            continue
        if normalized_value:
            result[normalized_key] = normalized_value[:1000]
    return result


def _structured_forms(value: Any, base_url: str) -> list[FormObservation]:
    if not isinstance(value, list):
        return []
    result: list[FormObservation] = []
    for form in value:
        if not isinstance(form, dict):
            continue
        action = _normal_form_action(base_url, str(form.get("action") or ""))
        fields: list[FormField] = []
        raw_fields = form.get("inputs") or form.get("fields") or []
        if isinstance(raw_fields, dict):
            raw_fields = [
                {"name": name, "type": field_type}
                for name, field_type in raw_fields.items()
            ]
        if isinstance(raw_fields, list):
            for raw_field in raw_fields:
                if isinstance(raw_field, dict):
                    fields.append(
                        FormField(
                            name=str(raw_field.get("name") or raw_field.get("id") or "")[:200],
                            field_type=str(raw_field.get("type") or "text").lower()[:50],
                            autocomplete=str(raw_field.get("autocomplete") or "").lower()[:100],
                            disabled=raw_field.get("disabled") is True,
                            hidden=raw_field.get("hidden") is True,
                        )
                    )
        result.append(
            FormObservation(
                action=action,
                method=str(form.get("method") or "get").lower()[:20],
                fields=fields,
            )
        )
    return result


def _knowledgebase_forms(value: Any, base_url: str) -> list[FormObservation]:
    return _structured_forms(value, base_url)


def _normal_form_action(base_url: str, action: str) -> str:
    if not action:
        return ""
    try:
        return normalize_url(urljoin(base_url, action))
    except ValueError:
        return ""
