"""Conservative authentication signals shared by HTTP form transports."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any


_JSON_MESSAGE_KEYS = {"message", "error", "error_message", "error_description", "detail", "description", "reason", "code", "error_code"}
_JSON_AUTH_FLAGS = {"authenticated", "is_authenticated", "isauthenticated", "logged_in", "loggedin", "is_logged_in", "isloggedin"}
_JSON_STATUS_KEYS = {"result", "status", "state", "outcome"}
_JSON_ERROR_STATES = {"error", "failed", "failure", "denied", "rejected"}
_JSON_SUCCESS_STATES = {"authenticated", "logged_in", "signed_in"}


def json_object(body: str) -> dict[str, Any]:
    """Accept only an unambiguous JSON object, regardless of Content-Type."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=unique_object)
        return value if isinstance(value, dict) else {}
    except (ValueError, RecursionError):
        return {}


def json_auth_signal(value: dict[str, Any], failure_pattern: re.Pattern[str]) -> str | None:
    """Require explicit credential evidence; HTTP 200 and generic 'success' do not count."""

    if not value:
        return None
    messages = _json_messages(value)
    failure = any(failure_pattern.search(message.replace("_", " ").replace("-", " ")) for message in messages)
    auth_flags = [flag for key, flag in value.items() if key.casefold() in _JSON_AUTH_FLAGS and isinstance(flag, bool)]
    success_flag = value.get("success")
    states = [state.casefold().replace("-", "_").replace(" ", "_")
              for key, state in value.items() if key.casefold() in _JSON_STATUS_KEYS and isinstance(state, str)]
    failure = failure or any(failure_pattern.search(state.replace("_", " ")) for state in states)
    success = True in auth_flags or success_flag is True or any(state in _JSON_SUCCESS_STATES for state in states)
    error = (False in auth_flags or success_flag is False
             or any(state in _JSON_ERROR_STATES for state in states)
             or value.get("error") is True
             or isinstance(value.get("error"), str) and bool(value["error"].strip()))
    if (failure or False in auth_flags) and success:
        return "error"
    if failure or False in auth_flags:
        return "failure"
    if success and not error:
        return "success"
    return "error" if error or success else None


def _json_messages(value: Any, *, depth: int = 0) -> Iterator[str]:
    """Inspect bounded, named response fields rather than arbitrary JSON strings."""

    if depth > 4:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str) and key.casefold() in _JSON_MESSAGE_KEYS:
                yield child[:10_000]
            elif isinstance(child, (dict, list)):
                yield from _json_messages(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value[:100]:
            if isinstance(child, (dict, list)):
                yield from _json_messages(child, depth=depth + 1)
