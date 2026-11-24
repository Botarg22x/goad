"""Validate optional discovery-template hints against observed form fields."""
from collections.abc import Mapping
from typing import Any
from .template_request import parse_raw_request


def template_credential_fields(metadata: Mapping[str, Any]) -> tuple[str, str]:
    hints, fields = metadata.get("credential_fields"), metadata.get("fields")
    if not metadata.get("login_template") or not isinstance(hints, Mapping):
        return "", ""
    username, password = hints.get("username"), hints.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password or username == password:
        return "", ""
    profile = metadata.get("login_verification")
    request = profile.get("request") if isinstance(profile, Mapping) else None
    if isinstance(request, Mapping) and request.get("action") in {"page", "fixed"}:
        recipe = parse_raw_request(request.get("raw"))
        return (username, password) if (username, password) == (recipe.username_field, recipe.password_field) else ("", "")
    if not isinstance(fields, list):
        return "", ""
    usable = [field for field in fields if isinstance(field, Mapping) and not field.get("disabled") and not field.get("hidden")]
    users = [field for field in usable if field.get("name") == username and field.get("type", "text") in {"text", "email", "tel"}]
    passwords = [field for field in usable if field.get("name") == password and field.get("type") == "password"]
    return (username, password) if len(users) == len(passwords) == 1 else ("", "")
