"""Load editable CLI help strings with a fail-safe built-in fallback."""

from __future__ import annotations

from importlib import resources
from typing import Any

import yaml


_DEFAULT_HELP: dict[str, Any] = {
    "common": {
        "usage": "Использование",
        "positional_arguments": "Позиционные аргументы",
        "options": "Параметры",
        "help": "Показать эту справку и выйти",
        "version": "Показать версию и выйти",
    },
    "quick": {
        "usage": "passgen -p PATTERN [OPTIONS]",
        "description": "Быстрая генерация паролей по паттернам и словарям.",
        "groups": {
            "patterns": "Паттерны",
            "wordlists": "Словари",
            "output": "Вывод",
            "mutations": "Мутации",
            "additional": "Дополнительные команды",
        },
        "additional_description": "Дополнительные параметры генерации.",
        "options": {},
    },
}


def _deep_merge(defaults: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = dict(defaults)
    for key, value in overrides.items():
        default = result.get(key)
        if isinstance(default, dict):
            # A malformed branch such as ``main: text`` must not erase the
            # usable built-in fallback for that entire section.
            if isinstance(value, dict):
                result[key] = _deep_merge(default, value)
        elif default is None:
            # Empty dictionaries such as ``options`` intentionally accept
            # additional user-editable string leaves.
            if isinstance(value, (str, dict)):
                result[key] = value
        elif isinstance(value, type(default)):
            result[key] = value
    return result


def load_help() -> dict[str, Any]:
    try:
        text = (
            resources.files("password_generator.help")
            .joinpath("ru.yaml")
            .read_text(encoding="utf-8")
        )
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            return _DEFAULT_HELP
        return _deep_merge(_DEFAULT_HELP, loaded)
    except (
        FileNotFoundError,
        ModuleNotFoundError,
        OSError,
        UnicodeError,
        yaml.YAMLError,
    ):
        return _DEFAULT_HELP


HELP_TEXTS = load_help()


def help_value(path: str, fallback: str = "") -> str:
    value: Any = HELP_TEXTS
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return fallback
        value = value[part]
    return value if isinstance(value, str) else fallback
