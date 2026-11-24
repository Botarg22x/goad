"""Streaming mutation engine, including a strict hashcat-rule subset."""

from __future__ import annotations

import base64
from typing import Any, Iterator
from urllib.parse import quote_from_bytes

from .config import ConfigError, MutationConfig, MutationOperation
from .limits import MAX_CANDIDATE_LENGTH


EFFECT_ALWAYS = "always_changes"
EFFECT_NEVER = "never_changes"
EFFECT_UNKNOWN = "unknown"
EFFECT_UPPERCASE = "uppercase"
EFFECT_LOWERCASE = "lowercase"
EFFECT_CAPITALIZE_FIRST = "capitalize_first"
EFFECT_RU_TO_ENG = "ru_to_eng"
EFFECT_URL_ENCODE_SPECIALS = "url_encode_specials"

COMPOSITIONAL_EFFECTS = frozenset(
    {
        EFFECT_UPPERCASE,
        EFFECT_LOWERCASE,
        EFFECT_RU_TO_ENG,
        EFFECT_URL_ENCODE_SPECIALS,
    }
)


CYRILLIC_TO_QWERTY = {
    "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t", "н": "y",
    "г": "u", "ш": "i", "щ": "o", "з": "p", "х": "[", "ъ": "]",
    "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g", "р": "h",
    "о": "j", "л": "k", "д": "l", "ж": ";", "э": "'", "я": "z",
    "ч": "x", "с": "c", "м": "v", "и": "b", "т": "n", "ь": "m",
    "б": ",", "ю": ".", "ё": "`",
}
CYRILLIC_TO_QWERTY.update(
    {
        russian.upper(): english.upper() if english.isalpha() else english
        for russian, english in list(CYRILLIC_TO_QWERTY.items())
    }
)


def ru_to_eng_layout(word: str) -> str:
    return "".join(CYRILLIC_TO_QWERTY.get(char, char) for char in word)


def url_encode_specials(word: str) -> str:
    return "".join(
        char if char.isalnum() else quote_from_bytes(char.encode("utf-8"), safe="")
        for char in word
    )


def decode_rule_position(char: str) -> int:
    if char in "0123456789":
        return int(char)
    if char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        return ord(char.upper()) - ord("A") + 10
    raise ConfigError(f"Invalid hashcat rule position: {char!r}")


def _rule_arg(rule: str, index: int, operation: str) -> str:
    if index >= len(rule):
        raise ConfigError(f"Hashcat operation {operation!r} is missing an argument")
    return rule[index]


def _swap_at(word: str, left: int, right: int) -> str:
    if left >= len(word) or right >= len(word):
        return word
    characters = list(word)
    characters[left], characters[right] = characters[right], characters[left]
    return "".join(characters)


def _toggle_at(word: str, position: int) -> str:
    if position >= len(word):
        return word
    return word[:position] + word[position].swapcase() + word[position + 1 :]


def _check_length(length: int, maximum: int, context: str) -> None:
    if length > maximum:
        raise ConfigError(
            f"{context} would exceed the hard candidate length limit "
            f"({maximum:,} characters)"
        )


def apply_hashcat_rule(
    word: str,
    rule: str,
    *,
    max_length: int = MAX_CANDIDATE_LENGTH,
) -> str:
    """Apply the documented passgen subset of hashcat rule syntax."""

    current = word
    _check_length(len(current), max_length, "Hashcat rule input")
    index = 0
    while index < len(rule):
        operation = rule[index]
        index += 1
        if operation.isspace() or operation == ":":
            continue
        if operation == "l":
            current = current.lower()
        elif operation == "u":
            current = current.upper()
        elif operation == "c":
            current = current.capitalize()
        elif operation == "C":
            current = current[:1].lower() + current[1:].upper()
        elif operation == "t":
            current = current.swapcase()
        elif operation == "T":
            position = decode_rule_position(_rule_arg(rule, index, operation))
            index += 1
            current = _toggle_at(current, position)
        elif operation == "r":
            current = current[::-1]
        elif operation == "d":
            _check_length(len(current) * 2, max_length, "Hashcat operation 'd'")
            current += current
        elif operation == "p":
            count = decode_rule_position(_rule_arg(rule, index, operation))
            index += 1
            _check_length(
                len(current) * (count + 1),
                max_length,
                "Hashcat operation 'p'",
            )
            current *= count + 1
        elif operation == "f":
            _check_length(len(current) * 2, max_length, "Hashcat operation 'f'")
            current += current[::-1]
        elif operation == "{":
            current = current[1:] + current[:1] if current else current
        elif operation == "}":
            current = current[-1:] + current[:-1] if current else current
        elif operation == "$":
            _check_length(len(current) + 1, max_length, "Hashcat operation '$'")
            current += _rule_arg(rule, index, operation)
            index += 1
        elif operation == "^":
            _check_length(len(current) + 1, max_length, "Hashcat operation '^'")
            current = _rule_arg(rule, index, operation) + current
            index += 1
        elif operation == "[":
            current = current[1:]
        elif operation == "]":
            current = current[:-1]
        elif operation == "D":
            position = decode_rule_position(_rule_arg(rule, index, operation))
            index += 1
            if position < len(current):
                current = current[:position] + current[position + 1 :]
        elif operation in {"x", "O"}:
            start = decode_rule_position(_rule_arg(rule, index, operation))
            length = decode_rule_position(_rule_arg(rule, index + 1, operation))
            index += 2
            if operation == "x":
                current = current[start : start + length]
            else:
                current = current[:start] + current[start + length :]
        elif operation == "'":
            length = decode_rule_position(_rule_arg(rule, index, operation))
            index += 1
            current = current[:length]
        elif operation in {"i", "o"}:
            position = decode_rule_position(_rule_arg(rule, index, operation))
            value = _rule_arg(rule, index + 1, operation)
            index += 2
            if operation == "i":
                _check_length(len(current) + 1, max_length, "Hashcat operation 'i'")
                position = min(position, len(current))
                current = current[:position] + value + current[position:]
            elif position < len(current):
                current = current[:position] + value + current[position + 1 :]
        elif operation == "s":
            old = _rule_arg(rule, index, operation)
            new = _rule_arg(rule, index + 1, operation)
            index += 2
            current = current.replace(old, new)
        elif operation == "@":
            value = _rule_arg(rule, index, operation)
            index += 1
            current = current.replace(value, "")
        elif operation == "k":
            current = _swap_at(current, 0, 1)
        elif operation == "K":
            if len(current) >= 2:
                current = _swap_at(current, len(current) - 2, len(current) - 1)
        elif operation == "*":
            left = decode_rule_position(_rule_arg(rule, index, operation))
            right = decode_rule_position(_rule_arg(rule, index + 1, operation))
            index += 2
            current = _swap_at(current, left, right)
        elif operation == "q":
            _check_length(len(current) * 2, max_length, "Hashcat operation 'q'")
            current = "".join(char * 2 for char in current)
        elif operation in {"z", "Z", "y", "Y"}:
            count = decode_rule_position(_rule_arg(rule, index, operation))
            index += 1
            if operation == "z":
                _check_length(
                    len(current) + (count if current else 0),
                    max_length,
                    "Hashcat operation 'z'",
                )
                current = current[:1] * count + current
            elif operation == "Z":
                _check_length(
                    len(current) + (count if current else 0),
                    max_length,
                    "Hashcat operation 'Z'",
                )
                current += current[-1:] * count
            elif operation == "y":
                _check_length(
                    len(current) + min(count, len(current)),
                    max_length,
                    "Hashcat operation 'y'",
                )
                current = current[:count] + current
            elif count:
                _check_length(
                    len(current) + min(count, len(current)),
                    max_length,
                    "Hashcat operation 'Y'",
                )
                current += current[-count:]
        elif operation == "E":
            current = current.title()
        else:
            raise ConfigError(f"Unsupported hashcat rule operation: {operation!r}")
        _check_length(len(current), max_length, f"Hashcat operation {operation!r}")
    return current


def _apply_custom(
    word: str,
    rule: dict[str, Any],
    *,
    max_length: int,
) -> str:
    action = str(rule["type"])
    if action == "append":
        value = str(rule["value"])
        _check_length(len(word) + len(value), max_length, "append mutation")
        return word + value
    if action == "prepend":
        value = str(rule["value"])
        _check_length(len(word) + len(value), max_length, "prepend mutation")
        return value + word
    if action == "replace":
        old = str(rule["from"])
        new = str(rule["to"])
        projected = len(word) + word.count(old) * (len(new) - len(old))
        _check_length(projected, max_length, "replace mutation")
        return word.replace(old, new)
    if action in {"uppercase", "uppercase_all"}:
        return word.upper()
    if action in {"lowercase", "lowercase_all"}:
        return word.lower()
    if action == "capitalize_first":
        return word[:1].upper() + word[1:]
    if action == "reverse":
        return word[::-1]
    if action == "ru_to_eng":
        return ru_to_eng_layout(word)
    if action == "url_encode_specials":
        projected = sum(
            1 if char.isalnum() else len(char.encode("utf-8")) * 3
            for char in word
        )
        _check_length(projected, max_length, "url_encode_specials mutation")
        return url_encode_specials(word)
    if action == "base64_encode":
        encoded = word.encode("utf-8")
        projected = 4 * ((len(encoded) + 2) // 3)
        _check_length(projected, max_length, "base64_encode mutation")
        return base64.b64encode(encoded).decode("ascii")
    raise ConfigError(f"Unsupported custom mutation type: {action}")


def apply_operation(
    word: str,
    operation: MutationOperation,
    *,
    max_length: int = MAX_CANDIDATE_LENGTH,
) -> str:
    try:
        _check_length(len(word), max_length, "Mutation input")
        if operation.kind == "hashcat":
            result = apply_hashcat_rule(
                word,
                str(operation.value),
                max_length=max_length,
            )
        elif operation.kind == "custom":
            result = _apply_custom(
                word,
                dict(operation.value),
                max_length=max_length,
            )
        else:
            raise ConfigError(
                f"Unknown mutation operation kind at {operation.source}: {operation.kind}"
            )
        _check_length(len(result), max_length, "Mutation result")
        return result
    except ConfigError as exc:
        raise ConfigError(f"Invalid mutation at {operation.source}: {exc}") from exc


def validate_operation(operation: MutationOperation) -> None:
    """Validate syntax without assuming an arbitrary real candidate length."""

    if operation.kind == "hashcat":
        try:
            apply_hashcat_rule("", str(operation.value))
        except ConfigError as exc:
            raise ConfigError(f"Invalid mutation at {operation.source}: {exc}") from exc
        return
    if operation.kind == "custom":
        try:
            _apply_custom("", dict(operation.value), max_length=MAX_CANDIDATE_LENGTH)
        except (KeyError, TypeError, ConfigError) as exc:
            raise ConfigError(f"Invalid mutation at {operation.source}: {exc}") from exc
        return
    raise ConfigError(
        f"Unknown mutation operation kind at {operation.source}: {operation.kind}"
    )


def mutation_effect_kind(operation: MutationOperation) -> str:
    """Classify whether an operation can be counted without candidate expansion."""

    if operation.kind == "hashcat":
        rule = str(operation.value)
        if all(character.isspace() or character == ":" for character in rule):
            return EFFECT_NEVER
        return EFFECT_UNKNOWN
    if operation.kind != "custom":
        return EFFECT_UNKNOWN

    rule = dict(operation.value)
    action = str(rule.get("type", ""))
    if action in {"append", "prepend"}:
        return EFFECT_NEVER if str(rule.get("value", "")) == "" else EFFECT_ALWAYS
    if action == "replace":
        return (
            EFFECT_NEVER
            if str(rule.get("from", "")) == str(rule.get("to", ""))
            else EFFECT_UNKNOWN
        )
    if action in {"uppercase", "uppercase_all"}:
        return EFFECT_UPPERCASE
    if action in {"lowercase", "lowercase_all"}:
        return EFFECT_LOWERCASE
    if action == "capitalize_first":
        return EFFECT_CAPITALIZE_FIRST
    if action == "ru_to_eng":
        return EFFECT_RU_TO_ENG
    if action == "url_encode_specials":
        return EFFECT_URL_ENCODE_SPECIALS
    return EFFECT_UNKNOWN


def value_is_unchanged_for_effect(value: str, effect: str) -> bool:
    """Return exact no-op status for a planner-supported mutation effect."""

    if effect == EFFECT_UPPERCASE:
        return value.upper() == value
    if effect == EFFECT_LOWERCASE:
        return value.lower() == value
    if effect == EFFECT_CAPITALIZE_FIRST:
        return value[:1].upper() == value[:1]
    if effect == EFFECT_RU_TO_ENG:
        return ru_to_eng_layout(value) == value
    if effect == EFFECT_URL_ENCODE_SPECIALS:
        return all(
            character.isalnum() or character in "_.-~"
            for character in value
        )
    raise ValueError(f"Effect does not support invariant analysis: {effect}")


class MutationEngine:
    def __init__(
        self,
        config: MutationConfig,
        *,
        max_candidate_length: int = MAX_CANDIDATE_LENGTH,
    ):
        self.config = config
        self.max_candidate_length = max_candidate_length
        for operation in config.operations:
            validate_operation(operation)

    def estimate_factor(self) -> int:
        if self.config.mode == "independent":
            return len(self.config.operations) + int(self.config.include_original)
        final_variant = int(bool(self.config.operations))
        return final_variant + int(self.config.include_original)

    def mutate(self, word: str) -> Iterator[str]:
        _check_length(len(word), self.max_candidate_length, "Mutation input")
        if self.config.mode == "independent":
            if self.config.include_original:
                yield word
            for operation in self.config.operations:
                result = apply_operation(
                    word,
                    operation,
                    max_length=self.max_candidate_length,
                )
                if result != word:
                    yield result
            return

        if self.config.mode != "chained":
            raise ConfigError(f"Unknown mutation mode: {self.config.mode}")
        if self.config.include_original:
            yield word
        current = word
        for operation in self.config.operations:
            current = apply_operation(
                current,
                operation,
                max_length=self.max_candidate_length,
            )
        if self.config.operations and current != word:
            yield current
