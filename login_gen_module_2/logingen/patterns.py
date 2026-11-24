from __future__ import annotations

import itertools
import re
from collections.abc import Mapping, Sequence

from .translit import normalize_login


TOKEN_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def pattern_tokens(pattern: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(TOKEN_RE.findall(pattern)))


def expand_pattern(
    pattern: str,
    context: Mapping[str, Sequence[str] | str],
    case: str = "lower",
    normalize_result: bool = True,
) -> tuple[str, ...]:
    tokens = pattern_tokens(pattern)
    if not tokens:
        return (normalize_login(pattern, case=case),) if normalize_result else (pattern,)

    values: list[tuple[str, ...]] = []
    for token in tokens:
        raw_value = context.get(token)
        if raw_value is None:
            raise KeyError(token)
        if isinstance(raw_value, str):
            values.append((raw_value,))
        else:
            values.append(tuple(str(item) for item in raw_value))

    expanded: list[str] = []
    for combination in itertools.product(*values):
        candidate = pattern
        for token, value in zip(tokens, combination, strict=True):
            candidate = candidate.replace("{" + token + "}", value)
        if normalize_result:
            candidate = normalize_login(candidate, case=case)
        if candidate and candidate not in expanded:
            expanded.append(candidate)
    return tuple(expanded)


def short_forms(value: str, prefix: str, max_len: int = 3) -> dict[str, str]:
    forms: dict[str, str] = {}
    for length in range(1, max_len + 1):
        forms[f"{prefix}{length}"] = value[:length]
    forms[prefix] = forms.get(f"{prefix}1", "")
    return forms
