from __future__ import annotations

from dataclasses import dataclass
import re

from . import defaults
from .generator import _person_context
from .models import AppConfig, Person
from .patterns import expand_pattern, pattern_tokens
from .translit import normalize_login


INFERENCE_EXTRA_PERSON_PATTERNS: tuple[str, ...] = (
    "{lastname}",
    "{firstname}",
    "{lastname}_{f}",
    "{lastname}.{f}",
    "{lastname}-{f}",
    "{lastname}_{f2}",
    "{lastname}.{f2}",
    "{lastname}-{f2}",
    "{lastname}_{f3}",
    "{lastname}.{f3}",
    "{lastname}-{f3}",
    "{f}_{lastname}",
    "{f}.{lastname}",
    "{f}-{lastname}",
    "{f2}_{lastname}",
    "{f2}.{lastname}",
    "{f2}-{lastname}",
    "{f3}_{lastname}",
    "{f3}.{lastname}",
    "{f3}-{lastname}",
    "{lastname}_{f}{p}",
    "{lastname}.{f}{p}",
    "{lastname}-{f}{p}",
    "{lastname}_{f}_{p}",
    "{lastname}.{f}.{p}",
    "{lastname}-{f}-{p}",
    "{lastname}{f}{p}",
    "{lastname}{f}",
    "{f}{p}_{lastname}",
    "{f}_{p}_{lastname}",
    "{f}{p}.{lastname}",
    "{f}.{p}.{lastname}",
)


@dataclass(frozen=True)
class PatternInference:
    pattern: str
    matched_count: int
    examples: tuple[str, ...]
    source: str = "person"


def infer_person_patterns(
    emails: tuple[str, ...],
    people: tuple[Person, ...],
    config: AppConfig,
    max_patterns: int = 5,
) -> tuple[str, ...]:
    candidates = infer_person_pattern_candidates(
        emails,
        people,
        config,
        max_patterns=max_patterns,
    )
    exact_candidates = tuple(candidate for candidate in candidates if candidate.source == "person")
    selected = exact_candidates or candidates
    return tuple(candidate.pattern for candidate in selected)


def infer_person_pattern_candidates(
    emails: tuple[str, ...],
    people: tuple[Person, ...],
    config: AppConfig,
    max_patterns: int = 8,
) -> tuple[PatternInference, ...]:
    local_parts = _email_local_parts(emails, config)
    if not local_parts:
        return ()

    exact_matches = _infer_exact_person_pattern_matches(local_parts, people, config)
    structural_matches = _infer_structural_pattern_matches(local_parts, config)

    merged: dict[str, PatternInference] = {}
    for candidate in (*exact_matches, *structural_matches):
        existing = merged.get(candidate.pattern)
        if existing is None:
            merged[candidate.pattern] = candidate
            continue
        examples = tuple(dict.fromkeys((*existing.examples, *candidate.examples)))[:5]
        merged[candidate.pattern] = PatternInference(
            pattern=candidate.pattern,
            matched_count=max(existing.matched_count, candidate.matched_count),
            examples=examples,
            source=existing.source if existing.source == "person" else candidate.source,
        )

    ordered = sorted(
        merged.values(),
        key=lambda item: (
            item.source != "person",
            -item.matched_count,
            _candidate_pattern_index(item.pattern, config),
            item.pattern,
        ),
    )
    return tuple(ordered[:max_patterns])


def _infer_exact_person_pattern_matches(
    local_parts: tuple[str, ...],
    people: tuple[Person, ...],
    config: AppConfig,
) -> tuple[PatternInference, ...]:
    if not people:
        return ()

    matches: dict[str, list[str]] = {}
    for person in people:
        context = _person_context(person, config)
        for pattern in _candidate_person_patterns(config):
            if not person.patronymic and _pattern_uses_patronymic(pattern):
                continue
            try:
                candidates = expand_pattern(pattern, context, case=config.generation.case)
            except KeyError:
                continue
            for candidate in candidates:
                if candidate in local_parts:
                    matches.setdefault(pattern, [])
                    if candidate not in matches[pattern]:
                        matches[pattern].append(candidate)

    return tuple(
        PatternInference(
            pattern=pattern,
            matched_count=len(examples),
            examples=tuple(examples[:5]),
            source="person",
        )
        for pattern, examples in matches.items()
    )


def _infer_structural_pattern_matches(
    local_parts: tuple[str, ...],
    config: AppConfig,
) -> tuple[PatternInference, ...]:
    matches: dict[str, list[str]] = {}
    for local in local_parts:
        if _should_skip_structural_local(local, config):
            continue
        for pattern in _structural_patterns_for_local(local):
            matches.setdefault(pattern, [])
            if local not in matches[pattern]:
                matches[pattern].append(local)

    return tuple(
        PatternInference(
            pattern=pattern,
            matched_count=len(examples),
            examples=tuple(examples[:5]),
            source="structure",
        )
        for pattern, examples in matches.items()
    )


def _email_local_parts(emails: tuple[str, ...], config: AppConfig) -> tuple[str, ...]:
    local_parts: list[str] = []
    for email in emails:
        if "@" not in email:
            continue
        local = normalize_login(email.rsplit("@", 1)[0], case=config.generation.case)
        if local and local not in local_parts:
            local_parts.append(local)
    return tuple(local_parts)


def _candidate_person_patterns(config: AppConfig) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*config.patterns.person, *defaults.DEFAULT_PERSON_PATTERNS, *INFERENCE_EXTRA_PERSON_PATTERNS)))


def _candidate_pattern_index(pattern: str, config: AppConfig) -> int:
    patterns = _candidate_person_patterns(config)
    try:
        return patterns.index(pattern)
    except ValueError:
        return len(patterns)


def _pattern_uses_patronymic(pattern: str) -> bool:
    return any(token in {"p", "p1", "p2", "p3", "patronymic", "middlename"} for token in pattern_tokens(pattern))


def _should_skip_structural_local(local: str, config: AppConfig) -> bool:
    role_terms = set(defaults.DEFAULT_CONTACT_ROLE_TERMS)
    if len(local) <= 1 or local in role_terms:
        return True
    return local.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx"))


def _structural_patterns_for_local(local: str) -> tuple[str, ...]:
    patterns: list[str] = []
    for separator in ("_", ".", "-"):
        escaped = "\\" + separator if separator == "." else separator
        if _fullmatch(rf"[a-z]{{2,}}{escaped}[a-z]", local):
            patterns.append(f"{{lastname}}{separator}{{f}}")
        if _fullmatch(rf"[a-z]{{2,}}{escaped}[a-z]{{2}}", local):
            patterns.append(f"{{lastname}}{separator}{{f}}{{p}}")
        if _fullmatch(rf"[a-z]{{2,}}{escaped}[a-z]{escaped}[a-z]", local):
            patterns.append(f"{{lastname}}{separator}{{f}}{separator}{{p}}")
        if _fullmatch(rf"[a-z]{escaped}[a-z]{{2,}}", local):
            patterns.append(f"{{f}}{separator}{{lastname}}")
        if _fullmatch(rf"[a-z]{{2}}{escaped}[a-z]{{2,}}", local):
            patterns.append(f"{{f2}}{separator}{{lastname}}")
        if _fullmatch(rf"[a-z]{{3}}{escaped}[a-z]{{2,}}", local):
            patterns.append(f"{{f3}}{separator}{{lastname}}")
    return tuple(patterns)


def _fullmatch(pattern: str, value: str) -> bool:
    return re.fullmatch(pattern, value) is not None
