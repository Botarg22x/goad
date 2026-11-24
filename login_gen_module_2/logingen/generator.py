from __future__ import annotations

from collections.abc import Iterable

from . import defaults
from .masks import expand_masked_value
from .models import AppConfig, GenerationResult, GenerationStats, Person
from .patterns import expand_pattern, pattern_tokens
from .translit import normalize_login, transliterate_variants


VALID_OUTPUT_KINDS = {"login", "email", "both"}
FIRSTNAME_TOKENS = frozenset(
    {"f", "f1", "f2", "f3", "firstname", "firstname1", "firstname2", "firstname3", "first", "name"}
)
LASTNAME_TOKENS = frozenset(
    {"l", "l1", "l2", "l3", "lastname", "lastname1", "lastname2", "lastname3", "surname", "secondname"}
)
PATRONYMIC_TOKENS = frozenset({"p", "p1", "p2", "p3", "patronymic", "patronymic1", "patronymic2", "patronymic3", "middlename"})
CANDIDATE_FORMAT_TOKENS = frozenset(
    {"login", "mail", "email", "mail_domain", "domain", "ad_domain", "netbios", "company"}
)
MAIL_FORMAT_TOKENS = frozenset({"mail", "email", "mail_domain", "domain"})


def generate(config: AppConfig) -> GenerationResult:
    warnings: list[str] = []
    if config.mode not in {"manual", "auto"}:
        warnings.append(f"Mode '{config.mode}' is not implemented in this module; using manual generation.")

    candidate_formats = config.generation.candidate_formats
    output_kind = config.output.kind
    if output_kind not in VALID_OUTPUT_KINDS:
        warnings.append(f"Unknown output kind '{output_kind}', using 'both'.")
        output_kind = "both"

    people, fio_warnings = _usable_people(config.people, config.patterns.person)
    warnings.extend(fio_warnings)
    if not people and config.generation.use_default_people_when_empty:
        people = defaults.fallback_people()
        warnings.append("No people in config; popular name-list fallback was used.")

    domains = tuple(_normalize_domains(config.domains))
    if not candidate_formats and output_kind == "email" and not domains:
        warnings.append("Output kind is 'email', but no domains are configured.")

    emitted: list[str] = []
    seen: set[str] = set()
    duplicate_count = 0

    for person in people:
        local_candidates = _generate_person_local_candidates(person, config, warnings)
        if config.limits.per_person is not None:
            local_candidates = local_candidates[: config.limits.per_person]
        for candidate in _expand_final_candidates(local_candidates, output_kind, domains, config, warnings):
            duplicate_count += _append_unique(candidate, emitted, seen)
            if _is_total_limit_reached(config, emitted):
                return _result(config, emitted, duplicate_count, warnings, people)

    technical_words_count = 0
    if config.generation.include_technical_words:
        technical_words = tuple(_usable_words(config.technical_words))
        technical_words_count = len(technical_words)
        for local_candidate in _generate_technical_local_candidates(technical_words, config, warnings):
            for candidate in _expand_final_candidates((local_candidate,), output_kind, domains, config, warnings):
                duplicate_count += _append_unique(candidate, emitted, seen)
                if _is_total_limit_reached(config, emitted):
                    return _result(config, emitted, duplicate_count, warnings, people, technical_words_count)

    return _result(config, emitted, duplicate_count, warnings, people, technical_words_count)


def _result(
    config: AppConfig,
    emitted: list[str],
    duplicate_count: int,
    warnings: list[str],
    people: tuple[Person, ...],
    technical_words_count: int | None = None,
) -> GenerationResult:
    if technical_words_count is None:
        technical_words_count = len(tuple(_usable_words(config.technical_words))) if config.generation.include_technical_words else 0
    return GenerationResult(
        candidates=tuple(emitted),
        stats=GenerationStats(
            people_count=len(people),
            technical_words_count=technical_words_count,
            emitted_count=len(emitted),
            duplicate_count=duplicate_count,
            warnings=tuple(dict.fromkeys(warnings)),
        ),
    )


def _generate_person_local_candidates(
    person: Person,
    config: AppConfig,
    warnings: list[str],
) -> tuple[str, ...]:
    context = _person_context(person, config)
    candidates: list[str] = []
    if not person.patronymic and any(_pattern_uses_patronymic(pattern) for pattern in config.patterns.person):
        warnings.append(
            f"Person '{_person_display(person)}' has no patronymic, but selected patterns require it; "
            "popular patronymics fallback was used for patronymic pattern variables."
        )
    for pattern in config.patterns.person:
        try:
            expanded = expand_pattern(pattern, context, case=config.generation.case, normalize_result=False)
        except KeyError as error:
            warnings.append(f"Pattern '{pattern}' uses unknown variable '{error.args[0]}'.")
            continue
        for raw_candidate in expanded:
            for candidate in _expand_masked_local_candidate(raw_candidate, pattern, config, warnings):
                if candidate and candidate not in candidates:
                    candidates.append(candidate)
    return tuple(candidates)


def _expand_masked_local_candidate(
    value: str,
    pattern: str,
    config: AppConfig,
    warnings: list[str],
) -> tuple[str, ...]:
    result = expand_masked_value(
        value,
        config.generation.custom_charsets,
        config.generation.max_mask_expansions_per_pattern,
    )
    if result.missing_custom_charsets:
        missing = ", ".join(f"?{token}" for token in result.missing_custom_charsets)
        warnings.append(f"Pattern '{pattern}' uses custom charset {missing}, but it is empty.")
        return ()
    if result.unknown_tokens:
        unknown = ", ".join(f"?{token}" for token in result.unknown_tokens)
        warnings.append(f"Pattern '{pattern}' uses unknown mask token {unknown}.")
        return ()
    if result.truncated:
        warnings.append(
            f"Mask pattern '{pattern}' expands to {result.total_count} variants; "
            f"limited to {config.generation.max_mask_expansions_per_pattern}."
        )
    candidates: list[str] = []
    for expanded in result.values:
        candidate = normalize_login(expanded, case=config.generation.case)
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return tuple(candidates)


def _generate_technical_local_candidates(
    words: tuple[str, ...],
    config: AppConfig,
    warnings: list[str],
) -> tuple[str, ...]:
    candidates: list[str] = []
    company = _company_variants(config)
    context_base = {
        "company": company,
        "separator": config.generation.separator,
        "domain": config.domains[0] if config.domains else "",
    }
    for word in words:
        context = dict(context_base)
        context["word"] = normalize_login(word, case=config.generation.case)
        for pattern in config.patterns.technical:
            try:
                expanded = expand_pattern(pattern, context, case=config.generation.case, normalize_result=False)
            except KeyError as error:
                warnings.append(f"Technical pattern '{pattern}' uses unknown variable '{error.args[0]}'.")
                continue
            for raw_candidate in expanded:
                for candidate in _expand_masked_local_candidate(raw_candidate, pattern, config, warnings):
                    if candidate and candidate not in candidates:
                        candidates.append(candidate)
    return tuple(candidates)


def _person_context(person: Person, config: AppConfig) -> dict[str, tuple[str, ...] | str]:
    max_variants = config.generation.max_translit_variants_per_field
    firstname = transliterate_variants(person.firstname, config.transliteration, max_variants)
    lastname = transliterate_variants(person.lastname, config.transliteration, max_variants)
    if person.patronymic:
        patronymic = transliterate_variants(person.patronymic, config.transliteration, max_variants)
    else:
        patronymic = _fallback_patronymic_variants(config, max_variants)
    company = _company_variants(config)

    context: dict[str, tuple[str, ...] | str] = {
        "firstname": firstname,
        "first": firstname,
        "name": firstname,
        "lastname": lastname,
        "surname": lastname,
        "secondname": lastname,
        "patronymic": patronymic,
        "middlename": patronymic,
        "company": company,
        "separator": config.generation.separator,
        "domain": config.domains[0] if config.domains else "",
    }

    _add_short_forms(context, firstname, "f", "firstname")
    _add_short_forms(context, lastname, "l", "lastname")
    _add_short_forms(context, patronymic, "p", "patronymic")
    return context


def _add_short_forms(
    context: dict[str, tuple[str, ...] | str],
    values: tuple[str, ...],
    short_prefix: str,
    full_prefix: str,
) -> None:
    for length in range(1, 4):
        context[f"{short_prefix}{length}"] = tuple(value[:length] for value in values)
        context[f"{full_prefix}{length}"] = tuple(value[:length] for value in values)
    context[short_prefix] = context[f"{short_prefix}1"]


def _company_variants(config: AppConfig) -> tuple[str, ...]:
    if not config.company:
        return ("",)
    return transliterate_variants(
        config.company,
        config.transliteration,
        config.generation.max_translit_variants_per_field,
    )


def _fallback_patronymic_variants(config: AppConfig, max_variants: int) -> tuple[str, ...]:
    return _transliterate_values(defaults.popular_patronymics(), config, max_variants) or ("",)


def _transliterate_values(values: Iterable[str], config: AppConfig, max_variants: int) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        for variant in transliterate_variants(value, config.transliteration, max_variants):
            if variant and variant not in normalized:
                normalized.append(variant)
    return tuple(normalized)


def _pattern_uses_patronymic(pattern: str) -> bool:
    return any(token in PATRONYMIC_TOKENS for token in pattern_tokens(pattern))


def _required_person_parts(patterns: tuple[str, ...]) -> frozenset[str]:
    required: set[str] = set()
    for pattern in patterns:
        tokens = set(pattern_tokens(pattern))
        if tokens & FIRSTNAME_TOKENS:
            required.add("firstname")
        if tokens & LASTNAME_TOKENS:
            required.add("lastname")
        if tokens & PATRONYMIC_TOKENS:
            required.add("patronymic")
    return frozenset(required)


def _expand_output_kind(
    local_candidates: Iterable[str],
    kind: str,
    domains: tuple[str, ...],
) -> tuple[str, ...]:
    emitted: list[str] = []
    for local_candidate in local_candidates:
        if kind in {"login", "both"}:
            emitted.append(local_candidate)
        if kind in {"email", "both"}:
            emitted.extend(f"{local_candidate}@{domain}" for domain in domains)
    return tuple(emitted)


def _expand_final_candidates(
    local_candidates: Iterable[str],
    kind: str,
    domains: tuple[str, ...],
    config: AppConfig,
    warnings: list[str],
) -> tuple[str, ...]:
    if not config.generation.candidate_formats:
        return _expand_output_kind(local_candidates, kind, domains)

    emitted: list[str] = []
    for local_candidate in local_candidates:
        for candidate in _expand_candidate_formats(local_candidate, config.generation.candidate_formats, domains, config, warnings):
            if candidate and candidate not in emitted:
                emitted.append(candidate)
    return tuple(emitted)


def _expand_candidate_formats(
    login: str,
    formats: tuple[str, ...],
    domains: tuple[str, ...],
    config: AppConfig,
    warnings: list[str],
) -> tuple[str, ...]:
    emitted: list[str] = []
    company = _first_value(_company_variants(config))
    netbios = _netbios_value(config, company)
    ad_domain = config.generation.ad_domain.strip().lower()

    for candidate_format in formats:
        tokens = pattern_tokens(candidate_format)
        unknown = tuple(token for token in tokens if token not in CANDIDATE_FORMAT_TOKENS)
        if unknown:
            warnings.append(f"Candidate format '{candidate_format}' uses unknown variable '{unknown[0]}'.")
            continue
        if tokens and any(token in MAIL_FORMAT_TOKENS for token in tokens) and not domains:
            warnings.append(f"Candidate format '{candidate_format}' needs a mail domain, but no domains are configured.")
            continue
        if "ad_domain" in tokens and not ad_domain:
            warnings.append(f"Candidate format '{candidate_format}' needs ad_domain, but it is not configured.")
            continue
        if "netbios" in tokens and not netbios:
            warnings.append(f"Candidate format '{candidate_format}' needs netbios, but it is not configured.")
            continue

        context: dict[str, tuple[str, ...] | str] = {
            "login": login,
            "mail": tuple(f"{login}@{domain}" for domain in domains),
            "email": tuple(f"{login}@{domain}" for domain in domains),
            "mail_domain": domains,
            "domain": domains,
            "ad_domain": ad_domain,
            "netbios": netbios,
            "company": company,
        }
        try:
            expanded = expand_pattern(candidate_format, context, case=config.generation.case, normalize_result=False)
        except KeyError as error:
            warnings.append(f"Candidate format '{candidate_format}' uses unknown variable '{error.args[0]}'.")
            continue
        for candidate in expanded:
            candidate = candidate.strip()
            if candidate and candidate not in emitted:
                emitted.append(candidate)
    return tuple(emitted)


def _first_value(values: tuple[str, ...]) -> str:
    return values[0] if values else ""


def _netbios_value(config: AppConfig, company: str) -> str:
    configured = config.generation.netbios.strip().upper()
    if configured:
        return configured
    return "".join(char for char in company.upper() if char.isalnum())[:15]


def _append_unique(candidate: str, emitted: list[str], seen: set[str]) -> int:
    if candidate in seen:
        return 1
    seen.add(candidate)
    emitted.append(candidate)
    return 0


def _is_total_limit_reached(config: AppConfig, emitted: list[str]) -> bool:
    return config.limits.total is not None and len(emitted) >= config.limits.total


def _usable_people(people: Iterable[Person], patterns: tuple[str, ...]) -> tuple[tuple[Person, ...], tuple[str, ...]]:
    required = _required_person_parts(patterns)
    usable: list[Person] = []
    warnings: list[str] = []
    for person in people:
        missing = []
        if "firstname" in required and not person.firstname:
            missing.append("firstname")
        if "lastname" in required and not person.lastname:
            missing.append("lastname")
        if missing:
            warnings.append(
                f"Person '{_person_display(person)}' is missing {', '.join(missing)}, "
                "but selected patterns require it; skipped this person."
            )
            continue
        if person.firstname or person.lastname or person.patronymic:
            usable.append(person)
    return tuple(usable), tuple(warnings)


def _person_display(person: Person) -> str:
    return " ".join(part for part in (person.lastname, person.firstname, person.patronymic) if part) or "<empty>"


def _usable_words(words: Iterable[str]) -> Iterable[str]:
    for word in words:
        normalized = normalize_login(str(word))
        if normalized:
            yield normalized


def _normalize_domains(domains: Iterable[str]) -> Iterable[str]:
    for domain in domains:
        normalized = str(domain).strip().lower()
        if normalized.startswith("@"):
            normalized = normalized[1:]
        if normalized:
            yield normalized
