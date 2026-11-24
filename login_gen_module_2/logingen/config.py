from __future__ import annotations

from pathlib import Path
from typing import Any

from . import defaults
from .models import (
    AppConfig,
    AutoConfig,
    GenerationConfig,
    LimitsConfig,
    OutputConfig,
    PatternsConfig,
    Person,
    DEFAULT_USER_AGENT,
)


_LEGACY_DEFAULT_USER_AGENT = "logingen/0.1 authorized-public-audit"


EXAMPLE_CONFIG = """# Generation mode for the current module. Future OSINT collection should live
# in a separate authorized-audit module and feed people/patterns into this file.
mode: manual

company: example
domains:
  - example.ru

auto:
  enabled: false
  url: ""
  extra_urls: []
  # Empty means: allow only the host from auto.url.
  allowed_domains: []
  max_pages: 20
  max_depth: 1
  timeout_seconds: 10
  # Pause between top-level network requests. 0 disables pacing.
  request_delay_seconds: 0
  # Default interval between Yandex/Google search queries.
  search_delay_seconds: 10
  user_agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
  proxy_url: ""
  ca_cert: ""
  respect_robots_txt: true
  collect_emails: true
  collect_people: true
  browser_crawl: true
  browser_headless: true
  browser_manual_access: true
  browser_channel: ""
  browser_user_data_dir: output/browser_profile
  browser_timeout_seconds: 20
  browser_wait_ms: 1500
  captcha_wait_seconds: 300
  captcha_poll_seconds: 2
  browser_pages_dir: output/site_pages
  mail_from_url_path: output/mail_from_url.txt
  fio_path: output/fio.txt
  vedomosti_enabled: false
  setka_enabled: false
  search_enabled: false
  search_engines:
    - yandex
  search_dorks_path: dictionary/dorks
  search_results_dir: output/search_results
  pdf_enabled: true
  pdf_files_dir: output/pdf
  pdf_max_files: 20
  found_emails_path: output/found_emails.txt
  email_sources_path: output/email_sources.csv
  log_path: output/auto.log

output:
  path: output/logins.txt
  # login, email, or both
  kind: both

limits:
  total: 1000
  per_person: 25

generation:
  use_default_people_when_empty: true
  include_technical_words: true
  case: lower
  separator: "."
  max_translit_variants_per_field: 16
  candidate_formats_path: dictionary/candidate_formats
  candidate_formats: []
  ad_domain: ""
  netbios: ""
  masks_path: dictionary/masks
  custom_charsets: {}
  max_mask_expansions_per_pattern: 1000

patterns:
  person:
    - "{f}.{lastname}"
    - "{firstname}.{lastname}"
    - "{lastname}.{firstname}"
    - "{lastname}.{f}"
    - "{f}{lastname}"
    - "{lastname}{f}"
    - "{firstname}_{lastname}"
    - "{lastname}_{firstname}"
    - "{lastname}.{f2}"
    - "{f2}.{lastname}"
    - "{f3}.{lastname}"
  technical:
    - "{word}"
    - "{word}.{company}"
    - "{company}.{word}"

people: []

technical_words_path: dictionary/technical_words

transliteration:
  а: a
  б: b
  в: v
  г: g
  д: d
  е: e
  ё: [e, yo]
  ж: [zh, j]
  з: z
  и: i
  й: [y, i]
  к: k
  л: l
  м: m
  н: n
  о: o
  п: p
  р: r
  с: s
  т: t
  у: u
  ф: f
  х: [kh, h]
  ц: [ts, c]
  ч: [ch, tch]
  ш: sh
  щ: [sch, shch]
  ъ: ""
  ы: [y, i]
  ь: ""
  э: e
  ю: [yu, iu]
  я: [ya, ia]
"""


def write_example_config(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(EXAMPLE_CONFIG, encoding="utf-8")


def load_config(path: Path) -> AppConfig:
    raw = _load_yaml(path)
    return config_from_dict(raw)


def config_from_dict(raw: dict[str, Any]) -> AppConfig:
    output_raw = _mapping(raw.get("output"))
    limits_raw = _mapping(raw.get("limits"))
    generation_raw = _mapping(raw.get("generation"))
    patterns_raw = _mapping(raw.get("patterns"))
    auto_raw = _mapping(raw.get("auto"))

    people = tuple(_parse_person(item) for item in _list(raw.get("people")))
    technical_words = _merge_unique(
        tuple(str(item).strip() for item in _list(raw.get("technical_words")) if str(item).strip()),
        _read_word_file(_optional_path(raw.get("technical_words_path"), None)),
    )
    masks = _merge_unique(
        tuple(str(item).strip() for item in _list(generation_raw.get("masks")) if str(item).strip()),
        _read_word_file(_optional_path(generation_raw.get("masks_path"), Path("dictionary/masks"))),
    )
    candidate_format_templates = _read_word_file(
        _optional_path(generation_raw.get("candidate_formats_path"), Path("dictionary/candidate_formats"))
    )
    search_dorks = _merge_unique(
        tuple(str(item).strip() for item in _list(auto_raw.get("search_dorks")) if str(item).strip()),
        _read_word_file(_optional_path(auto_raw.get("search_dorks_path"), Path("dictionary/dorks"))),
    )

    transliteration = dict(defaults.DEFAULT_TRANSLITERATION)
    transliteration.update(_parse_transliteration(_mapping(raw.get("transliteration"))))
    configured_user_agent = str(auto_raw.get("user_agent", DEFAULT_USER_AGENT)).strip()
    if configured_user_agent in {"", _LEGACY_DEFAULT_USER_AGENT}:
        configured_user_agent = DEFAULT_USER_AGENT

    return AppConfig(
        mode=str(raw.get("mode", "manual")).strip() or "manual",
        company=str(raw.get("company", "")).strip(),
        domains=tuple(str(item).strip().lower() for item in _list(raw.get("domains")) if str(item).strip()),
        output=OutputConfig(
            path=Path(str(output_raw.get("path", "output/logins.txt"))),
            kind=str(output_raw.get("kind", "both")).strip().lower() or "both",
        ),
        limits=LimitsConfig(
            total=_optional_positive_int(limits_raw.get("total"), 1000),
            per_person=_optional_positive_int(limits_raw.get("per_person"), 25),
        ),
        generation=GenerationConfig(
            use_default_people_when_empty=bool(generation_raw.get("use_default_people_when_empty", True)),
            include_technical_words=bool(generation_raw.get("include_technical_words", True)),
            case=str(generation_raw.get("case", "lower")).strip().lower() or "lower",
            separator=str(generation_raw.get("separator", ".")),
            max_translit_variants_per_field=_positive_int(
                generation_raw.get("max_translit_variants_per_field"),
                16,
            ),
            candidate_formats=tuple(
                str(item).strip() for item in _list(generation_raw.get("candidate_formats")) if str(item).strip()
            ),
            candidate_format_templates=candidate_format_templates,
            candidate_formats_path=_optional_path(
                generation_raw.get("candidate_formats_path"),
                Path("dictionary/candidate_formats"),
            ),
            ad_domain=str(generation_raw.get("ad_domain", "")).strip().lower(),
            netbios=str(generation_raw.get("netbios", "")).strip().upper(),
            masks=masks,
            masks_path=_optional_path(generation_raw.get("masks_path"), Path("dictionary/masks")),
            custom_charsets=_parse_custom_charsets(_mapping(generation_raw.get("custom_charsets"))),
            max_mask_expansions_per_pattern=_positive_int(
                generation_raw.get("max_mask_expansions_per_pattern"),
                1000,
            ),
        ),
        patterns=PatternsConfig(
            person=tuple(str(item) for item in _list(patterns_raw.get("person"))) or defaults.DEFAULT_PERSON_PATTERNS,
            technical=tuple(str(item) for item in _list(patterns_raw.get("technical"))) or defaults.DEFAULT_TECHNICAL_PATTERNS,
        ),
        auto=AutoConfig(
            enabled=bool(auto_raw.get("enabled", False)),
            url=str(auto_raw.get("url", "")).strip(),
            extra_urls=tuple(str(item).strip() for item in _list(auto_raw.get("extra_urls")) if str(item).strip()),
            allowed_domains=tuple(
                _normalize_domain_value(str(item))
                for item in _list(auto_raw.get("allowed_domains"))
                if str(item).strip()
            ),
            exact_hosts=bool(auto_raw.get("exact_hosts", False)),
            max_pages=_positive_int(auto_raw.get("max_pages"), 20),
            max_depth=_non_negative_int(auto_raw.get("max_depth"), 1),
            timeout_seconds=_positive_int(auto_raw.get("timeout_seconds"), 10),
            request_delay_seconds=_non_negative_float(
                auto_raw.get("request_delay_seconds"),
                0.0,
            ),
            search_delay_seconds=_non_negative_float(
                auto_raw.get("search_delay_seconds"),
                10.0,
            ),
            user_agent=configured_user_agent,
            proxy_url=str(auto_raw.get("proxy_url", "")).strip(),
            ca_cert=_optional_path(auto_raw.get("ca_cert"), None),
            respect_robots_txt=bool(auto_raw.get("respect_robots_txt", True)),
            collect_emails=bool(auto_raw.get("collect_emails", True)),
            collect_people=bool(auto_raw.get("collect_people", True)),
            browser_crawl=bool(auto_raw.get("browser_crawl", True)),
            browser_headless=bool(auto_raw.get("browser_headless", True)),
            browser_manual_access=bool(auto_raw.get("browser_manual_access", True)),
            browser_channel=str(auto_raw.get("browser_channel", "")).strip(),
            browser_user_data_dir=_optional_path(auto_raw.get("browser_user_data_dir"), Path("output/browser_profile")),
            browser_timeout_seconds=_positive_int(auto_raw.get("browser_timeout_seconds"), 20),
            browser_wait_ms=_non_negative_int(auto_raw.get("browser_wait_ms"), 1500),
            captcha_wait_seconds=_positive_int(auto_raw.get("captcha_wait_seconds"), 300),
            captcha_poll_seconds=_positive_int(auto_raw.get("captcha_poll_seconds"), 2),
            browser_pages_dir=Path(str(auto_raw.get("browser_pages_dir", "output/site_pages"))),
            mail_from_url_path=_optional_path(auto_raw.get("mail_from_url_path"), Path("output/mail_from_url.txt")),
            fio_path=_optional_path(auto_raw.get("fio_path"), Path("output/fio.txt")),
            vedomosti_enabled=bool(auto_raw.get("vedomosti_enabled", False)),
            setka_enabled=bool(auto_raw.get("setka_enabled", False)),
            search_enabled=bool(auto_raw.get("search_enabled", False)),
            search_engines=_parse_string_list(auto_raw.get("search_engines")) or ("yandex",),
            search_terms=tuple(str(item).strip() for item in _list(auto_raw.get("search_terms")) if str(item).strip()),
            search_dorks=search_dorks or defaults.DEFAULT_SEARCH_DORKS,
            search_dorks_path=_optional_path(auto_raw.get("search_dorks_path"), Path("dictionary/dorks")),
            search_results_dir=Path(str(auto_raw.get("search_results_dir", "output/search_results"))),
            search_fetch_enabled=bool(auto_raw.get("search_fetch_enabled", False)),
            pdf_enabled=bool(auto_raw.get("pdf_enabled", True)),
            pdf_files_dir=Path(str(auto_raw.get("pdf_files_dir", "output/pdf"))),
            pdf_max_files=_positive_int(auto_raw.get("pdf_max_files"), 20),
            found_emails_path=_optional_path(auto_raw.get("found_emails_path"), Path("output/found_emails.txt")),
            email_sources_path=_optional_path(auto_raw.get("email_sources_path"), Path("output/email_sources.csv")),
            log_path=_optional_path(auto_raw.get("log_path"), Path("output/auto.log")),
        ),
        people=people,
        technical_words=technical_words or defaults.DEFAULT_TECHNICAL_WORDS,
        transliteration=transliteration,
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        from .simple_yaml import load_yaml_file

        return load_yaml_file(path)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError("Root YAML value must be a mapping")
    return loaded


def _parse_person(value: Any) -> Person:
    if isinstance(value, dict):
        return Person(
            firstname=str(value.get("firstname") or value.get("first") or value.get("name") or "").strip(),
            lastname=str(value.get("lastname") or value.get("surname") or value.get("secondname") or "").strip(),
            patronymic=str(value.get("patronymic") or value.get("middlename") or "").strip(),
        )
    parts = [part.strip() for part in str(value).replace(",", ";").split(";")]
    if len(parts) == 1:
        name_parts = parts[0].split()
        if len(name_parts) >= 2:
            return Person(firstname=name_parts[1], lastname=name_parts[0], patronymic=name_parts[2] if len(name_parts) > 2 else "")
    return Person(
        firstname=parts[0] if len(parts) > 0 else "",
        lastname=parts[1] if len(parts) > 1 else "",
        patronymic=parts[2] if len(parts) > 2 else "",
    )


def _parse_transliteration(value: dict[str, Any]) -> dict[str, str | list[str]]:
    parsed: dict[str, str | list[str]] = {}
    for key, raw in value.items():
        normalized_key = str(key).strip().lower()
        if not normalized_key:
            continue
        if isinstance(raw, list):
            parsed[normalized_key] = [str(item) for item in raw]
        else:
            parsed[normalized_key] = "" if raw is None else str(raw)
    return parsed


def _parse_custom_charsets(value: dict[str, Any]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for key, raw in value.items():
        token = str(key).strip().removeprefix("?")
        if token in {"1", "2", "3", "4"}:
            parsed[token] = "" if raw is None else str(raw)
    return parsed


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _parse_string_list(value: Any) -> tuple[str, ...]:
    result: list[str] = []
    for item in _list(value):
        for part in str(item).replace(";", ",").split(","):
            normalized = part.strip().lower()
            if normalized and normalized not in result:
                result.append(normalized)
    return tuple(result)


def _read_word_file(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Technical words file not found: {path}")
    values: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#") and value not in values:
            values.append(value)
    return tuple(values)


def _merge_unique(*groups: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    for group in groups:
        for value in group:
            if value and value not in values:
                values.append(value)
    return tuple(values)


def _optional_positive_int(value: Any, default: int | None) -> int | None:
    if value is None or str(value).strip().lower() in {"", "none", "null"}:
        return default
    return _positive_int(value, default or 0)


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _non_negative_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _non_negative_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _optional_path(value: Any, default: Path | None) -> Path | None:
    if value is None:
        return default
    raw = str(value).strip()
    if raw.lower() in {"", "none", "null"}:
        return None
    return Path(raw)


def _normalize_domain_value(value: str) -> str:
    value = value.strip().lower()
    value = value.removeprefix("http://").removeprefix("https://")
    value = value.split("/", 1)[0]
    return value.lstrip("@")
