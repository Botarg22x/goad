from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class Person:
    firstname: str
    lastname: str
    patronymic: str = ""


@dataclass(frozen=True)
class OutputConfig:
    path: Path = Path("output/logins.txt")
    kind: str = "both"


@dataclass(frozen=True)
class LimitsConfig:
    total: int | None = 1000
    per_person: int | None = 25


@dataclass(frozen=True)
class GenerationConfig:
    use_default_people_when_empty: bool = True
    include_technical_words: bool = True
    case: str = "lower"
    separator: str = "."
    max_translit_variants_per_field: int = 16
    candidate_formats: tuple[str, ...] = field(default_factory=tuple)
    candidate_format_templates: tuple[str, ...] = field(default_factory=tuple)
    candidate_formats_path: Path | None = Path("dictionary/candidate_formats")
    ad_domain: str = ""
    netbios: str = ""
    masks: tuple[str, ...] = field(default_factory=tuple)
    masks_path: Path | None = Path("dictionary/masks")
    custom_charsets: dict[str, str] = field(default_factory=dict)
    max_mask_expansions_per_pattern: int = 1000


@dataclass(frozen=True)
class PatternsConfig:
    person: tuple[str, ...] = field(default_factory=tuple)
    technical: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class AutoConfig:
    enabled: bool = False
    site_crawler: str = "http"
    katana_executable: str = "katana"
    save_artifacts: bool = True
    url: str = ""
    extra_urls: tuple[str, ...] = field(default_factory=tuple)
    allowed_domains: tuple[str, ...] = field(default_factory=tuple)
    exact_hosts: bool = False
    max_pages: int = 20
    max_depth: int = 1
    timeout_seconds: int = 10
    request_delay_seconds: float = 0.0
    search_delay_seconds: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    proxy_url: str = ""
    ca_cert: Path | None = None
    respect_robots_txt: bool = True
    collect_emails: bool = True
    collect_people: bool = True
    browser_crawl: bool = True
    browser_headless: bool = True
    browser_manual_access: bool = True
    browser_channel: str = ""
    browser_user_data_dir: Path | None = Path("output/browser_profile")
    browser_timeout_seconds: int = 20
    browser_wait_ms: int = 1500
    captcha_wait_seconds: int = 300
    captcha_poll_seconds: int = 2
    browser_pages_dir: Path = Path("output/site_pages")
    mail_from_url_path: Path | None = Path("output/mail_from_url.txt")
    fio_path: Path | None = Path("output/fio.txt")
    vedomosti_enabled: bool = False
    setka_enabled: bool = False
    setka_max_pages: int | None = None
    search_enabled: bool = False
    search_engines: tuple[str, ...] = ("yandex",)
    search_terms: tuple[str, ...] = field(default_factory=tuple)
    search_dorks: tuple[str, ...] = field(default_factory=tuple)
    search_dorks_path: Path | None = Path("dictionary/dorks")
    search_results_dir: Path = Path("output/search_results")
    search_fetch_enabled: bool = False
    pdf_enabled: bool = True
    pdf_files_dir: Path = Path("output/pdf")
    pdf_max_files: int = 20
    document_types: tuple[str, ...] = ("pdf", "docx", "pptx", "xlsx", "odt", "odp", "ods", "txt", "csv")
    found_emails_path: Path | None = Path("output/found_emails.txt")
    email_sources_path: Path | None = Path("output/email_sources.csv")
    evidence_path: Path | None = Path("output/evidence.jsonl")
    log_path: Path | None = Path("output/auto.log")


@dataclass(frozen=True)
class AppConfig:
    mode: str = "manual"
    company: str = ""
    domains: tuple[str, ...] = field(default_factory=tuple)
    output: OutputConfig = field(default_factory=OutputConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    generation: GenerationConfig = field(default_factory=GenerationConfig)
    patterns: PatternsConfig = field(default_factory=PatternsConfig)
    auto: AutoConfig = field(default_factory=AutoConfig)
    people: tuple[Person, ...] = field(default_factory=tuple)
    technical_words: tuple[str, ...] = field(default_factory=tuple)
    transliteration: dict[str, str | list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class GenerationStats:
    people_count: int = 0
    technical_words_count: int = 0
    emitted_count: int = 0
    duplicate_count: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GenerationResult:
    candidates: tuple[str, ...]
    stats: GenerationStats
