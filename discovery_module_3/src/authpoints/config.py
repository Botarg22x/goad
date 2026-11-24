from __future__ import annotations

from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .normalize import normalize_hostname


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)
MAX_USER_AGENT_LENGTH = 512


def validate_browser_resource_domain(value: str) -> str:
    """Validate one exact asset host without granting navigation scope."""
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("resource domain must not contain control characters")
    host = value.strip()
    if not host or any(character in host for character in "/\\:@?#*"):
        raise ValueError("resource domain must be one hostname without a scheme, port or path")
    return normalize_hostname(host)


def validate_user_agent(value: str) -> str:
    user_agent = value.strip()
    if not user_agent:
        raise ValueError("User-Agent must not be empty")
    if len(user_agent) > MAX_USER_AGENT_LENGTH:
        raise ValueError(
            f"User-Agent must not be longer than {MAX_USER_AGENT_LENGTH} characters"
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in user_agent):
        raise ValueError("User-Agent must not contain control characters")
    return user_agent


def validate_proxy_url(value: str) -> str:
    proxy = value.strip()
    if not proxy:
        return ""
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in proxy):
        raise ValueError("proxy URL must not contain control characters")
    if "://" not in proxy:
        proxy = "http://" + proxy
    try:
        parts = urlsplit(proxy)
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid proxy URL: {exc}") from exc
    if parts.scheme.lower() != "http":
        raise ValueError("proxy must use the http scheme")
    if not parts.hostname or port is None:
        raise ValueError("proxy must contain a host and an explicit port")
    if parts.username is not None or parts.password is not None:
        raise ValueError("proxy credentials are not accepted on the command line")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError("proxy URL must not contain a path, query, or fragment")
    host = parts.hostname.lower().rstrip(".")
    authority = f"[{host}]" if ":" in host else host
    return f"http://{authority}:{port}"


@dataclass(slots=True)
class NmapConfig:
    executable: str = "nmap"
    version_db: str = ""
    enabled: bool = True
    timeout_seconds: int = 900
    top_ports: int = 1000
    all_ports: bool = False
    timing_template: int = 3
    udp_enabled: bool = False


@dataclass(slots=True)
class KatanaConfig:
    executable: str = "katana"
    chrome_executable: str = ""
    enabled: bool = True
    timeout_seconds: int = 240
    depth: int = 2
    crawl_duration: str = "2m"
    request_timeout_seconds: int = 10
    concurrency: int = 5
    parallelism: int = 2
    rate_limit_per_second: int = 10
    max_domain_pages: int = 250
    max_total_pages: int | None = None
    max_response_bytes: int = 256 * 1024
    max_dom_bytes: int = 2 * 1024 * 1024
    js_crawl: bool = False
    headless: bool = False
    auto_headless: bool = False
    auto_headless_timeout_seconds: int = 60
    page_load_strategy: str = "domcontentloaded"
    dom_wait_seconds: int = 5
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str = ""
    ca_cert: str = ""
    browser_resource_domains: tuple[str, ...] = ()
    browser_diagnostics_dir: str = ""


@dataclass(slots=True)
class HttpConfig:
    enabled: bool = True
    timeout_seconds: int = 10
    concurrency: int = 5
    request_delay_seconds: float = 0.0
    max_response_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 5
    user_agent: str = DEFAULT_USER_AGENT
    proxy: str = ""
    ca_cert: str = ""


@dataclass(slots=True)
class SubfinderConfig:
    executable: str = "subfinder"
    enabled: bool = False
    timeout_seconds: int = 120
    rate_limit_per_second: int = 10
    max_results: int = 100
    all_sources: bool = False
    proxy: str = ""


@dataclass(slots=True)
class ScanConfig:
    speed_profile: str = "normal"
    include_subdomains: bool = False
    page_only: bool = False
    standard_paths: list[str] = field(default_factory=list)
    login_templates: tuple[str, ...] = ()
    nmap: NmapConfig = field(default_factory=NmapConfig)
    subfinder: SubfinderConfig = field(default_factory=SubfinderConfig)
    katana: KatanaConfig = field(default_factory=KatanaConfig)
    http: HttpConfig = field(default_factory=HttpConfig)

    def public_dict(self) -> dict[str, object]:
        return asdict(self)
