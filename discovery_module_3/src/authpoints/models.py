from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _finding_id(kind: str, auth_type: str, endpoint: str) -> str:
    identity = f"{kind}\0{auth_type}\0{endpoint}".encode("utf-8")
    return "auth-" + hashlib.sha256(identity).hexdigest()[:16]


class Source(StrEnum):
    NMAP = "nmap"
    KATANA = "katana"
    URL_LIST = "url_list"
    HTTP_PROBE = "http_probe"


class FindingKind(StrEnum):
    WEB_LOGIN = "web_login_page"
    HTTP_AUTH = "http_auth_challenge"
    SSO = "sso_entry"
    NETWORK_SERVICE = "network_auth_surface"


@dataclass(slots=True)
class Evidence:
    rule_id: str
    group: str
    source: str
    detail: str


@dataclass(slots=True)
class FormField:
    name: str = ""
    field_type: str = "text"
    autocomplete: str = ""
    disabled: bool = False
    hidden: bool = False


@dataclass(slots=True)
class FormObservation:
    action: str = ""
    method: str = "get"
    fields: list[FormField] = field(default_factory=list)
    text: str = ""
    is_orphan: bool = False


@dataclass(slots=True)
class ServiceObservation:
    host: str
    port: int
    transport: str
    state: str
    service: str
    address: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""
    detection_method: str = ""
    service_confidence: int | None = None
    source: str = Source.NMAP


@dataclass(slots=True)
class WebObservation:
    url: str
    source: str
    status_code: int | None = None
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    text: str = ""
    body: str = ""
    forms: list[FormObservation] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    redirect_target: str = ""
    blocked_redirect: str = ""
    knowledgebase_page_type: str = ""
    discovery_diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    kind: str
    auth_type: str
    endpoint: str
    host: str
    port: int | None
    protocol: str
    evidence: list[Evidence]
    sources: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    discovered_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _finding_id(self.kind, self.auth_type, self.endpoint)


@dataclass(slots=True)
class Issue:
    stage: str
    message: str
    target: str = ""
    fatal: bool = False


@dataclass(slots=True)
class Report:
    scope: list[str]
    findings: list[Finding] = field(default_factory=list)
    services: list[ServiceObservation] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    schema_version: str = "2.0"
    detector_version: str = "0.2.0"
    run_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    partial: bool = False
    config: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        self.finished_at = utc_now()
        self.partial = bool(self.issues)
        self.findings.sort(key=lambda item: (item.kind, item.auth_type, item.endpoint))
        self.services.sort(key=lambda item: (item.host, item.port, item.transport))

    def add_or_merge_finding(self, finding: Finding) -> bool:
        for existing in self.findings:
            existing_fingerprint = existing.metadata.get("auth_fingerprint")
            finding_fingerprint = finding.metadata.get("auth_fingerprint")
            both_web_logins = bool(
                existing.kind == FindingKind.WEB_LOGIN
                and finding.kind == FindingKind.WEB_LOGIN
            )
            same_endpoint = (
                existing.kind == finding.kind
                and existing.auth_type == finding.auth_type
                and existing.endpoint == finding.endpoint
            )
            if (
                same_endpoint
                and both_web_logins
                and existing_fingerprint
                and finding_fingerprint
                and existing_fingerprint != finding_fingerprint
            ):
                # One URL can expose genuinely different authentication forms.
                same_endpoint = False
            same_form = bool(
                both_web_logins
                and existing.auth_type == finding.auth_type
                and existing_fingerprint == finding_fingerprint
                and existing_fingerprint
            )
            existing_route = _web_route_identity(existing) if both_web_logins else ""
            finding_route = _web_route_identity(finding) if both_web_logins else ""
            same_route = bool(existing_route and existing_route == finding_route)
            same_js_route = bool(
                same_route
                and existing.auth_type == "js_login"
                and finding.auth_type == "js_login"
            )
            js_form_route = bool(
                same_route
                and (
                    (existing.auth_type == "js_login" and finding_fingerprint)
                    or (finding.auth_type == "js_login" and existing_fingerprint)
                )
            )
            if same_endpoint or same_form or same_js_route or js_form_route:
                promote_to_form = bool(
                    existing.auth_type == "js_login" and finding_fingerprint
                )
                existing.sources = sorted(set(existing.sources) | set(finding.sources))
                known = {(e.rule_id, e.source, e.detail) for e in existing.evidence}
                existing.evidence.extend(
                    evidence
                    for evidence in finding.evidence
                    if (evidence.rule_id, evidence.source, evidence.detail) not in known
                )
                for key, value in finding.metadata.items():
                    if key == "discovered_on":
                        continue
                    if promote_to_form:
                        existing.metadata[key] = value
                    elif key not in existing.metadata or existing.metadata[key] in (
                        None,
                        "",
                        [],
                        {},
                    ):
                        existing.metadata[key] = value
                if both_web_logins:
                    locations = [
                        *_finding_locations(existing),
                        *_finding_locations(finding),
                    ]
                    existing.metadata["discovered_on"] = list(dict.fromkeys(locations))
                if promote_to_form:
                    existing.auth_type = finding.auth_type
                    existing.port = finding.port
                    existing.protocol = finding.protocol
                    existing.id = _finding_id(
                        existing.kind,
                        existing.auth_type,
                        existing.endpoint,
                    )
                return False
        self.findings.append(finding)
        return True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _web_route_identity(finding: Finding) -> str:
    try:
        parts = urlsplit(finding.endpoint)
        _ = parts.port
    except ValueError:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return ""
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def _finding_locations(finding: Finding) -> list[str]:
    locations = finding.metadata.get("discovered_on", [])
    if not isinstance(locations, list):
        locations = []
    return list(dict.fromkeys([finding.endpoint, *locations]))
