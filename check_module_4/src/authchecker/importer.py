from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from uuid import UUID


_FINDING_ID = re.compile(r"^auth-[0-9a-f]{16}$")
_RFC3339_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
_UUID_TEXT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_FINDING_KINDS = {
    "web_login_page",
    "http_auth_challenge",
    "sso_entry",
    "network_auth_surface",
}
_ROOT_KEYS = {
    "scope",
    "findings",
    "services",
    "issues",
    "schema_version",
    "detector_version",
    "run_id",
    "started_at",
    "finished_at",
    "partial",
    "config",
}
_FINDING_KEYS = {
    "kind",
    "auth_type",
    "endpoint",
    "host",
    "port",
    "protocol",
    "evidence",
    "sources",
    "metadata",
    "id",
    "discovered_at",
}
_EVIDENCE_KEYS = {"rule_id", "group", "source", "detail"}
_SERVICE_KEYS = {
    "host",
    "port",
    "transport",
    "state",
    "service",
    "address",
    "product",
    "version",
    "extra_info",
    "tunnel",
    "detection_method",
    "service_confidence",
    "source",
}
_ISSUE_KEYS = {"stage", "message", "target", "fatal"}


class ReportValidationError(ValueError):
    """Raised when input does not conform to PointFinder report schema 2.0."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


@dataclass(frozen=True, slots=True)
class Evidence:
    rule_id: str
    group: str
    source: str
    detail: str


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    auth_type: str
    endpoint: str
    host: str
    port: int | None
    protocol: str
    evidence: tuple[Evidence, ...]
    sources: tuple[str, ...]
    metadata: Mapping[str, Any]
    id: str
    discovered_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class PointFinderReport:
    scope: tuple[str, ...]
    findings: tuple[Finding, ...]
    services: tuple[Mapping[str, Any], ...]
    issues: tuple[Mapping[str, Any], ...]
    schema_version: str
    detector_version: str
    run_id: str
    started_at: str
    finished_at: str
    partial: bool
    config: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "services", tuple(MappingProxyType(dict(x)) for x in self.services))
        object.__setattr__(self, "issues", tuple(MappingProxyType(dict(x)) for x in self.issues))
        object.__setattr__(self, "config", MappingProxyType(dict(self.config)))


class _DuplicateKey(ValueError):
    pass


class _InvalidConstant(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(f"duplicate object member {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise _InvalidConstant(f"non-JSON numeric constant {value!r}")


def load_report(path: str | Path) -> PointFinderReport:
    """Load and strictly validate a UTF-8 PointFinder schema-2.0 report."""

    report_path = Path(path)
    try:
        text = report_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ReportValidationError("$", "report must be UTF-8") from exc
    return parse_report(text)


def parse_report(source: str | bytes | bytearray | Mapping[str, Any]) -> PointFinderReport:
    """Parse JSON text or validate an already decoded report mapping."""

    if isinstance(source, Mapping):
        data: Any = dict(source)
    else:
        try:
            data = json.loads(
                source,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_non_json_constant,
            )
        except _DuplicateKey as exc:
            raise ReportValidationError("$", str(exc)) from exc
        except _InvalidConstant as exc:
            raise ReportValidationError("$", str(exc)) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReportValidationError("$", f"invalid JSON: {exc}") from exc
    root = _object(data, "$")
    _exact_keys(root, _ROOT_KEYS, "$")

    schema_version = _string(root["schema_version"], "$.schema_version")
    if schema_version != "2.0":
        raise ReportValidationError("$.schema_version", "must equal '2.0'")
    scope = _string_array(root["scope"], "$.scope", unique=True)
    detector_version = _string(root["detector_version"], "$.detector_version")
    run_id = _string(root["run_id"], "$.run_id")
    _uuid(run_id, "$.run_id")
    started_at = _string(root["started_at"], "$.started_at")
    finished_at = _string(root["finished_at"], "$.finished_at")
    _date_time(started_at, "$.started_at")
    _date_time(finished_at, "$.finished_at")
    partial = _boolean(root["partial"], "$.partial")
    config = _object(root["config"], "$.config")

    findings_data = _array(root["findings"], "$.findings")
    findings = tuple(
        _parse_finding(item, f"$.findings[{index}]")
        for index, item in enumerate(findings_data)
    )
    services_data = _array(root["services"], "$.services")
    services = tuple(
        _parse_service(item, f"$.services[{index}]")
        for index, item in enumerate(services_data)
    )
    issues_data = _array(root["issues"], "$.issues")
    issues = tuple(
        _parse_issue(item, f"$.issues[{index}]")
        for index, item in enumerate(issues_data)
    )

    return PointFinderReport(
        scope=tuple(scope),
        findings=findings,
        services=services,
        issues=issues,
        schema_version=schema_version,
        detector_version=detector_version,
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        partial=partial,
        config=config,
    )


def _parse_finding(value: Any, path: str) -> Finding:
    item = _object(value, path)
    _exact_keys(item, _FINDING_KEYS, path)
    kind = _string(item["kind"], f"{path}.kind")
    if kind not in _FINDING_KINDS:
        raise ReportValidationError(f"{path}.kind", "unknown finding kind")
    auth_type = _string(item["auth_type"], f"{path}.auth_type")
    if not auth_type:
        raise ReportValidationError(f"{path}.auth_type", "must not be empty")
    endpoint = _string(item["endpoint"], f"{path}.endpoint")
    host = _string(item["host"], f"{path}.host")
    port = _nullable_integer(item["port"], f"{path}.port")
    if port is not None and not 1 <= port <= 65535:
        raise ReportValidationError(f"{path}.port", "must be between 1 and 65535")
    protocol = _string(item["protocol"], f"{path}.protocol")
    evidence_data = _array(item["evidence"], f"{path}.evidence")
    evidence = tuple(
        _parse_evidence(entry, f"{path}.evidence[{index}]")
        for index, entry in enumerate(evidence_data)
    )
    sources = tuple(_string_array(item["sources"], f"{path}.sources", unique=True))
    metadata = _object(item["metadata"], f"{path}.metadata")
    if "login_verification" in metadata:
        from .template_profile import profile_from_metadata
        try:
            profile_from_metadata(metadata)
        except ValueError as exc:
            raise ReportValidationError(f"{path}.metadata.login_verification", str(exc)) from exc
    finding_id = _string(item["id"], f"{path}.id")
    if not _FINDING_ID.fullmatch(finding_id):
        raise ReportValidationError(
            f"{path}.id", "must match ^auth-[0-9a-f]{16}$"
        )
    discovered_at = _string(item["discovered_at"], f"{path}.discovered_at")
    _date_time(discovered_at, f"{path}.discovered_at")
    return Finding(
        kind=kind,
        auth_type=auth_type,
        endpoint=endpoint,
        host=host,
        port=port,
        protocol=protocol,
        evidence=evidence,
        sources=sources,
        metadata=metadata,
        id=finding_id,
        discovered_at=discovered_at,
    )


def _parse_evidence(value: Any, path: str) -> Evidence:
    item = _object(value, path)
    _exact_keys(item, _EVIDENCE_KEYS, path)
    return Evidence(
        rule_id=_string(item["rule_id"], f"{path}.rule_id"),
        group=_string(item["group"], f"{path}.group"),
        source=_string(item["source"], f"{path}.source"),
        detail=_string(item["detail"], f"{path}.detail"),
    )


def _parse_service(value: Any, path: str) -> Mapping[str, Any]:
    item = _object(value, path)
    _exact_keys(item, _SERVICE_KEYS, path)
    for key in (
        "host",
        "transport",
        "state",
        "service",
        "address",
        "product",
        "version",
        "extra_info",
        "tunnel",
        "detection_method",
        "source",
    ):
        _string(item[key], f"{path}.{key}")
    port = _integer(item["port"], f"{path}.port")
    if not 1 <= port <= 65535:
        raise ReportValidationError(f"{path}.port", "must be between 1 and 65535")
    if item["service_confidence"] is not None:
        _integer(item["service_confidence"], f"{path}.service_confidence")
    return dict(item)


def _parse_issue(value: Any, path: str) -> Mapping[str, Any]:
    item = _object(value, path)
    _exact_keys(item, _ISSUE_KEYS, path)
    for key in ("stage", "message", "target"):
        _string(item[key], f"{path}.{key}")
    _boolean(item["fatal"], f"{path}.fatal")
    return dict(item)


def _exact_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        raise ReportValidationError(path, f"missing required member(s): {', '.join(missing)}")
    if extra:
        raise ReportValidationError(path, f"unexpected member(s): {', '.join(extra)}")


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportValidationError(path, "must be an object")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportValidationError(path, "must be an array")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise ReportValidationError(path, "must be a string")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ReportValidationError(path, "must be a boolean")
    return value


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportValidationError(path, "must be an integer")
    return value


def _nullable_integer(value: Any, path: str) -> int | None:
    if value is None:
        return None
    return _integer(value, path)


def _string_array(value: Any, path: str, *, unique: bool) -> Sequence[str]:
    items = _array(value, path)
    result = [_string(item, f"{path}[{index}]") for index, item in enumerate(items)]
    if unique and len(set(result)) != len(result):
        raise ReportValidationError(path, "items must be unique")
    return result


def _uuid(value: str, path: str) -> None:
    if not _UUID_TEXT.fullmatch(value):
        raise ReportValidationError(path, "must be a canonical UUID")
    try:
        UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ReportValidationError(path, "must be a UUID") from exc


def _date_time(value: str, path: str) -> None:
    if not _RFC3339_DATE_TIME.fullmatch(value):
        raise ReportValidationError(path, "must be an RFC 3339 date-time")
    candidate = value[:-1] + "+00:00" if value[-1] in "Zz" else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ReportValidationError(path, "must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReportValidationError(path, "date-time must include a UTC offset")

