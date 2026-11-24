from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


class OutcomeStatus(StrEnum):
    """Normalized result returned by every authentication adapter."""

    SUCCESS = "success"
    FAILURE = "failure"
    MFA_REQUIRED = "mfa_required"
    LOCKED_OUT = "locked_out"
    RATE_LIMITED = "rate_limited"
    AMBIGUOUS = "ambiguous"
    NETWORK_ERROR = "network_error"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class Credential:
    username: str
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.username, str):
            raise TypeError("username must be a string")
        if not isinstance(self.password, str):
            raise TypeError("password must be a string")


@dataclass(frozen=True, slots=True)
class AuthJob:
    job_key: str
    report_run_id: str
    finding_id: str
    kind: str
    auth_type: str
    endpoint: str
    host: str
    port: int | None
    protocol: str
    auth_fingerprint: str | None = None
    form_action: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "job_key",
            "report_run_id",
            "finding_id",
            "kind",
            "auth_type",
            "endpoint",
            "host",
            "protocol",
        ):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")
        if self.port is not None and (
            isinstance(self.port, bool) or not isinstance(self.port, int)
        ):
            raise TypeError("port must be an integer or None")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def account_key(self, username: str) -> tuple[str, str]:
        """Return the policy key used for per-account attempt limits."""

        return (self.job_key, username)


@dataclass(frozen=True, slots=True)
class Outcome:
    status: OutcomeStatus
    detail: str = ""
    retry_after_seconds: float | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.status, OutcomeStatus):
            object.__setattr__(self, "status", OutcomeStatus(self.status))
        if not isinstance(self.detail, str):
            raise TypeError("detail must be a string")
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("retry_after_seconds cannot be negative")
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))


def outcome_attempted_count(outcome: Outcome) -> int:
    """Return whether an authentication request was actually submitted."""

    browser_count = outcome.evidence.get("browser_attempted_count")
    if isinstance(browser_count, (bool, int)):
        return int(bool(browser_count))
    attempted = outcome.evidence.get("attempted")
    if isinstance(attempted, bool):
        return int(attempted)
    if outcome.status in {OutcomeStatus.UNSUPPORTED, OutcomeStatus.SKIPPED}:
        return 0
    return 1

