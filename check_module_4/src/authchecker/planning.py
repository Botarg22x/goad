from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .importer import PointFinderReport, load_report
from .jobs import DEFAULT_SUPPORTED_AUTH_TYPES, build_jobs
from .loaders import count_candidates
from .models import AuthJob


def _planned_adapter(job: AuthJob) -> str:
    """Describe the available live path without performing a network check."""
    if job.auth_type == "http_basic":
        return "http_basic"
    if job.auth_type == "password_form":
        return "template_form" if isinstance(job.metadata.get("login_verification"), Mapping) else "password_form"
    return "unsupported"


@dataclass(frozen=True, slots=True)
class DryRunPlan:
    report_path: str
    report_run_id: str
    report_partial: bool
    finding_count: int
    job_count: int
    omitted_findings_by_auth_type: dict[str, int]
    login_count: int
    password_count: int
    potential_attempt_count: int
    supported_auth_types: tuple[str, ...]
    jobs: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": "dry-run",
            "report_path": self.report_path,
            "report_run_id": self.report_run_id,
            "report_partial": self.report_partial,
            "finding_count": self.finding_count,
            "job_count": self.job_count,
            "omitted_findings_by_auth_type": self.omitted_findings_by_auth_type,
            "login_count": self.login_count,
            "password_count": self.password_count,
            "potential_attempt_count": self.potential_attempt_count,
            "supported_auth_types": list(self.supported_auth_types),
            "jobs": list(self.jobs),
        }


def build_dry_run_plan(
    report_path: str | Path,
    logins_path: str | Path | None,
    passwords_path: str | Path | None,
    *,
    password_encoding: str = "utf-8",
    supported_auth_types: Collection[str] = DEFAULT_SUPPORTED_AUTH_TYPES,
    login_values: Collection[str] = (),
    password_values: Collection[str] = (),
) -> DryRunPlan:
    report = load_report(report_path)
    return plan_for_report(
        report,
        report_path=report_path,
        logins_path=logins_path,
        passwords_path=passwords_path,
        password_encoding=password_encoding,
        supported_auth_types=supported_auth_types,
        login_values=login_values,
        password_values=password_values,
    )


def plan_for_report(
    report: PointFinderReport,
    *,
    report_path: str | Path,
    logins_path: str | Path | None,
    passwords_path: str | Path | None,
    password_encoding: str = "utf-8",
    supported_auth_types: Collection[str] = DEFAULT_SUPPORTED_AUTH_TYPES,
    login_values: Collection[str] = (),
    password_values: Collection[str] = (),
) -> DryRunPlan:
    allowlist = frozenset(supported_auth_types)
    jobs = build_jobs(report, supported_auth_types=allowlist)
    login_count, password_count = count_candidates(
        logins_path,
        passwords_path,
        password_encoding=password_encoding,
        login_values=login_values,
        password_values=password_values,
    )
    omitted = Counter(
        finding.auth_type
        for finding in report.findings
        if finding.auth_type not in allowlist
    )
    sanitized_jobs = tuple(
        {
            "job_key": job.job_key,
            "finding_id": job.finding_id,
            "kind": job.kind,
            "auth_type": job.auth_type,
            "endpoint": job.endpoint,
            "host": job.host,
            "port": job.port,
            "protocol": job.protocol,
            "auth_fingerprint": job.auth_fingerprint,
            "form_action": job.form_action,
            "adapter": _planned_adapter(job),
        }
        for job in jobs
    )
    return DryRunPlan(
        report_path=str(Path(report_path)),
        report_run_id=report.run_id,
        report_partial=report.partial,
        finding_count=len(report.findings),
        job_count=len(jobs),
        omitted_findings_by_auth_type=dict(sorted(omitted.items())),
        login_count=login_count,
        password_count=password_count,
        potential_attempt_count=len(jobs) * login_count * password_count,
        supported_auth_types=tuple(sorted(allowlist)),
        jobs=sanitized_jobs,
    )
