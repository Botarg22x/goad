from __future__ import annotations

import hashlib
import json
from collections.abc import Collection

from .importer import Finding, PointFinderReport
from .models import AuthJob


DEFAULT_SUPPORTED_AUTH_TYPES = frozenset(
    {
        "password_form",
        "http_basic",
        "http_digest",
        "ftp",
        "ftps",
        "ssh",
    }
)


def build_jobs(
    report: PointFinderReport,
    *,
    supported_auth_types: Collection[str] = DEFAULT_SUPPORTED_AUTH_TYPES,
) -> list[AuthJob]:
    """Build jobs only from supported findings; services are never consumed."""

    allowlist = frozenset(supported_auth_types)
    jobs: list[AuthJob] = []
    seen: set[str] = set()
    for finding in report.findings:
        if finding.auth_type not in allowlist:
            continue
        job = _job_from_finding(report.run_id, finding)
        if job.job_key in seen:
            continue
        seen.add(job.job_key)
        jobs.append(job)
    return jobs


def make_job_key(run_id: str, finding: Finding) -> str:
    """Make a stable key that remains unique for colliding finding IDs/forms."""

    identity = {
        "run_id": run_id,
        "finding_id": finding.id,
        "auth_type": finding.auth_type,
        "endpoint": finding.endpoint,
        "auth_fingerprint": finding.metadata.get("auth_fingerprint"),
        "form_action": finding.metadata.get("form_action"),
    }
    canonical = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()[:24]
    return f"job-{digest}"


def _job_from_finding(run_id: str, finding: Finding) -> AuthJob:
    fingerprint = finding.metadata.get("auth_fingerprint")
    action = finding.metadata.get("form_action")
    return AuthJob(
        job_key=make_job_key(run_id, finding),
        report_run_id=run_id,
        finding_id=finding.id,
        kind=finding.kind,
        auth_type=finding.auth_type,
        endpoint=finding.endpoint,
        host=finding.host,
        port=finding.port,
        protocol=finding.protocol,
        auth_fingerprint=fingerprint if isinstance(fingerprint, str) else None,
        form_action=action if isinstance(action, str) else None,
        metadata=finding.metadata,
    )

