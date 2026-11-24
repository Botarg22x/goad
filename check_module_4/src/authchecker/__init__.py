"""Credential-check orchestration primitives for PointFinder reports."""

from .importer import PointFinderReport, ReportValidationError, load_report, parse_report
from .jobs import DEFAULT_SUPPORTED_AUTH_TYPES, build_jobs
from .models import AuthJob, Credential, Outcome, OutcomeStatus
from .policy import AttemptPolicy

__all__ = [
    "AuthJob",
    "AttemptPolicy",
    "Credential",
    "DEFAULT_SUPPORTED_AUTH_TYPES",
    "Outcome",
    "OutcomeStatus",
    "PointFinderReport",
    "ReportValidationError",
    "build_jobs",
    "load_report",
    "parse_report",
]

__version__ = "0.1.0"

