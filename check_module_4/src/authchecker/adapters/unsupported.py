from __future__ import annotations

from collections.abc import Collection

from .base import AuthAdapter
from ..models import AuthJob, Credential, Outcome, OutcomeStatus


class UnsupportedAdapter(AuthAdapter):
    """Non-network fallback used when no adapter is registered."""

    @property
    def auth_types(self) -> Collection[str]:
        return ()

    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        return Outcome(
            OutcomeStatus.UNSUPPORTED,
            detail=f"no adapter registered for auth_type={job.auth_type!r}",
            evidence={"attempted": False, "reason": "unsupported_auth_type"},
        )

