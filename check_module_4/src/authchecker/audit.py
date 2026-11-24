from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, TextIO

from .models import AuthJob, Credential, Outcome, outcome_attempted_count


_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "credential",
    "authorization",
    "proxy-authorization",
}


class JsonlAuditWriter:
    """Append-only audit writer that never emits a plaintext password."""

    def __init__(
        self,
        destination: str | Path | TextIO,
        *,
        correlation_key: bytes | None = None,
    ) -> None:
        self._owns_stream = not hasattr(destination, "write")
        if self._owns_stream:
            self._stream: TextIO = Path(destination).open(
                "a", encoding="utf-8", newline="\n"
            )
        else:
            self._stream = destination  # type: ignore[assignment]
        self._correlation_key = correlation_key or os.urandom(32)

    def __enter__(self) -> "JsonlAuditWriter":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_stream and not self._stream.closed:
            self._stream.close()

    def record_attempt(
        self, job: AuthJob, credential: Credential, outcome: Outcome
    ) -> None:
        secret_ref = hmac.new(
            self._correlation_key,
            credential.password.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:20]
        attempted = bool(outcome_attempted_count(outcome))
        record = {
            "event": "attempt" if attempted else "check",
            "attempted": attempted,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": job.report_run_id,
            "job_key": job.job_key,
            "finding_id": job.finding_id,
            "auth_type": job.auth_type,
            "endpoint": job.endpoint,
            "username": credential.username,
            "secret_ref": secret_ref,
            "outcome": outcome.status.value,
            "detail": _redact(outcome.detail, credential.password),
            "retry_after_seconds": outcome.retry_after_seconds,
            "evidence": _redact(outcome.evidence, credential.password),
        }
        self.write_event(record)

    def write_event(self, record: Mapping[str, Any]) -> None:
        self._stream.write(
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        )
        self._stream.flush()


def _redact(value: Any, password: str, *, key: str | None = None) -> Any:
    if key is not None and key.casefold() in _SENSITIVE_KEYS:
        return "<redacted>"
    if isinstance(value, str):
        return value.replace(password, "<redacted>") if password else value
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact(item_value, password, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item, password) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)

