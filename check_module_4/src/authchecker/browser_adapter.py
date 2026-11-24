"""Run scheduler credentials in separate browser sessions with a shared rate."""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import replace
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit

from .adapters.base import AuthAdapter
from .adapters.http import PasswordFormAdapter, TargetScope
from .browser import BrowserCheckCancelled, BrowserCheckConfig, BrowserCheckResult, run_browser_check
from .models import AuthJob, Credential, Outcome, OutcomeStatus
from .form_fields import template_credential_fields
from .template_profile import profile_from_metadata


class TemplateFormAdapter(AuthAdapter):
    """Use a report's auto transport without ever repeating an attempted POST."""

    def __init__(self, client, target_scope, config: BrowserCheckConfig, *, rate_per_second=1.0):
        self.http = PasswordFormAdapter(client, target_scope)
        self.browser = BrowserAdapter(config, target_scope=target_scope, rate_per_second=rate_per_second)

    @property
    def auth_types(self):
        return ("password_form",)

    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        checked = self.http.attempt(job, credential)
        if checked.evidence.get("attempted") is not False:
            return checked
        if not (checked.evidence.get("reason") == "preflight" or checked.status == OutcomeStatus.NETWORK_ERROR):
            return checked
        try:
            profile = profile_from_metadata(job.metadata)
        except ValueError:
            return checked
        if profile is None or profile["transport"] != "auto":
            return checked
        return self.browser.attempt(job, credential)


class BrowserAdapter(AuthAdapter):
    """Keep only shared configuration and timing, never browser/session state."""

    def __init__(
        self,
        config: BrowserCheckConfig,
        *,
        target_scope: TargetScope | None = None,
        on_progress: Callable[[str], None] | None = None,
        rate_per_second: float = 1.0,
        checker: Callable[..., BrowserCheckResult] = run_browser_check,
    ) -> None:
        if not math.isfinite(rate_per_second) or rate_per_second <= 0:
            raise ValueError("rate_per_second must be a finite positive number")
        self._config = config
        self._target_scope = target_scope
        self._on_progress = on_progress
        self._checker = checker
        self._interval = 1.0 / rate_per_second
        self._submit_lock = threading.Lock()
        self._previous_submit: float | None = None
        self._interrupted = threading.Event()

    @property
    def auth_types(self) -> Collection[str]:
        return ("password_form",)

    @property
    def interrupted(self) -> bool:
        return self._interrupted.is_set()

    def _before_submit(self, waiter: Callable[[float], None]) -> None:
        # Waiting through Playwright, rather than time.sleep, lets the owning
        # browser continue processing loading, failure and route events.  Never
        # pump that event loop while holding a lock shared with other browsers.
        while True:
            with self._submit_lock:
                if self.interrupted:
                    raise BrowserCheckCancelled()
                now = time.monotonic()
                remaining = (
                    0.0 if self._previous_submit is None
                    else self._interval - (now - self._previous_submit)
                )
                if remaining <= 0:
                    self._previous_submit = now
                    return
            waiter(min(remaining, 0.5))

    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        if self.interrupted:
            return Outcome(
                OutcomeStatus.SKIPPED, "Браузерная проверка прервана пользователем",
                evidence={"browser_attempted_count": 0, "reason": "interrupted"},
            )
        if job.auth_type not in self.auth_types:
            return Outcome(
                OutcomeStatus.UNSUPPORTED,
                "Browser adapter supports only password forms",
                evidence={"browser_attempted_count": 0},
            )

        def clean(value: str, limit: int = 2000) -> str:
            # Only the current credential lives in this call's closure.  In
            # particular, the adapter does not accumulate a password list.
            for secret in {credential.password, quote(credential.password, safe=""), quote_plus(credential.password)}:
                if secret:
                    value = value.replace(secret, "<redacted>")
            return "".join(character if ord(character) >= 32 and ord(character) != 127 else " " for character in value)[:limit]

        progress = None
        if self._on_progress is not None:
            def progress(message: str) -> None:
                self._on_progress(clean(message))

        submitted = False

        def before_submit(waiter: Callable[[float], None]) -> None:
            nonlocal submitted
            self._before_submit(waiter)
            submitted = True

        try:
            username_hint, password_hint = template_credential_fields(job.metadata)
            config = self._config
            if username_hint and password_hint:
                config = replace(config, username_field_hint=username_hint, password_field_hint=password_hint)
            profile = profile_from_metadata(job.metadata)
            if profile is not None:
                declared_csrf = set(profile["request"]["csrf_fields"])
                required_csrf = tuple(sorted({
                    field["name"] for field in job.metadata["fields"]
                    if isinstance(field, dict) and field.get("name") in declared_csrf
                    and not field.get("disabled")
                }))
                config = replace(config, verification_json=json.dumps(profile, ensure_ascii=False, sort_keys=True),
                                 required_csrf_fields=required_csrf)
            checked = self._checker(
                job.endpoint,
                credential,
                config=config,
                target_scope=self._target_scope,
                on_progress=progress,
                before_submit=before_submit,
            )
        except BrowserCheckCancelled:
            return Outcome(
                OutcomeStatus.SKIPPED, "Браузерная проверка прервана пользователем",
                evidence={"browser_attempted_count": 0, "reason": "interrupted"},
            )
        except Exception as exc:
            # Driver errors can include HTML, request data and cookies in their
            # messages.  Only expose the exception type, never its contents.
            return Outcome(
                OutcomeStatus.ERROR,
                clean(f"Browser check failed: {type(exc).__name__}"),
                evidence={
                    "browser_attempted_count": int(submitted),
                    "reason": "browser_error",
                },
            )
        evidence: dict[str, object] = {
            "browser_attempted_count": int(checked.attempted_count > 0),
            "final_url": clean(_safe_url(checked.final_url)),
            "fields": [clean(name, 200) for name in checked.fields[:20] if isinstance(name, str)],
        }
        reason = checked.outcome.evidence.get("reason")
        if reason == "interrupted":
            self._interrupted.set()
        if isinstance(reason, str):
            evidence["reason"] = clean(reason, 200)
        http_status = checked.outcome.evidence.get("http_status")
        if isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599:
            evidence["http_status"] = http_status
        blocked_origin = checked.outcome.evidence.get("blocked_origin")
        if isinstance(blocked_origin, str):
            safe_origin = _safe_url(blocked_origin)
            if safe_origin:
                parts = urlsplit(safe_origin)
                evidence["blocked_origin"] = clean(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
        for name in ("blocked_method", "blocked_request_type"):
            value = checked.outcome.evidence.get(name)
            if isinstance(value, str):
                evidence[name] = clean(value, 40)
        return Outcome(
            checked.outcome.status,
            clean(checked.outcome.detail),
            checked.outcome.retry_after_seconds,
            evidence=evidence,
        )


def _safe_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
            return ""
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))
    except (ValueError, TypeError):
        return ""
