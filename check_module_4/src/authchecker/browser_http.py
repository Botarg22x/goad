"""Prepare one browser session, then check credentials with scoped HTTP requests."""

from __future__ import annotations

import math
import threading
from collections.abc import Callable

from .adapters.http import TargetScope
from .browser import (
    BrowserCheckConfig,
    BrowserCheckResult,
    BrowserRequestSnapshot,
    run_browser_check,
)
from .http_replay import HttpReplayTemplate, run_http_replay
from .models import Credential, Outcome, OutcomeStatus
from .template_profile import profile_from_json


class BrowserHttpChecker:
    """Capture once per batch; keep session secrets in memory, not diagnostics.

    The browser intercepts and aborts the first credential request. Each real
    attempt then uses an independent HTTP cookie jar and refreshes the login
    page before submitting. A browser capture does not spend an auth rate slot.
    """

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
            raise ValueError("HTTP timeout must be greater than 0 and at most 60 seconds")
        self._timeout_seconds = timeout_seconds
        self._prepare_lock = threading.Lock()
        self._replay_lock = threading.Lock()
        self._key: tuple[str, BrowserCheckConfig, TargetScope | None] | None = None
        self._template: HttpReplayTemplate | None = None
        self._failure: BrowserCheckResult | None = None

    def __call__(
        self,
        url: str,
        credential: Credential,
        *,
        config: BrowserCheckConfig,
        target_scope: TargetScope | None = None,
        on_progress: Callable[[str], None] | None = None,
        before_submit: Callable[[Callable[[float], None]], None] | None = None,
    ) -> BrowserCheckResult:
        profile = profile_from_json(config.verification_json)
        if profile is not None and profile["request"]["action"] in {"page", "fixed"}:
            # The request is already declared. Render a fresh page/session and
            # submit it over HTTP, without capturing a native form click.
            return run_browser_check(url, credential, config=config, target_scope=target_scope,
                                     on_progress=on_progress, before_submit=before_submit)
        key = (url, config, target_scope)
        with self._prepare_lock:
            if self._key is not None and self._key != key:
                # A checker belongs to exactly one target/configuration. Never
                # reuse captured cookies or request templates on another job.
                return self._unsupported("Сессия подготовлена для другой цели или настроек", "capture_target")
            if self._key is None:
                self._key = key
                self._prepare(url, credential, config, target_scope, on_progress)
            failure = self._failure
            template = self._template
        if failure is not None:
            return failure
        if template is None:
            return self._unsupported("Браузер не подготовил шаблон запроса входа", "capture_error")
        # Separate jars can still contain the same server-side session ID. A
        # successful parallel POST could authenticate a different credential's
        # response. Serialize this captured session and check its baseline on
        # every replay; --threads remains a cap, not session isolation.
        with self._replay_lock:
            return run_http_replay(
                template, credential, config=config, target_scope=target_scope,
                timeout_seconds=self._timeout_seconds, on_progress=on_progress,
                before_submit=before_submit,
            )

    def _prepare(
        self,
        url: str,
        credential: Credential,
        config: BrowserCheckConfig,
        target_scope: TargetScope | None,
        on_progress: Callable[[str], None] | None,
    ) -> None:
        captured: HttpReplayTemplate | None = None

        def receive(snapshot: BrowserRequestSnapshot) -> None:
            nonlocal captured
            captured = HttpReplayTemplate.from_capture(snapshot, credential)

        try:
            checked = run_browser_check(
                url, credential, config=config, target_scope=target_scope,
                on_progress=on_progress, on_capture=receive,
            )
        except Exception:
            # Driver and capture exceptions can contain request bodies/tokens.
            # Cache a fixed diagnostic, never their original text or traceback.
            self._failure = self._unsupported("Не удалось подготовить HTTP-запрос через браузер", "capture_error")
            return
        if captured is not None and checked.outcome.evidence.get("reason") == "request_captured" and not checked.attempted_count:
            self._template = captured
            if on_progress is not None:
                on_progress("Шаблон входа перехвачен; браузер закрыт, дальнейшие попытки идут через HTTP")
        elif checked.attempted_count:
            # A capture implementation must not send a browser login first.
            # Do not follow an unexpected submission with a duplicate POST.
            self._failure = BrowserCheckResult(
                Outcome(OutcomeStatus.UNSUPPORTED, "Не удалось безопасно перехватить запрос до отправки", evidence={"reason": "capture_error"}),
                checked.attempted_count, checked.final_url, checked.fields,
            )
        elif checked.outcome.evidence.get("reason") == "request_captured":
            self._failure = self._unsupported("Запрос входа не поддерживает перенос в HTTP", "capture_error")
        else:
            self._failure = checked

    @staticmethod
    def _unsupported(detail: str, reason: str) -> BrowserCheckResult:
        return BrowserCheckResult(Outcome(OutcomeStatus.UNSUPPORTED, detail, evidence={"reason": reason}))


class AdaptiveBrowserChecker:
    """Prefer captured HTTP replay, then use one native browser session safely.

    This is used only by ``--auto-browser``. Explicit ``--browser-http`` keeps
    its strict capture-only contract and never submits credentials in Chromium.
    """

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self._http = BrowserHttpChecker(timeout_seconds=timeout_seconds)

    def __call__(
        self,
        url: str,
        credential: Credential,
        *,
        config: BrowserCheckConfig,
        target_scope: TargetScope | None = None,
        on_progress: Callable[[str], None] | None = None,
        before_submit: Callable[[Callable[[float], None]], None] | None = None,
    ) -> BrowserCheckResult:
        prepared = self._http(
            url,
            credential,
            config=config,
            target_scope=target_scope,
            on_progress=on_progress,
            before_submit=before_submit,
        )
        if (
            prepared.attempted_count == 0
            and prepared.outcome.evidence.get("reason") in {"capture_error", "browser_required"}
        ):
            if on_progress is not None:
                if prepared.outcome.evidence.get("reason") == "browser_required":
                    on_progress(
                        "HTTP не видит созданную JavaScript форму; "
                        "проверяю эту пару в изолированном браузере до отправки пароля"
                    )
                else:
                    on_progress(
                        "Шаблон нельзя безопасно перенести в HTTP; "
                        "проверяю эту пару в изолированном браузере"
                    )
            return run_browser_check(
                url,
                credential,
                config=config,
                target_scope=target_scope,
                on_progress=on_progress,
                before_submit=before_submit,
            )
        return prepared
