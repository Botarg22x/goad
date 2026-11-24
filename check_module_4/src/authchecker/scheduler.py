from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Protocol

from .adapters import AdapterRegistry
from .models import (
    AuthJob,
    Credential,
    Outcome,
    OutcomeStatus,
    outcome_attempted_count,
)
from .policy import AttemptPolicy


class AuditSink(Protocol):
    def record_attempt(
        self, job: AuthJob, credential: Credential, outcome: Outcome
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ScheduledAttempt:
    job: AuthJob
    credential: Credential
    outcome: Outcome


@dataclass(frozen=True, slots=True)
class ScheduleResult:
    attempts: tuple[ScheduledAttempt, ...]
    attempted_count: int
    halt_reason: str | None


class Scheduler:
    def __init__(
        self,
        registry: AdapterRegistry,
        policy: AttemptPolicy | None = None,
        *,
        audit_sink: AuditSink | None = None,
        on_attempt: Callable[[ScheduledAttempt, int], None] | None = None,
        max_workers: int = 1,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.registry = registry
        self.policy = policy or AttemptPolicy()
        self.audit_sink = audit_sink
        self.on_attempt = on_attempt
        self.max_workers = max_workers
        self._clock = clock
        self._sleep = sleeper

    def run(
        self, attempts: Iterable[tuple[AuthJob, Credential]]
    ) -> ScheduleResult:
        if self.max_workers == 1:
            return self._run_sequential(attempts)
        return self._run_parallel(attempts)

    def _run_sequential(
        self, attempts: Iterable[tuple[AuthJob, Credential]]
    ) -> ScheduleResult:
        completed: list[ScheduledAttempt] = []
        per_account: dict[tuple[str, str], int] = defaultdict(int)
        completed_accounts: set[tuple[str, str]] = set()
        unsupported_jobs: set[str] = set()
        attempted_count = 0
        halt_reason: str | None = None
        previous_start: float | None = None
        interval = 1.0 / self.policy.rate_per_second

        for job, credential in attempts:
            if self._total_limit_reached(attempted_count):
                halt_reason = "max_total_attempts"
                break
            account_key = job.account_key(credential.username)
            if account_key in completed_accounts or job.job_key in unsupported_jobs:
                continue
            if per_account[account_key] >= self.policy.max_attempts_per_account:
                continue
            if previous_start is not None:
                remaining = interval - (self._clock() - previous_start)
                if remaining > 0:
                    self._sleep(remaining)
            previous_start = self._clock()

            outcome = self._attempt(job, credential)
            counted = outcome_attempted_count(outcome)
            attempted_count += counted
            per_account[account_key] += counted
            scheduled = ScheduledAttempt(job, credential, outcome)
            completed.append(scheduled)
            if self.audit_sink is not None:
                self.audit_sink.record_attempt(job, credential, outcome)
            if self.on_attempt is not None:
                self.on_attempt(scheduled, attempted_count)

            if outcome.status is OutcomeStatus.UNSUPPORTED:
                # One diagnostic is enough for an adapter-less job. In
                # particular, never walk an entire password stream here.
                unsupported_jobs.add(job.job_key)
            if self._completes_account(outcome.status):
                completed_accounts.add(account_key)
            if (
                outcome.status is OutcomeStatus.RATE_LIMITED
                and self.policy.stop_on_rate_limit
            ):
                halt_reason = outcome.status.value
                break

        return ScheduleResult(tuple(completed), attempted_count, halt_reason)

    def _run_parallel(
        self, attempts: Iterable[tuple[AuthJob, Credential]],
    ) -> ScheduleResult:
        completed: list[ScheduledAttempt] = []
        per_account: dict[tuple[str, str], int] = defaultdict(int)
        completed_accounts: set[tuple[str, str]] = set()
        unsupported_jobs: set[str] = set()
        attempted_count = 0
        halt_reason: str | None = None
        previous_start: float | None = None
        interval = 1.0 / self.policy.rate_per_second
        source = iter(attempts)
        exhausted = False
        stop_submission = False
        futures: dict[Future[Outcome], tuple[AuthJob, Credential]] = {}

        with ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="authchecker",
        ) as executor:
            while futures or (not exhausted and not stop_submission):
                while (
                    len(futures) < self.max_workers
                    and not exhausted
                    and not stop_submission
                ):
                    if self._total_limit_reached(attempted_count):
                        halt_reason = "max_total_attempts"
                        stop_submission = True
                        break
                    if self._total_limit_reached(attempted_count + len(futures)):
                        # Wait for an in-flight result. A diagnostic that did
                        # not submit credentials must not spend this limit.
                        break
                    try:
                        job, credential = next(source)
                    except StopIteration:
                        exhausted = True
                        break
                    account_key = job.account_key(credential.username)
                    if account_key in completed_accounts or job.job_key in unsupported_jobs:
                        continue
                    if per_account[account_key] >= self.policy.max_attempts_per_account:
                        continue

                    if previous_start is not None:
                        remaining = interval - (self._clock() - previous_start)
                        if remaining > 0:
                            self._sleep(remaining)
                    previous_start = self._clock()
                    future = executor.submit(self._attempt, job, credential)
                    futures[future] = (job, credential)
                    # Reserve the limit at submission time so parallel workers
                    # cannot exceed the per-account cap.
                    per_account[account_key] += 1

                if not futures:
                    continue

                done, _pending = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    job, credential = futures.pop(future)
                    outcome = future.result()
                    attempted_count += outcome_attempted_count(outcome)
                    scheduled = ScheduledAttempt(job, credential, outcome)
                    completed.append(scheduled)
                    if self.audit_sink is not None:
                        # Only the scheduler thread writes JSONL records.
                        self.audit_sink.record_attempt(job, credential, outcome)
                    if self.on_attempt is not None:
                        self.on_attempt(scheduled, attempted_count)

                    account_key = job.account_key(credential.username)
                    if outcome.status is OutcomeStatus.UNSUPPORTED:
                        unsupported_jobs.add(job.job_key)
                    if self._completes_account(outcome.status):
                        completed_accounts.add(account_key)
                    if (
                        outcome.status is OutcomeStatus.RATE_LIMITED
                        and self.policy.stop_on_rate_limit
                    ):
                        halt_reason = outcome.status.value
                        stop_submission = True

                    if self._total_limit_reached(attempted_count):
                        halt_reason = "max_total_attempts"
                        stop_submission = True

        return ScheduleResult(tuple(completed), attempted_count, halt_reason)

    def _attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        adapter = self.registry.resolve(job.auth_type)
        try:
            return adapter.attempt(job, credential)
        except Exception as exc:  # adapters must not tear down the scheduler
            return Outcome(
                OutcomeStatus.ERROR,
                detail=f"adapter error: {type(exc).__name__}: {exc}",
                evidence={"attempted": False, "reason": "adapter_error"},
            )

    def _total_limit_reached(self, count: int) -> bool:
        limit = self.policy.max_total_attempts
        return limit is not None and count >= limit

    def _completes_account(self, status: OutcomeStatus) -> bool:
        return (
            (status is OutcomeStatus.SUCCESS and self.policy.stop_on_success)
            or (status is OutcomeStatus.MFA_REQUIRED and self.policy.stop_on_mfa)
            or (status is OutcomeStatus.LOCKED_OUT and self.policy.stop_on_lockout)
        )

