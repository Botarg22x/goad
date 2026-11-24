from __future__ import annotations

import io
import json
import threading
import unittest

from authchecker.adapters import AdapterRegistry, AuthAdapter, UnsupportedAdapter
from authchecker.audit import JsonlAuditWriter
from authchecker.models import AuthJob, Credential, Outcome, OutcomeStatus
from authchecker.policy import AttemptPolicy
from authchecker.scheduler import Scheduler


def job(*, job_key: str = "job-one", auth_type: str = "fake") -> AuthJob:
    return AuthJob(
        job_key=job_key,
        report_run_id="12345678-1234-5678-9234-567812345678",
        finding_id="auth-0123456789abcdef",
        kind="web_login_page",
        auth_type=auth_type,
        endpoint="https://example.test/login",
        host="example.test",
        port=443,
        protocol="https",
    )


class FakeAdapter(AuthAdapter):
    def __init__(self, outcomes: list[Outcome]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    @property
    def auth_types(self) -> tuple[str, ...]:
        return ("fake",)

    def attempt(self, auth_job: AuthJob, credential: Credential) -> Outcome:
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        return outcome


class ConcurrentAdapter(AuthAdapter):
    def __init__(self) -> None:
        self.barrier = threading.Barrier(2)
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    @property
    def auth_types(self) -> tuple[str, ...]:
        return ("fake",)

    def attempt(self, auth_job: AuthJob, credential: Credential) -> Outcome:
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            self.barrier.wait(timeout=2)
            return Outcome(OutcomeStatus.FAILURE)
        finally:
            with self.lock:
                self.active -= 1


class SchedulerTests(unittest.TestCase):
    def test_progress_callback_receives_each_completed_check(self) -> None:
        for workers in (1, 2):
            with self.subTest(workers=workers):
                registry = AdapterRegistry()
                registry.register(FakeAdapter([Outcome(OutcomeStatus.FAILURE)]))
                updates: list[tuple[int, int]] = []
                result = Scheduler(
                    registry,
                    AttemptPolicy(rate_per_second=1000, max_attempts_per_account=2),
                    max_workers=workers,
                    sleeper=lambda _: None,
                    on_attempt=lambda _attempt, count: updates.append((len(updates) + 1, count)),
                ).run((job(), Credential("alice", password)) for password in ("one", "two"))
                self.assertEqual(result.attempted_count, 2)
                self.assertEqual(updates, [(1, 1), (2, 2)])

    def test_default_policy_does_not_stop_after_100_attempts(self) -> None:
        for workers in (1, 2):
            with self.subTest(workers=workers):
                adapter = FakeAdapter([Outcome(OutcomeStatus.FAILURE)])
                registry = AdapterRegistry()
                registry.register(adapter)
                result = Scheduler(
                    registry, AttemptPolicy(rate_per_second=1000),
                    max_workers=workers, sleeper=lambda _: None,
                ).run((job(), Credential(f"user-{index}", "secret")) for index in range(101))

                self.assertEqual(result.attempted_count, 101)
                self.assertIsNone(result.halt_reason)

    def test_registry_falls_back_without_network_adapter(self) -> None:
        registry = AdapterRegistry()
        adapter = registry.resolve("ssh")
        self.assertIsInstance(adapter, UnsupportedAdapter)
        result = adapter.attempt(job(auth_type="ssh"), Credential("u", "p"))
        self.assertEqual(result.status, OutcomeStatus.UNSUPPORTED)

    def test_registry_rejects_collisions(self) -> None:
        registry = AdapterRegistry()
        registry.register(FakeAdapter([Outcome(OutcomeStatus.FAILURE)]))
        with self.assertRaises(ValueError):
            registry.register(FakeAdapter([Outcome(OutcomeStatus.FAILURE)]))

    def test_global_and_per_account_limits(self) -> None:
        adapter = FakeAdapter([Outcome(OutcomeStatus.FAILURE)])
        registry = AdapterRegistry()
        registry.register(adapter)
        policy = AttemptPolicy(
            rate_per_second=1000,
            max_total_attempts=3,
            max_attempts_per_account=2,
        )
        scheduler = Scheduler(registry, policy, sleeper=lambda _: None)
        attempts = [
            (job(), Credential("alice", "one")),
            (job(), Credential("alice", "two")),
            (job(), Credential("alice", "three")),
            (job(), Credential("bob", "one")),
            (job(), Credential("bob", "two")),
        ]
        result = scheduler.run(attempts)
        self.assertEqual(result.attempted_count, 3)
        self.assertEqual(result.halt_reason, "max_total_attempts")
        self.assertEqual(adapter.calls, 3)

    def test_account_guard_outcomes_skip_only_same_job_and_username(self) -> None:
        for status in (
            OutcomeStatus.SUCCESS,
            OutcomeStatus.MFA_REQUIRED,
            OutcomeStatus.LOCKED_OUT,
        ):
            with self.subTest(status=status):
                adapter = FakeAdapter([Outcome(status), Outcome(OutcomeStatus.FAILURE)])
                registry = AdapterRegistry()
                registry.register(adapter)
                result = Scheduler(
                    registry,
                    AttemptPolicy(rate_per_second=1000),
                    sleeper=lambda _: None,
                ).run(
                    [
                        (job(), Credential("alice", "one")),
                        (job(), Credential("alice", "two")),
                        (job(), Credential("bob", "two")),
                    ]
                )
                self.assertEqual(result.attempted_count, 2)
                self.assertIsNone(result.halt_reason)

    def test_rate_limited_stops_entire_run(self) -> None:
        adapter = FakeAdapter(
            [Outcome(OutcomeStatus.RATE_LIMITED), Outcome(OutcomeStatus.FAILURE)]
        )
        registry = AdapterRegistry()
        registry.register(adapter)
        result = Scheduler(
            registry,
            AttemptPolicy(rate_per_second=1000),
            sleeper=lambda _: None,
        ).run(
            [
                (job(), Credential("alice", "one")),
                (job(), Credential("bob", "two")),
            ]
        )
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(result.halt_reason, "rate_limited")

    def test_unsupported_job_is_reported_only_once(self) -> None:
        registry = AdapterRegistry()
        result = Scheduler(
            registry,
            AttemptPolicy(rate_per_second=1000),
            sleeper=lambda _: None,
        ).run(
            [
                (job(auth_type="ssh"), Credential("alice", "one")),
                (job(auth_type="ssh"), Credential("alice", "two")),
                (job(auth_type="ssh"), Credential("bob", "three")),
            ]
        )
        self.assertEqual(result.attempted_count, 0)
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(result.attempts[0].outcome.status, OutcomeStatus.UNSUPPORTED)

    def test_unsupported_diagnostic_does_not_spend_parallel_attempt_limit(self) -> None:
        adapter = FakeAdapter([
            Outcome(OutcomeStatus.UNSUPPORTED, evidence={"attempted": False}),
            Outcome(OutcomeStatus.FAILURE),
        ])
        registry = AdapterRegistry()
        registry.register(adapter)
        result = Scheduler(
            registry,
            AttemptPolicy(rate_per_second=1000, max_total_attempts=1),
            max_workers=2,
            sleeper=lambda _: None,
        ).run(
            [
                (job(job_key="unsupported"), Credential("alice", "one")),
                (job(job_key="supported"), Credential("bob", "two")),
            ]
        )

        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(len(result.attempts), 2)

    def test_rate_limit_waits_between_adapter_calls(self) -> None:
        now = [0.0]
        sleeps: list[float] = []

        def clock() -> float:
            return now[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        adapter = FakeAdapter([Outcome(OutcomeStatus.FAILURE)])
        registry = AdapterRegistry()
        registry.register(adapter)
        Scheduler(
            registry,
            AttemptPolicy(rate_per_second=2, max_attempts_per_account=3),
            clock=clock,
            sleeper=sleep,
        ).run(
            [
                (job(), Credential("alice", "one")),
                (job(), Credential("alice", "two")),
            ]
        )
        self.assertEqual(sleeps, [0.5])

    def test_multiple_workers_execute_attempts_concurrently(self) -> None:
        adapter = ConcurrentAdapter()
        registry = AdapterRegistry()
        registry.register(adapter)
        result = Scheduler(
            registry,
            AttemptPolicy(rate_per_second=1000),
            max_workers=2,
        ).run(
            [
                (job(job_key="job-one"), Credential("alice", "one")),
                (job(job_key="job-two"), Credential("bob", "two")),
            ]
        )

        self.assertEqual(result.attempted_count, 2)
        self.assertEqual(adapter.max_active, 2)
        self.assertEqual(
            {attempt.outcome.status for attempt in result.attempts},
            {OutcomeStatus.FAILURE},
        )

    def test_parallel_workers_share_one_global_start_rate(self) -> None:
        now = [0.0]
        sleeps: list[float] = []

        def clock() -> float:
            return now[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        adapter = FakeAdapter([Outcome(OutcomeStatus.FAILURE)])
        registry = AdapterRegistry()
        registry.register(adapter)
        Scheduler(
            registry,
            AttemptPolicy(rate_per_second=2),
            max_workers=2,
            clock=clock,
            sleeper=sleep,
        ).run(
            [
                (job(job_key="job-one"), Credential("alice", "one")),
                (job(job_key="job-two"), Credential("bob", "two")),
            ]
        )

        self.assertEqual(sleeps, [0.5])

    def test_worker_count_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 1"):
            Scheduler(AdapterRegistry(), max_workers=0)

    def test_audit_never_contains_failed_plaintext_password(self) -> None:
        stream = io.StringIO()
        writer = JsonlAuditWriter(stream, correlation_key=b"k" * 32)
        credential = Credential("alice", "Top Secret!")
        outcome = Outcome(
            OutcomeStatus.FAILURE,
            detail="server rejected Top Secret!",
            evidence={"password": "Top Secret!", "nested": ["Top Secret!"]},
        )
        writer.record_attempt(job(), credential, outcome)
        raw = stream.getvalue()
        self.assertNotIn("Top Secret!", raw)
        record = json.loads(raw)
        self.assertEqual(record["outcome"], "failure")
        self.assertEqual(record["evidence"]["password"], "<redacted>")
        self.assertIn("secret_ref", record)

    def test_audit_records_unsupported_preflight_as_check(self) -> None:
        stream = io.StringIO()
        writer = JsonlAuditWriter(stream, correlation_key=b"k" * 32)
        writer.record_attempt(
            job(auth_type="ssh"),
            Credential("alice", "secret"),
            Outcome(
                OutcomeStatus.UNSUPPORTED,
                "adapter unavailable",
                evidence={"attempted": False},
            ),
        )

        record = json.loads(stream.getvalue())
        self.assertEqual(record["event"], "check")
        self.assertFalse(record["attempted"])


if __name__ == "__main__":
    unittest.main()

