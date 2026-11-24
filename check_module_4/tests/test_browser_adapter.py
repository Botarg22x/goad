from __future__ import annotations

import unittest
from unittest.mock import patch

from authchecker.adapters.http import TargetScope
from authchecker.browser import BrowserCheckConfig, BrowserCheckResult
from authchecker.browser_adapter import BrowserAdapter
from authchecker.models import AuthJob, Credential, Outcome, OutcomeStatus


def _job() -> AuthJob:
    return AuthJob(
        job_key="browser-job", report_run_id="test-run", finding_id="test-form",
        kind="web_login_page", auth_type="password_form",
        endpoint="https://example.test/login?from=account", host="example.test",
        port=443, protocol="https",
    )


class BrowserAdapterTests(unittest.TestCase):
    def test_scope_diagnostics_keep_origin_only_without_secret_url_parts(self) -> None:
        def checker(*args, **kwargs):
            return BrowserCheckResult(Outcome(
                OutcomeStatus.UNSUPPORTED,
                evidence={"reason": "scope", "blocked_origin": "https://user:private@other.test:8443/path?token=private#private",
                          "blocked_method": "POST", "blocked_request_type": "fetch"},
            ))

        result = BrowserAdapter(BrowserCheckConfig(), checker=checker).attempt(_job(), Credential("student", "password"))
        self.assertEqual(result.evidence["blocked_origin"], "https://other.test:8443")
        self.assertEqual(result.evidence["blocked_method"], "POST")
        self.assertEqual(result.evidence["blocked_request_type"], "fetch")
        self.assertNotIn("private", str(dict(result.evidence)))

    def test_interruption_cancels_an_already_started_check_before_submission(self) -> None:
        adapter = None

        def checker(_url, credential, **options):
            if credential.username == "interrupt":
                return BrowserCheckResult(Outcome(OutcomeStatus.SKIPPED, evidence={"reason": "interrupted"}))
            adapter.attempt(_job(), Credential("interrupt", "other-password"))
            options["before_submit"](lambda _: self.fail("cancelled check must not wait or submit"))
            self.fail("cancelled check must not release the POST")

        adapter = BrowserAdapter(BrowserCheckConfig(), checker=checker)
        outcome = adapter.attempt(_job(), Credential("pending", "test-password"))
        self.assertEqual(outcome.status, OutcomeStatus.SKIPPED)
        self.assertEqual(outcome.evidence["browser_attempted_count"], 0)
        self.assertTrue(adapter.interrupted)

    def test_each_credential_uses_a_separate_checker_call_with_configuration(self) -> None:
        config = BrowserCheckConfig(headless=True, proxy="http://127.0.0.1:8085")
        scope = TargetScope("example.test")
        calls = []
        progress = []

        def checker(url, credential, **options):
            calls.append((url, credential, options))
            options["on_progress"]("loading " + credential.password)
            return BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)

        adapter = BrowserAdapter(config, target_scope=scope, on_progress=progress.append, checker=checker)
        first = Credential("student", "first-password")
        second = Credential("student", "second-password")
        adapter.attempt(_job(), first)
        adapter.attempt(_job(), second)

        self.assertEqual([call[1] for call in calls], [first, second])
        self.assertEqual([call[0] for call in calls], [_job().endpoint] * 2)
        self.assertTrue(all(call[2]["config"] is config for call in calls))
        self.assertTrue(all(call[2]["target_scope"] is scope for call in calls))
        self.assertIsNot(calls[0][2]["before_submit"], calls[1][2]["before_submit"])
        self.assertEqual(progress, ["loading <redacted>"] * 2)

    def test_outcome_evidence_is_whitelisted_and_does_not_include_session_secrets(self) -> None:
        password = "secret value!"

        def checker(*args, **kwargs):
            return BrowserCheckResult(
                Outcome(
                    OutcomeStatus.SUCCESS, "accepted " + password,
                    evidence={"reason": "authenticated_marker", "http_status": 200,
                              "cookies": "private cookie", "body": password,
                              "nested": {"storage": "private"}},
                ),
                attempted_count=9,
                final_url="https://user:private@example.test/account?token=private#private",
                fields=("username", "password\n" + password),
            )

        result = BrowserAdapter(BrowserCheckConfig(), checker=checker).attempt(_job(), Credential("student", password))
        self.assertEqual(result.detail, "accepted <redacted>")
        self.assertEqual(dict(result.evidence), {
            "browser_attempted_count": 1,
            "final_url": "https://example.test/account?token=private",
            "fields": ["username", "password <redacted>"],
            "reason": "authenticated_marker", "http_status": 200,
        })

    def test_no_submission_has_zero_count_and_does_not_spend_rate_slot(self) -> None:
        calls = 0
        clock = [10.0]
        submitted_at = []
        waits = []

        def waiter(seconds):
            waits.append(seconds)
            clock[0] += seconds

        def checker(*args, **options):
            nonlocal calls
            calls += 1
            if calls == 1:
                return BrowserCheckResult(Outcome(OutcomeStatus.UNSUPPORTED))
            options["before_submit"](waiter)
            submitted_at.append(clock[0])
            return BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)

        adapter = BrowserAdapter(BrowserCheckConfig(), rate_per_second=2, checker=checker)
        with patch("authchecker.browser_adapter.time.monotonic", side_effect=lambda: clock[0]):
            first = adapter.attempt(_job(), Credential("student", "a-password"))
            adapter.attempt(_job(), Credential("student", "b-password"))
            clock[0] += 0.2
            adapter.attempt(_job(), Credential("student", "c-password"))
        self.assertEqual(first.evidence["browser_attempted_count"], 0)
        self.assertEqual(submitted_at, [10.0, 10.5])
        self.assertEqual(len(waits), 1)
        self.assertAlmostEqual(waits[0], 0.3)

    def test_rate_waiter_does_not_hold_global_lock_and_rechecks_other_submissions(self) -> None:
        clock = [20.0]
        adapter = BrowserAdapter(BrowserCheckConfig(), rate_per_second=2)
        waited = []

        def waiter(seconds):
            self.assertTrue(adapter._submit_lock.acquire(blocking=False))
            adapter._submit_lock.release()
            waited.append(seconds)
            clock[0] += seconds
            if len(waited) == 1:
                # A different browser used the newly available slot while this
                # browser was waiting, so the caller must wait another interval.
                adapter._before_submit(lambda _: self.fail("slot should be free"))

        with patch("authchecker.browser_adapter.time.monotonic", side_effect=lambda: clock[0]):
            adapter._before_submit(lambda _: self.fail("first slot should be free"))
            adapter._before_submit(waiter)
        self.assertEqual(waited, [0.5, 0.5])

    def test_checker_exception_does_not_leak_exception_body(self) -> None:
        def checker(*args, **options):
            options["before_submit"](lambda _: None)
            raise RuntimeError("raw HTML cookie=private; password=top-secret")

        result = BrowserAdapter(BrowserCheckConfig(), checker=checker).attempt(_job(), Credential("student", "top-secret"))
        self.assertEqual(result.status, OutcomeStatus.ERROR)
        self.assertEqual(result.detail, "Browser check failed: RuntimeError")
        self.assertEqual(result.evidence["browser_attempted_count"], 1)
        self.assertNotIn("private", str(dict(result.evidence)))

    def test_invalid_rates_are_rejected(self) -> None:
        for rate in (0, -1, float("nan"), float("inf")):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                BrowserAdapter(BrowserCheckConfig(), rate_per_second=rate)


if __name__ == "__main__":
    unittest.main()
