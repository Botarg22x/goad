from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from authchecker.browser import BrowserCheckConfig, BrowserCheckResult
from authchecker.browser_http import AdaptiveBrowserChecker, BrowserHttpChecker
from authchecker.models import Credential, Outcome, OutcomeStatus


class BrowserHttpCheckerTests(unittest.TestCase):
    def test_adaptive_checker_uses_native_browser_only_after_safe_capture_failure(self) -> None:
        checker = AdaptiveBrowserChecker()
        capture_failure = BrowserCheckResult(
            Outcome(
                OutcomeStatus.UNSUPPORTED,
                "capture failed",
                evidence={"reason": "capture_error"},
            )
        )
        native = BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)
        progress = []
        with (
            patch.object(checker, "_http", return_value=capture_failure) as captured,
            patch("authchecker.browser_http.run_browser_check", return_value=native) as browser,
        ):
            result = checker(
                "https://example.test/login",
                Credential("student", "wrong"),
                config=BrowserCheckConfig(),
                on_progress=progress.append,
            )
        self.assertIs(result, native)
        captured.assert_called_once()
        browser.assert_called_once()
        self.assertTrue(any("изолированном браузере" in item for item in progress))

    def test_adaptive_checker_switches_before_post_for_javascript_login_page(self) -> None:
        checker = AdaptiveBrowserChecker()
        preflight = BrowserCheckResult(
            Outcome(OutcomeStatus.UNSUPPORTED, evidence={"reason": "browser_required"}),
            attempted_count=0,
        )
        native = BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)
        progress = []
        with (
            patch.object(checker, "_http", return_value=preflight) as http,
            patch("authchecker.browser_http.run_browser_check", return_value=native) as browser,
        ):
            result = checker(
                "https://example.test/login",
                Credential("student", "wrong"),
                config=BrowserCheckConfig(),
                on_progress=progress.append,
            )
        self.assertIs(result, native)
        http.assert_called_once()
        browser.assert_called_once()
        self.assertTrue(any("JavaScript" in item for item in progress))

    def test_adaptive_checker_does_not_retry_challenge_in_native_browser(self) -> None:
        checker = AdaptiveBrowserChecker()
        challenge = BrowserCheckResult(
            Outcome(
                OutcomeStatus.UNSUPPORTED,
                "challenge",
                evidence={"reason": "challenge"},
            )
        )
        with (
            patch.object(checker, "_http", return_value=challenge),
            patch("authchecker.browser_http.run_browser_check") as browser,
        ):
            result = checker(
                "https://example.test/login",
                Credential("student", "wrong"),
                config=BrowserCheckConfig(),
            )
        self.assertIs(result, challenge)
        browser.assert_not_called()

    def test_prepares_once_and_replays_each_credential_with_rate_hook(self) -> None:
        credentials = [Credential("student", "wrong"), Credential("student", "correct")]
        template = object()
        snapshot = object()
        config = BrowserCheckConfig(headless=True)
        progress = []
        gate = object()

        def capture(url, credential, **options):
            self.assertNotIn("before_submit", options)
            options["on_capture"](snapshot)
            return BrowserCheckResult(Outcome(OutcomeStatus.SKIPPED, evidence={"reason": "request_captured"}))

        replay_result = BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)
        checker = BrowserHttpChecker(timeout_seconds=7)
        with patch("authchecker.browser_http.run_browser_check", side_effect=capture) as browser, patch(
            "authchecker.browser_http.HttpReplayTemplate.from_capture", return_value=template,
        ) as factory, patch("authchecker.browser_http.run_http_replay", return_value=replay_result) as replay:
            for credential in credentials:
                self.assertIs(checker("https://example.test/login", credential, config=config, on_progress=progress.append, before_submit=gate), replay_result)
        self.assertEqual(browser.call_count, 1)
        factory.assert_called_once_with(snapshot, credentials[0])
        self.assertEqual([call.args[1] for call in replay.call_args_list], credentials)
        self.assertTrue(all(call.args[0] is template and call.kwargs["timeout_seconds"] == 7 and call.kwargs["before_submit"] is gate for call in replay.call_args_list))
        self.assertTrue(any("HTTP" in line for line in progress))

    def test_concurrent_callers_share_only_preparation(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def capture(*args, **options):
            started.set()
            self.assertTrue(release.wait(3))
            options["on_capture"](object())
            return BrowserCheckResult(Outcome(OutcomeStatus.SKIPPED, evidence={"reason": "request_captured"}))

        checker = BrowserHttpChecker()
        with patch("authchecker.browser_http.run_browser_check", side_effect=capture) as browser, patch(
            "authchecker.browser_http.HttpReplayTemplate.from_capture", return_value=object(),
        ), patch("authchecker.browser_http.run_http_replay", return_value=BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), 1)) as replay:
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(checker, "https://example.test/login", Credential("student", "a"), config=BrowserCheckConfig())
                self.assertTrue(started.wait(3))
                second = executor.submit(checker, "https://example.test/login", Credential("student", "b"), config=BrowserCheckConfig())
                release.set()
                self.assertEqual(first.result().attempted_count, 1)
                self.assertEqual(second.result().attempted_count, 1)
        self.assertEqual(browser.call_count, 1)
        self.assertEqual(replay.call_count, 2)

    def test_failed_capture_is_cached_without_http_submission(self) -> None:
        failure = BrowserCheckResult(Outcome(OutcomeStatus.UNSUPPORTED, "Защитная страница", evidence={"reason": "challenge"}))
        checker = BrowserHttpChecker()
        with patch("authchecker.browser_http.run_browser_check", return_value=failure) as browser, patch("authchecker.browser_http.run_http_replay") as replay:
            for password in ("a", "b"):
                self.assertIs(checker("https://example.test/login", Credential("student", password), config=BrowserCheckConfig()), failure)
        self.assertEqual(browser.call_count, 1)
        replay.assert_not_called()

    def test_copied_server_session_is_not_used_by_parallel_http_attempts(self) -> None:
        first_inside = threading.Event()
        second_started = threading.Event()
        second_inside = threading.Event()
        release_first = threading.Event()
        checker = BrowserHttpChecker()
        config = BrowserCheckConfig()

        def capture(*args, **options):
            options["on_capture"](object())
            return BrowserCheckResult(Outcome(OutcomeStatus.SKIPPED, evidence={"reason": "request_captured"}))

        def replay(template, credential, **options):
            if credential.password == "first":
                first_inside.set()
                self.assertTrue(release_first.wait(3))
            else:
                second_inside.set()
            return BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), 1)

        def second():
            second_started.set()
            return checker("https://example.test/login", Credential("student", "second"), config=config)

        with patch("authchecker.browser_http.run_browser_check", side_effect=capture), patch(
            "authchecker.browser_http.HttpReplayTemplate.from_capture", return_value=object(),
        ), patch("authchecker.browser_http.run_http_replay", side_effect=replay):
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(checker, "https://example.test/login", Credential("student", "first"), config=config)
                self.assertTrue(first_inside.wait(3))
                pending = executor.submit(second)
                self.assertTrue(second_started.wait(3))
                try:
                    self.assertFalse(second_inside.wait(0.05))
                finally:
                    release_first.set()
                self.assertEqual(first.result().attempted_count, 1)
                self.assertEqual(pending.result().attempted_count, 1)
                self.assertTrue(second_inside.is_set())

    def test_capture_errors_do_not_leak_secrets_or_retry_bootstrap(self) -> None:
        checker = BrowserHttpChecker()
        with patch("authchecker.browser_http.run_browser_check", side_effect=RuntimeError("cookie=private; password=secret")) as browser, patch("authchecker.browser_http.run_http_replay") as replay:
            for _ in range(2):
                result = checker("https://example.test/login", Credential("student", "secret"), config=BrowserCheckConfig())
                self.assertEqual(result.attempted_count, 0)
                self.assertEqual(result.outcome.evidence["reason"], "capture_error")
                self.assertNotIn("private", result.outcome.detail)
                self.assertNotIn("secret", result.outcome.detail)
        self.assertEqual(browser.call_count, 1)
        replay.assert_not_called()

    def test_never_reuses_session_with_different_url_or_configuration(self) -> None:
        checker = BrowserHttpChecker()
        config = BrowserCheckConfig()
        with patch("authchecker.browser_http.run_browser_check", return_value=BrowserCheckResult(Outcome(OutcomeStatus.UNSUPPORTED))) as browser:
            checker("https://example.test/login", Credential("student", "a"), config=config)
            for url, other_config in (("https://other.test/login", config), ("https://example.test/login", BrowserCheckConfig(headless=True))):
                result = checker(url, Credential("student", "b"), config=other_config)
                self.assertEqual(result.outcome.evidence["reason"], "capture_target")
        self.assertEqual(browser.call_count, 1)

    def test_invalid_timeout_rejected(self) -> None:
        for timeout in (0, -1, 61, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                BrowserHttpChecker(timeout)

    def test_unexpected_browser_submission_is_counted_and_not_replayed(self) -> None:
        checker = BrowserHttpChecker()
        native = BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), 1, "https://example.test/login", ("user", "password"))
        with patch("authchecker.browser_http.run_browser_check", return_value=native), patch("authchecker.browser_http.run_http_replay") as replay:
            result = checker("https://example.test/login", Credential("student", "wrong"), config=BrowserCheckConfig())
        self.assertEqual(result.attempted_count, 1)
        self.assertEqual(result.outcome.evidence["reason"], "capture_error")
        replay.assert_not_called()


if __name__ == "__main__":
    unittest.main()
