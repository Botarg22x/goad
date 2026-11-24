from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from authchecker.cli import (
    _AttemptProgress,
    _attempt_budget,
    _attempts,
    _compact_live_lines,
    _unsupported_page_message,
    build_parser,
    main as _main,
)
from authchecker.browser import BrowserCheckResult
from authchecker.importer import parse_report
from authchecker.models import AuthJob, Credential, Outcome, OutcomeStatus
from authchecker.scheduler import ScheduleResult, ScheduledAttempt

from support import valid_finding, valid_report


def main(argv: list[str]) -> int:
    """Pass explicit live settings in tests that exercise unrelated behavior."""
    live = (argv and argv[0].startswith("-") and "--dry-run" not in argv) or "--live" in argv
    if not live:
        return _main(argv)
    options = list(argv)
    if "--max-per-account" not in options:
        options.extend(("--max-per-account", "3"))
    if "--rate" not in options and "--slow" not in options:
        options.extend(("--rate", "1"))
    return _main(options)


class CliTests(unittest.TestCase):
    def test_terminal_progress_rewrites_one_line_and_keeps_redirects_clean(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self) -> bool:
                return True

        stream = TtyBuffer()
        progress = _AttemptProgress(_attempt_budget(1, 1, 5, 3, None), stream=stream)
        progress.start()
        progress.record(None, 1)
        progress.record(None, 2)
        progress.finish()
        rendered = stream.getvalue()
        self.assertIn("Отправлено: 0/3; осталось не более 3", rendered)
        self.assertIn("Отправлено: 2/3; осталось не более 1", rendered)
        self.assertTrue(rendered.endswith("Завершено: отправлено 2; проверено 2\n"))
        self.assertIn("\r\x1b[2K", rendered)

        redirected = io.StringIO()
        quiet = _AttemptProgress(3, stream=redirected)
        quiet.start()
        quiet.record(None, 1)
        quiet.finish()
        self.assertEqual(redirected.getvalue(), "")

    def test_file_login_progress_shows_current_login_and_attempt_limit(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self) -> bool:
                return True

        stream = TtyBuffer()
        progress = _AttemptProgress(6, per_login_budget=3, stream=stream)
        progress.start()
        progress.record(ScheduledAttempt(None, Credential("alice", "private-password"),
                                         Outcome(OutcomeStatus.FAILURE, "отказ")), 1)
        progress.record(ScheduledAttempt(None, Credential("alice", "private-password"),
                                         Outcome(OutcomeStatus.UNSUPPORTED, "не отправлено")), 1)
        progress.record(ScheduledAttempt(None, Credential("bob", "private-password"),
                                         Outcome(OutcomeStatus.SUCCESS, "успех")), 2)
        progress.finish()
        rendered = stream.getvalue()
        self.assertIn("Логин из файла: ожидание — 0/3; всего: 0/6", rendered)
        self.assertIn("Логин из файла: «alice» — 1/3; всего: 1/6", rendered)
        self.assertIn("Логин из файла: «bob» — 1/3; всего: 2/6", rendered)
        self.assertNotIn("private-password", rendered)

        quiet_stream = io.StringIO()
        quiet = _AttemptProgress(6, per_login_budget=3, stream=quiet_stream)
        quiet.start()
        quiet.record(ScheduledAttempt(None, Credential("alice", "private-password"),
                                      Outcome(OutcomeStatus.FAILURE, "отказ")), 1)
        quiet.finish()
        self.assertEqual(quiet_stream.getvalue(), "")

    def test_success_pair_is_printed_before_run_finishes(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self) -> bool:
                return True

        progress_stream = TtyBuffer()
        success_stream = io.StringIO()
        progress = _AttemptProgress(
            3, stream=progress_stream, success_stream=success_stream,
        )
        job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        progress.start()
        progress.record(
            ScheduledAttempt(
                job, Credential("student", "wrong"), Outcome(OutcomeStatus.FAILURE),
            ),
            1,
        )
        self.assertEqual(success_stream.getvalue(), "")
        progress.record(
            ScheduledAttempt(
                job, Credential("student", "secret\x1b[31m"), Outcome(OutcomeStatus.SUCCESS),
            ),
            2,
        )
        self.assertEqual(
            success_stream.getvalue(),
            "[УСПЕШНО] http://127.0.0.1:8080/login — "
            "логин: student — пароль: secret\\u001b[31m\n",
        )
        self.assertNotIn("Завершено", progress_stream.getvalue())
        progress.finish()

    def test_ambiguous_pair_is_printed_before_run_finishes(self) -> None:
        class TtyBuffer(io.StringIO):
            def isatty(self) -> bool:
                return True

        progress_stream = TtyBuffer()
        notice_stream = io.StringIO()
        progress = _AttemptProgress(2, stream=progress_stream, success_stream=notice_stream)
        job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        progress.start()
        progress.record(
            ScheduledAttempt(job, Credential("student", "wrong"), Outcome(OutcomeStatus.FAILURE)),
            1,
        )
        self.assertEqual(notice_stream.getvalue(), "")
        progress.record(
            ScheduledAttempt(
                job, Credential("student", "maybe\x1b[31m"),
                Outcome(
                    OutcomeStatus.AMBIGUOUS,
                    "Неизвестный ответ для maybe\x1b[31m",
                    evidence={"attempted": True, "post_status": 302, "http_status": 200},
                ),
            ),
            2,
        )
        self.assertEqual(
            notice_stream.getvalue(),
            "[РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН] http://127.0.0.1:8080/login — "
            "логин: student — пароль: maybe\\u001b[31m; POST 302; итоговый HTTP 200; "
            "Неизвестный ответ для <redacted>; проверьте ответ вручную\n",
        )
        self.assertNotIn("Завершено", progress_stream.getvalue())
        progress.finish()

    def test_ambiguous_notice_uses_stderr_when_json_output_is_selected(self) -> None:
        progress_stream = io.StringIO()
        progress = _AttemptProgress(1, stream=progress_stream)
        job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        progress.record(
            ScheduledAttempt(
                job, Credential("student", "secret"),
                Outcome(OutcomeStatus.AMBIGUOUS, "Вход не подтверждён", evidence={"attempted": True}),
            ),
            1,
        )
        self.assertIn("логин: student — пароль: secret", progress_stream.getvalue())
        self.assertIn("[РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН]", progress_stream.getvalue())

    def test_ambiguous_preflight_does_not_claim_password_was_sent(self) -> None:
        notice_stream = io.StringIO()
        progress = _AttemptProgress(1, stream=io.StringIO(), success_stream=notice_stream)
        job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        progress.record(
            ScheduledAttempt(
                job, Credential("student", "secret"),
                Outcome(OutcomeStatus.AMBIGUOUS, "Форма изменилась", evidence={"attempted": False}),
            ),
            0,
        )
        self.assertIn("пароль не отправлялся", notice_stream.getvalue())
        self.assertNotIn("secret", notice_stream.getvalue())

    def test_short_pages_file_checks_only_supplied_urls_with_template(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pages = Path(directory, "auth-links.txt")
            pages.write_text(
                "# PointFinder links\nhttps://example.test/bitrix/admin/\n"
                "https://example.test/bitrix/admin/\n",
                encoding="utf-8",
            )
            report = parse_report(valid_report())
            output = io.StringIO()
            with (
                patch("authchecker.cli.discover_login_pages", return_value=report) as discover,
                patch("authchecker.cli._run_live", return_value=0) as run_live,
                redirect_stdout(output),
            ):
                code = main(["-u", str(pages), "-t", "bitrix", "-l", "admin", "-p", "secret"])

            self.assertEqual(code, 0)
            self.assertEqual(discover.call_args.args[0], ["https://example.test/bitrix/admin/"])
            self.assertEqual(discover.call_args.kwargs["template"], "bitrix")
            self.assertEqual(discover.call_args.kwargs["target_scope"].domain, "example.test")
            self.assertIs(run_live.call_args.kwargs["report_override"], report)
            args = run_live.call_args.args[0]
            self.assertEqual(args.audit.parent, pages.parent)
            self.assertEqual(args.rate, 1.0)
            self.assertTrue(args.compact)

    def test_short_url_accepts_http_basic_without_product_template(self) -> None:
        target = "https://example.test/private"
        finding = valid_finding(auth_type="http_basic", endpoint=target,
                                metadata={"status_code": 401, "authentication_scheme": "Basic"})
        finding["kind"] = "http_auth_challenge"
        finding["evidence"][0]["rule_id"] = "http.auth.challenge"
        report = parse_report(valid_report(findings=[finding]))

        with (
            patch("authchecker.cli.discover_login_pages", return_value=report) as discover,
            patch("authchecker.cli._run_live", return_value=0) as run_live,
            redirect_stdout(io.StringIO()),
        ):
            code = main(["-u", target, "-l", "student", "-p", "test-pass"])

        self.assertEqual(code, 0)
        self.assertIsNone(discover.call_args.kwargs["template"])
        self.assertIs(run_live.call_args.kwargs["report_override"], report)

    def test_pages_file_requires_explicit_scope_for_multiple_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pages = Path(directory, "links.txt")
            pages.write_text(
                "https://a.example.test/login\nhttps://b.example.test/login\n",
                encoding="utf-8",
            )
            error = io.StringIO()
            with patch("authchecker.cli.discover_login_pages") as discover, redirect_stderr(error):
                code = main(["-u", str(pages), "-t", "bitrix", "-l", "admin", "-p", "secret"])

        self.assertEqual(code, 2)
        self.assertIn("несколько хостов", error.getvalue())
        discover.assert_not_called()

    def test_pages_source_without_matching_form_never_runs_authorization(self) -> None:
        report = parse_report(valid_report(findings=[]))
        error = io.StringIO()
        with (
            patch("authchecker.cli.discover_login_pages", return_value=report),
            patch("authchecker.cli._run_live") as run_live,
            redirect_stderr(error),
        ):
            code = main(["-u", "https://example.test/bitrix/admin/", "-t", "bitrix", "-l", "admin", "-p", "secret"])

        self.assertEqual(code, 2)
        self.assertIn("попытки авторизации не выполнялись", error.getvalue())
        run_live.assert_not_called()

    def test_short_report_run_infers_scope_audit_without_implicit_slow_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "bitrix-report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            output = io.StringIO()
            with patch("authchecker.cli._run_live", return_value=0) as run_live, redirect_stdout(output):
                code = main(["-r", str(report), "-l", "student", "-p", "secret"])

            self.assertEqual(code, 0)
            args = run_live.call_args.args[0]
            self.assertEqual(args.scope_domain, "example.test")
            self.assertEqual(args.rate, 1.0)
            self.assertEqual(args.threads, 1)
            self.assertTrue(args.compact)
            self.assertEqual(args.audit.parent, report.parent)
            self.assertIn(str(args.audit), output.getvalue())

    def test_short_report_run_respects_explicit_limits_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            audit = Path(directory, "chosen-audit.jsonl")
            with patch("authchecker.cli._run_live", return_value=0) as run_live, redirect_stdout(io.StringIO()):
                code = main([
                    "-r", str(report), "-l", "student", "-p", "secret",
                    "--scope-domain", "example.test", "--audit", str(audit),
                    "--rate", "2", "--threads", "2", "--max-total", "2",
                ])

            self.assertEqual(code, 0)
            args = run_live.call_args.args[0]
            self.assertFalse(args.slow)
            self.assertEqual((args.rate, args.threads, args.max_total), (2.0, 2, 2))
            self.assertEqual(args.audit, audit)

    def test_short_report_run_accepts_candidate_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            logins = Path(directory, "logins.txt")
            passwords = Path(directory, "passwords.txt")
            logins.write_text("student\n", encoding="utf-8")
            passwords.write_text("secret\n", encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live, redirect_stdout(io.StringIO()):
                code = main([
                    "-r", str(report), "--logins", str(logins),
                    "--passwords", str(passwords),
                ])

            self.assertEqual(code, 0)
            args = run_live.call_args.args[0]
            self.assertEqual(args.logins_path, logins)
            self.assertEqual(args.passwords, passwords)

    def test_short_p_accepts_password_file_without_loading_it_as_a_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            passwords = Path(directory, "passwords.txt")
            passwords.write_text("wrong\nsecret\n", encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live, redirect_stdout(io.StringIO()):
                code = main(["-r", str(report), "-l", "student", "-p", str(passwords)])

            self.assertEqual(code, 0)
            self.assertEqual(run_live.call_args.args[0].passwords, passwords)
            self.assertEqual(run_live.call_args.args[3], ())

    def test_short_l_accepts_login_file_without_loading_it_as_a_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            logins = Path(directory, "logins.txt")
            logins.write_text("alice\nbob\n", encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live, redirect_stdout(io.StringIO()):
                code = main(["-r", str(report), "-l", str(logins), "-p", "secret"])

            self.assertEqual(code, 0)
            self.assertEqual(run_live.call_args.args[0].logins_path, logins)
            self.assertEqual(run_live.call_args.args[2], ())

    def test_plan_l_file_counts_candidates_and_explicit_login_stays_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            logins = Path(directory, "logins.txt")
            logins.write_text("alice\nbob\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["plan", "--report", str(report), "-l", str(logins), "-p", "secret"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["login_count"], 2)

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["plan", "--report", str(report), "--login", str(logins), "-p", "secret"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["login_count"], 1)

    def test_l_file_mistakes_fail_before_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            logins = Path(directory, "logins.txt")
            logins.write_text("alice\n", encoding="utf-8")
            cases = (
                (["-l", str(Path(directory, "missing.txt"))], "не найден"),
                (["-l", directory], "каталог"),
                (["-l", str(logins), "-l", "bob"], "нельзя смешивать"),
            )
            for options, expected in cases:
                error = io.StringIO()
                with self.subTest(options=options), patch("authchecker.cli._run_live") as run_live, redirect_stderr(error):
                    code = main(["-r", str(report), *options, "-p", "secret"])
                self.assertEqual(code, 2)
                self.assertIn(expected, error.getvalue())
                run_live.assert_not_called()

    def test_plan_p_file_counts_candidates_and_explicit_password_stays_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            passwords = Path(directory, "passwords.txt")
            passwords.write_text("wrong\nsecret\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["plan", "--report", str(report), "-l", "student", "-p", str(passwords)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["password_count"], 2)

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["plan", "--report", str(report), "-l", "student", "--password", str(passwords)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["password_count"], 1)

    def test_p_file_mistakes_fail_before_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            passwords = Path(directory, "passwords.txt")
            passwords.write_text("secret\n", encoding="utf-8")
            cases = (
                (["-p", str(Path(directory, "missing.txt"))], "не найден"),
                (["-p", directory], "каталог"),
                (["-p", str(passwords), "-p", "secret"], "нельзя смешивать"),
            )
            for options, expected in cases:
                error = io.StringIO()
                with self.subTest(options=options), patch("authchecker.cli._run_live") as run_live, redirect_stderr(error):
                    code = main(["-r", str(report), "-l", "student", *options])
                self.assertEqual(code, 2)
                self.assertIn(expected, error.getvalue())
                run_live.assert_not_called()

    def test_short_report_run_requires_explicit_scope_for_multiple_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            second = valid_finding(
                finding_id="auth-fedcba9876543210", endpoint="https://other.test/login",
            )
            second["host"] = "other.test"
            payload = valid_report(findings=[valid_finding(), second])
            payload["scope"] = ["example.test", "other.test"]
            report.write_text(json.dumps(payload), encoding="utf-8")
            error = io.StringIO()
            with patch("authchecker.cli._run_live") as run_live, redirect_stderr(error):
                code = main(["-r", str(report), "-l", "student", "-p", "secret"])

            self.assertEqual(code, 2)
            self.assertIn("несколько хостов", error.getvalue())
            run_live.assert_not_called()

    def test_short_report_run_does_not_submit_without_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report(findings=[])), encoding="utf-8")
            error = io.StringIO()
            with patch("authchecker.cli._run_live") as run_live, redirect_stderr(error):
                code = main(["-r", str(report), "-l", "student", "-p", "secret"])

            self.assertEqual(code, 2)
            self.assertIn("нет поддерживаемых точек", error.getvalue())
            run_live.assert_not_called()

    def test_short_dry_run_uses_same_auth_types_as_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["-r", str(report), "-l", "student", "-p", "secret", "--dry-run"])

            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["supported_auth_types"],
                             ["http_basic", "password_form"])

    def test_total_attempt_limit_is_optional(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live:
                code = main([
                    "run", "--live", "--report", str(report),
                    "--login", "student", "--password", "secret",
                    "--audit", str(Path(directory, "audit.jsonl")),
                ])

        self.assertEqual(code, 0)
        self.assertIsNone(run_live.call_args.args[0].max_total)

    def test_live_has_no_small_default_attempt_limit_and_uses_one_request_per_second(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            base = ["-r", str(report), "-l", "student", "-p", "secret"]
            with patch("authchecker.cli._run_live", return_value=0) as run_live:
                code = _main(base)
            self.assertEqual(code, 0)
            delegated = run_live.call_args.args[0]
            self.assertGreater(delegated.max_per_account, 3)
            self.assertEqual(delegated.rate, 1.0)
            self.assertEqual(delegated.threads, 1)

    def test_live_without_explicit_attempt_limit_reaches_scheduler_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            audit = Path(directory, "audit.jsonl")
            with patch("authchecker.cli.Scheduler.run", return_value=ScheduleResult((), 0, None)), redirect_stdout(io.StringIO()):
                code = _main([
                    "run", "--live", "--report", str(report),
                    "--login", "student", "--password", "secret",
                    "--scope-domain", "example.test", "--audit", str(audit),
                ])
            self.assertEqual(code, 0)
            started = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
            self.assertGreater(started["max_attempts_per_account"], 3)
            self.assertEqual(started["rate_per_second"], 1.0)

    def test_explicit_slow_mode_needs_no_rate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live:
                code = _main([
                    "-r", str(report), "-l", "student", "-p", "secret",
                    "--max-per-account", "2", "--slow",
                ])
        self.assertEqual(code, 0)
        self.assertEqual(run_live.call_args.args[0].rate, 1.0 / 15.0)

    def test_help_is_russian_and_explains_commands(self) -> None:
        rendered = build_parser().format_help()

        self.assertIn("Использование:", rendered)
        self.assertIn("# ==================== ОСНОВНОЕ", rendered)
        self.assertIn("authchecker validate report.json", rendered)
        self.assertIn("--max-per-account", rendered)
        self.assertNotIn("Validate and perform", rendered)

    def test_slow_caps_live_rate_and_threads_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text(json.dumps(valid_report()), encoding="utf-8")
            with patch("authchecker.cli._run_live", return_value=0) as run_live:
                code = main([
                    "run", "--live", "--report", str(report),
                    "--login", "student", "--password", "secret",
                    "--audit", str(Path(directory, "audit.jsonl")),
                    "--slow", "--rate", "8", "--threads", "7",
                ])

        self.assertEqual(code, 0)
        delegated = run_live.call_args.args[0]
        self.assertEqual(delegated.rate, 1.0 / 15.0)
        self.assertEqual(delegated.threads, 1)

    def test_browser_scope_stop_explains_skipped_password_and_safe_diagnostics(self) -> None:
        blocked = BrowserCheckResult(Outcome(
            OutcomeStatus.UNSUPPORTED, "Blocked request outside scope",
            evidence={
                "reason": "scope", "blocked_origin": "https://outside.example/submit?token=private-token",
                "blocked_method": "POST", "blocked_request_type": "fetch",
                "body": "private-body", "cookies": "private-cookie",
            },
        ))
        with tempfile.TemporaryDirectory() as directory:
            data, browser, events, report = self._browser_cli(
                directory,
                ["--login", "student", "--password", "first-secret", "--password", "second-secret"],
                result=blocked,
            )
            browser.assert_called_once()
            self.assertEqual(data["checked_count"], 1)
            self.assertEqual(data["attempted_count"], 0)
            self.assertEqual(data["halt_reason"], "unsupported:scope")
            self.assertEqual(data["results"][0]["blocked_origin"], "https://outside.example")
            self.assertEqual(data["blocked_method"], "POST")
            self.assertEqual(data["blocked_request_type"], "fetch")
            self.assertEqual(events[-1]["halt_reason"], "unsupported:scope")
            self.assertEqual(events[1]["blocked_origin"], "https://outside.example")
            serialized = report.read_text(encoding="utf-8") + json.dumps(events)
            for secret in ("first-secret", "second-secret", "private-token", "private-body", "private-cookie"):
                self.assertNotIn(secret, serialized)

    def test_browser_scope_stop_is_visible_in_compact_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            blocked = BrowserCheckResult(Outcome(
                OutcomeStatus.UNSUPPORTED, "Blocked request outside scope",
                evidence={"reason": "scope", "blocked_origin": "https://outside.example", "blocked_method": "POST", "blocked_request_type": "fetch"},
            ))
            with patch("authchecker.cli.run_browser_check", return_value=blocked) as check, redirect_stdout(output):
                code = main([
                    "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "first-secret", "--password", "second-secret",
                    "--audit", str(Path(directory, "audit.jsonl")), "--compact",
                ])
            self.assertEqual(code, 0)
            check.assert_called_once()
            self.assertIn("POST https://outside.example (fetch)", output.getvalue())
            self.assertIn("остановка: unsupported:scope", output.getvalue())

    def test_browser_http_creates_one_shared_checker_and_keeps_bounded_batch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            report = Path(directory, "hybrid-report.json")
            audit = Path(directory, "hybrid-audit.jsonl")
            results = [
                BrowserCheckResult(Outcome(OutcomeStatus.FAILURE, "Invalid password"), attempted_count=1),
                BrowserCheckResult(Outcome(OutcomeStatus.SUCCESS, "Signed in", evidence={"cookies": "private-cookie", "body": "private-body"}), attempted_count=1, final_url="http://127.0.0.1:8080/account?token=private-token", fields=("username", "password")),
            ]
            with (
                patch("authchecker.cli.BrowserHttpChecker") as factory,
                patch("authchecker.cli.run_browser_check", side_effect=AssertionError("no per-pair browser")),
                patch("authchecker.cli.discover_login_url", side_effect=AssertionError("no PointFinder discovery")),
                redirect_stdout(output),
            ):
                factory.return_value.side_effect = results
                code = main([
                    "run", "--live", "--browser-http", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "wrong-secret", "--password", "correct-secret",
                    "--audit", str(audit), "--save-report", str(report),
                    "--headless", "--browser-timeout", "90", "--timeout", "20",
                    "--success-selector", "#logout", "--failure-selector", "#error",
                    "--max-total", "2", "--max-per-account", "2", "--rate", "10", "--threads", "2",
                ])
            self.assertEqual(code, 0)
            factory.assert_called_once_with(timeout_seconds=20.0)
            self.assertEqual(factory.return_value.call_count, 2)
            config = factory.return_value.call_args.kwargs["config"]
            self.assertTrue(config.headless)
            self.assertEqual(config.timeout_seconds, 90.0)
            self.assertEqual(config.success_selector, "#logout")
            self.assertEqual(config.failure_selector, "#error")
            data = json.loads(output.getvalue())
            self.assertEqual(data["mode"], "browser_http")
            self.assertEqual(data["transport"], "http")
            self.assertEqual(data["checked_count"], 2)
            self.assertEqual(data["attempted_count"], 2)
            self.assertEqual(data["outcomes"], {"failure": 1, "success": 1})
            self.assertEqual(data["successes"][0]["password"], "correct-secret")
            events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[0]["mode"], "browser_http")
            self.assertEqual(events[0]["transport"], "http")
            self.assertEqual(sum(event["event"] == "attempt" for event in events), 2)
            report_data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(report_data["mode"], "browser_http")
            serialized = audit.read_text(encoding="utf-8") + report.read_text(encoding="utf-8")
            for secret in ("wrong-secret", "correct-secret", "private-cookie", "private-body"):
                self.assertNotIn(secret, serialized)
            self.assertIn("private-token", serialized)

    def test_browser_http_and_browser_flags_are_exclusive(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main([
                "run", "--live", "--browser", "--browser-http", "--url", "http://127.0.0.1:8080/login",
                "--login", "student", "--password", "secret", "--audit", "unused-audit.jsonl",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_browser_interruption_stops_remaining_candidates(self) -> None:
        interrupted = BrowserCheckResult(Outcome(
            OutcomeStatus.SKIPPED, "Interrupted", evidence={"reason": "interrupted"},
        ))
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("authchecker.cli.run_browser_check", return_value=interrupted) as check, redirect_stdout(output):
                code = main([
                    "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "first", "--password", "second",
                    "--audit", str(Path(directory, "audit.jsonl")),
                ])
            self.assertEqual(code, 0)
            check.assert_called_once()
            self.assertEqual(json.loads(output.getvalue())["halt_reason"], "interrupted")

    def test_browser_mode_bypasses_http_discovery_and_sanitizes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory, "audit.jsonl")
            report = Path(directory, "browser.json")
            output = io.StringIO()
            browser_result = BrowserCheckResult(
                outcome=Outcome(OutcomeStatus.SUCCESS, "signed in", evidence={"cookies": "cookie-secret", "html": "token-secret"}),
                attempted_count=1, final_url="http://127.0.0.1:8080/account?csrf=token-secret", fields=("username", "password"),
            )
            with (
                patch("authchecker.cli.run_browser_check", return_value=browser_result) as browser,
                patch("authchecker.cli.discover_login_url", side_effect=AssertionError("no HTTP discovery")),
                redirect_stdout(output),
            ):
                code = main([
                    "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login?csrf=token-secret",
                    "--login", "student", "--password", "sensitive-password",
                    "--audit", str(audit), "--save-report", str(report),
                ])
            self.assertEqual(code, 0)
            browser.assert_called_once()
            self.assertFalse(browser.call_args.kwargs["config"].headless)
            self.assertEqual(browser.call_args.kwargs["config"].timeout_seconds, 60)
            data = json.loads(output.getvalue())
            self.assertEqual(data["successes"][0]["password"], "sensitive-password")
            self.assertEqual(data["final_url"], "http://127.0.0.1:8080/account?csrf=token-secret")
            self.assertEqual(data["checked_count"], 1)
            self.assertEqual(data["attempted_count"], 1)
            self.assertEqual(data["outcomes"], {"success": 1})
            self.assertEqual(len(data["results"]), 1)
            events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([event["event"] for event in events], ["browser_started", "attempt", "browser_finished"])
            serialized = audit.read_text(encoding="utf-8") + report.read_text(encoding="utf-8")
            for secret in ("sensitive-password", "cookie-secret"):
                self.assertNotIn(secret, serialized)
            self.assertIn("token-secret", serialized)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["schema"], "browser-check/1")

    def _browser_cli(self, directory, credentials, *, extra=(), result=None):
        output = io.StringIO()
        audit = Path(directory, "audit.jsonl")
        report = Path(directory, "browser.json")
        if result is None:
            result = BrowserCheckResult(
                Outcome(OutcomeStatus.FAILURE, "Invalid credentials"),
                attempted_count=1,
                final_url="http://127.0.0.1:8080/login",
                fields=("username", "password"),
            )
        mock_options = {"side_effect": result} if callable(result) else {"return_value": result}
        with (
            patch("authchecker.cli.run_browser_check", **mock_options) as browser,
            patch("authchecker.cli.discover_login_url", side_effect=AssertionError("no HTTP discovery")),
            redirect_stdout(output),
        ):
            code = main([
                "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login",
                "--audit", str(audit), "--save-report", str(report), "--rate", "10",
                *credentials, *extra,
            ])
        self.assertEqual(code, 0)
        events = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        return json.loads(output.getvalue()), browser, events, report

    def test_browser_accepts_inline_and_file_credential_streams(self) -> None:
        for source in ("inline", "files"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                if source == "inline":
                    credentials = [
                        "--login", "alice", "--login", "bob",
                        "--password", "first-secret", "--password", "second-secret",
                    ]
                else:
                    logins = Path(directory, "logins.txt")
                    passwords = Path(directory, "passwords.txt")
                    logins.write_text("alice\nbob\n", encoding="utf-8")
                    passwords.write_text("first-secret\nsecond-secret\n", encoding="utf-8")
                    credentials = ["--logins", str(logins), "--passwords", str(passwords)]
                data, browser, events, report = self._browser_cli(directory, credentials)
                pairs = [
                    (call.args[1].username, call.args[1].password)
                    for call in browser.call_args_list
                ]
                self.assertEqual(pairs, [
                    ("alice", "first-secret"), ("alice", "second-secret"),
                    ("bob", "first-secret"), ("bob", "second-secret"),
                ])
                self.assertEqual(data["checked_count"], 4)
                self.assertEqual(data["attempted_count"], 4)
                self.assertEqual(data["outcomes"], {"failure": 4})
                self.assertEqual(len(data["results"]), 4)
                self.assertEqual(sum(event["event"] == "attempt" for event in events), 4)
                for secret in ("first-secret", "second-secret"):
                    self.assertNotIn(secret, report.read_text(encoding="utf-8"))
                self.assertFalse(data.get("successes"))

    def test_browser_scheduler_honors_total_attempt_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data, browser, events, _ = self._browser_cli(
                directory,
                ["--login", "alice", "--login", "bob", "--password", "first", "--password", "second"],
                extra=["--max-total", "2"],
            )
            self.assertEqual(browser.call_count, 2)
            self.assertEqual(data["attempted_count"], 2)
            self.assertEqual(data["checked_count"], 2)
            self.assertEqual(data["halt_reason"], "max_total_attempts")
            self.assertEqual(sum(event["event"] == "attempt" for event in events), 2)

    def test_browser_scheduler_honors_per_account_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data, browser, _, _ = self._browser_cli(
                directory,
                ["--login", "alice", "--login", "bob", "--password", "first", "--password", "second"],
                extra=["--max-per-account", "1"],
            )
            self.assertEqual(
                [(call.args[1].username, call.args[1].password) for call in browser.call_args_list],
                [("alice", "first"), ("bob", "first")],
            )
            self.assertEqual(data["attempted_count"], 2)
            self.assertEqual(data["checked_count"], 2)

    def test_browser_scheduler_stops_completed_account_after_success_or_mfa(self) -> None:
        for terminal in (OutcomeStatus.SUCCESS, OutcomeStatus.MFA_REQUIRED):
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as directory:
                def check(_url, credential, **_kwargs):
                    status = terminal if credential.password == "correct-secret" else OutcomeStatus.FAILURE
                    return BrowserCheckResult(Outcome(status), attempted_count=1)

                data, browser, events, report = self._browser_cli(
                    directory,
                    ["--login", "alice", "--login", "bob", "--password", "wrong-secret",
                     "--password", "correct-secret", "--password", "never-try-secret"],
                    result=check,
                )
                self.assertEqual(
                    [(call.args[1].username, call.args[1].password) for call in browser.call_args_list],
                    [("alice", "wrong-secret"), ("alice", "correct-secret"),
                     ("bob", "wrong-secret"), ("bob", "correct-secret")],
                )
                self.assertEqual(data["attempted_count"], 4)
                self.assertEqual(data["outcomes"], {"failure": 2, terminal.value: 2})
                self.assertEqual(sum(event["event"] == "attempt" for event in events), 4)
                successes = data.get("successes", [])
                self.assertEqual(len(successes), 2 if terminal is OutcomeStatus.SUCCESS else 0)
                self.assertTrue(all(entry["password"] == "correct-secret" for entry in successes))
                mfa_candidates = data.get("mfa_candidates", [])
                self.assertEqual(len(mfa_candidates), 2 if terminal is OutcomeStatus.MFA_REQUIRED else 0)
                self.assertTrue(all(entry["password"] == "correct-secret" for entry in mfa_candidates))
                self.assertNotIn("correct-secret", report.read_text(encoding="utf-8"))
                self.assertNotIn("correct-secret", Path(directory, "audit.jsonl").read_text(encoding="utf-8"))
                for secret in ("wrong-secret", "correct-secret", "never-try-secret"):
                    self.assertNotIn(secret, report.read_text(encoding="utf-8"))

    def test_browser_compact_output_shows_pair_that_reached_mfa(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            report = Path(directory, "browser.json")
            audit = Path(directory, "audit.jsonl")
            checked = BrowserCheckResult(
                Outcome(OutcomeStatus.MFA_REQUIRED, "Требуется код", evidence={"reason": "otp"}),
                attempted_count=1,
            )
            with patch("authchecker.cli.run_browser_check", return_value=checked), redirect_stdout(output):
                code = main([
                    "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "correct-secret",
                    "--audit", str(audit), "--save-report", str(report), "--compact",
                ])
            self.assertEqual(code, 0)
            line = output.getvalue()
            self.assertIn("[ТРЕБУЕТСЯ MFA]", line)
            self.assertIn("пара вызвала запрос кода: логин: student — пароль: correct-secret", line)
            self.assertIn("вход не завершён", line)
            self.assertNotIn("correct-secret", report.read_text(encoding="utf-8"))
            self.assertNotIn("correct-secret", audit.read_text(encoding="utf-8"))

    def test_browser_scheduler_runs_configured_number_of_workers(self) -> None:
        release = threading.Event()
        both_started = threading.Event()
        lock = threading.Lock()
        started = 0

        def check(_url, _credential, **_kwargs):
            nonlocal started
            with lock:
                started += 1
                if started == 2:
                    both_started.set()
                    release.set()
            if not release.wait(timeout=3):
                raise RuntimeError("second browser worker did not start")
            return BrowserCheckResult(Outcome(OutcomeStatus.FAILURE), attempted_count=1)

        with tempfile.TemporaryDirectory() as directory:
            data, browser, events, _ = self._browser_cli(
                directory,
                ["--login", "alice", "--login", "bob", "--password", "secret"],
                extra=["--threads", "2"], result=check,
            )
            self.assertTrue(both_started.is_set())
            self.assertEqual(browser.call_count, 2)
            self.assertEqual(data["threads"], 2)
            self.assertEqual(data["rate_per_second"], 10)
            self.assertEqual(data["attempted_count"], 2)
            self.assertEqual(sum(event["event"] == "attempt" for event in events), 2)

    def test_browser_mode_zero_submission_is_not_an_attempt_or_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory, "audit.jsonl")
            output = io.StringIO()
            result = BrowserCheckResult(Outcome(OutcomeStatus.UNSUPPORTED, "Protection challenge", evidence={"reason": "challenge"}))
            with patch("authchecker.cli.run_browser_check", return_value=result), redirect_stdout(output):
                code = main([
                    "run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "secret", "--audit", str(audit), "--compact",
                ])
            self.assertEqual(code, 0)
            self.assertIn("ЗАЩИТА ОБНАРУЖЕНА", output.getvalue())
            self.assertIn("protected:captcha", output.getvalue())
            self.assertIn("попыток: 0", output.getvalue())
            self.assertNotIn('"event":"attempt"', audit.read_text(encoding="utf-8"))

    def test_browser_protection_stops_candidate_stream_without_attempt_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = BrowserCheckResult(Outcome(
                OutcomeStatus.UNSUPPORTED, "Protection challenge", evidence={"reason": "challenge"},
            ))
            data, browser, events, _ = self._browser_cli(
                directory,
                ["--login", "alice", "--login", "bob", "--password", "first", "--password", "second"],
                result=result,
            )
            browser.assert_called_once()
            self.assertEqual(data["attempted_count"], 0)
            self.assertEqual(data["checked_count"], 1)
            self.assertEqual(data["outcomes"], {"unsupported": 1})
            self.assertNotIn("attempt", [event["event"] for event in events])

    def test_browser_credentials_and_flags_are_validated_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty_file = Path(directory, "empty.txt")
            empty_file.write_text("", encoding="utf-8")
            nul_file = Path(directory, "nul.txt")
            nul_file.write_text("first\nbad\x00value\n", encoding="utf-8")
            report_file = Path(directory, "report.json")
            report_file.write_text(json.dumps(valid_report()), encoding="utf-8")
            base = ["run", "--live", "--browser", "--url", "http://127.0.0.1:8080/login", "--login", "student", "--password", "secret", "--audit", str(Path(directory, "audit.jsonl"))]
            cases = [
                [*base, "--threads", "0"],
                [*base, "--threads", "11"],
                [*base, "--max-total", "0"],
                [*base, "--max-per-account", "0"],
                [*base, "--rate", "0"],
                [*base, "--auth-type", "password_form"],
                [*base, "--browser-timeout", "0"],
                [*base, "--browser-timeout", "nan"],
                ["run", "--dry-run", *base[2:]],
                ["run", "--live", "--browser", "--report", str(report_file), "--login", "student", "--password", "secret", "--audit", str(Path(directory, "audit.jsonl"))],
                [*base, "--login", "bad\nlogin"],
                [*base, "--password", "bad\x00password"],
            ]
            for flag, value in (("--login", ""), ("--password", "")):
                argv = base.copy()
                argv[argv.index(flag) + 1] = value
                cases.append(argv)
            for flag, path in (("--logins", empty_file), ("--passwords", empty_file), ("--logins", nul_file), ("--passwords", nul_file)):
                argv = base.copy()
                original_flag = "--login" if flag == "--logins" else "--password"
                index = argv.index(original_flag)
                argv[index:index + 2] = [flag, str(path)]
                cases.append(argv)
            for argv in cases:
                with self.subTest(argv=argv), patch("authchecker.cli.run_browser_check") as browser, redirect_stderr(io.StringIO()):
                    code = main(argv)
                    self.assertEqual(code, 2)
                    browser.assert_not_called()
            self.assertFalse(Path(directory, "audit.jsonl").exists())

    def test_browser_options_require_browser_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            with redirect_stderr(io.StringIO()):
                code = main(["run", "--dry-run", "--report", str(report), "--login", "student", "--password", "secret", "--headless"])
            self.assertEqual(code, 2)

    def test_identifier_step_explains_otp_without_sending_credentials(self) -> None:
        finding = valid_finding(
            auth_type="passwordless_form",
            metadata={"form_action": "https://example.test/signups/send_email_otp"},
        )
        report = parse_report(valid_report(findings=[finding]))
        message = _unsupported_page_message(report, "https://example.test/login")
        self.assertIn("email/OTP", message)
        self.assertIn("не выполняла", message)
        self.assertIn("не проверяла пароли", message)

    def test_unsupported_page_explains_captcha_and_http_403(self) -> None:
        challenge_data = valid_report(findings=[])
        challenge_data["issues"] = [{
            "stage": "page_only",
            "target": "https://example.test/login",
            "message": "HTTP 403: получена CAPTCHA/защитная страница (challenge)",
            "fatal": False,
        }]
        forbidden_data = valid_report(findings=[])
        forbidden_data["issues"] = [{
            "stage": "page_only",
            "target": "https://example.test/login",
            "message": "HTTP 403: сервер запретил доступ",
            "fatal": False,
        }]

        challenge = _unsupported_page_message(
            parse_report(challenge_data), "https://example.test/login"
        )
        forbidden = _unsupported_page_message(
            parse_report(forbidden_data), "https://example.test/login"
        )

        self.assertIn("CAPTCHA", challenge)
        self.assertIn("не отправлялись", challenge)
        self.assertIn("HTTP 403", forbidden)
        self.assertIn("не отправлялись", forbidden)

    def test_live_identifier_step_stops_before_audit_or_attempts(self) -> None:
        finding = valid_finding(
            auth_type="passwordless_form",
            endpoint="http://127.0.0.1:8080/login",
            metadata={"form_action": "http://127.0.0.1:8080/send_email_otp"},
        )
        finding.update(host="127.0.0.1", port=8080, protocol="http")
        report = parse_report(valid_report(findings=[finding]))
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory, "audit.jsonl")
            errors = io.StringIO()
            with (
                patch("authchecker.cli.discover_login_url", return_value=report),
                redirect_stderr(errors),
            ):
                code = main([
                    "run", "--live", "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "secret",
                    "--audit", str(audit),
                ])
            self.assertEqual(code, 2)
            self.assertIn("email/OTP", errors.getvalue())
            self.assertFalse(audit.exists())

    def make_job(
        self,
        job_key: str,
        endpoint: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> AuthJob:
        return AuthJob(
            job_key=job_key,
            report_run_id="12345678-1234-5678-9234-567812345678",
            finding_id=f"auth-{job_key[-16:].zfill(16)}",
            kind="web_login_page",
            auth_type="password_form",
            endpoint=endpoint,
            host="127.0.0.1",
            port=8080,
            protocol="http",
            metadata=metadata or {},
        )

    def test_automatic_candidates_follow_each_forms_identifier_kind(self) -> None:
        password_values = ("secret",)
        login_values = ("petr@example.test", "p.ivanov")
        cases = (
            ("email", ["petr@example.test"]),
            ("username", ["p.ivanov"]),
            ("unknown", ["petr@example.test", "p.ivanov"]),
        )

        for kind, expected in cases:
            with self.subTest(kind=kind):
                job = self.make_job(
                    f"job-{kind}",
                    f"https://example.test/{kind}",
                    metadata={"identifier_kind": kind},
                )
                attempts = list(_attempts(
                    [job],
                    logins_path=None,
                    login_values=login_values,
                    passwords_path=None,
                    password_encoding="utf-8",
                    password_values=password_values,
                    filter_login_candidates=True,
                ))
                self.assertEqual(
                    [credential.username for _, credential in attempts],
                    expected,
                )

        manual_job = self.make_job(
            "job-manual",
            "https://example.test/manual",
            metadata={"identifier_kind": "email"},
        )
        manual_attempts = list(_attempts(
            [manual_job],
            logins_path=None,
            login_values=login_values,
            passwords_path=None,
            password_encoding="utf-8",
            password_values=password_values,
        ))
        self.assertEqual(
            [credential.username for _, credential in manual_attempts],
            ["petr@example.test", "p.ivanov"],
        )

    def make_inputs(self, directory: str) -> tuple[Path, Path, Path]:
        report = Path(directory, "report.json")
        logins = Path(directory, "logins.txt")
        passwords = Path(directory, "passwords.txt")
        report.write_text(json.dumps(valid_report()), encoding="utf-8")
        logins.write_text("alice\n", encoding="utf-8")
        passwords.write_text("not-printed\n", encoding="utf-8")
        return report, logins, passwords

    def test_validate_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["validate", str(report)])
            self.assertEqual(result, 0)
            self.assertTrue(json.loads(output.getvalue())["valid"])

    def test_plan_and_run_dry_run_have_no_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, logins, passwords = self.make_inputs(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "run",
                        "--dry-run",
                        "--report",
                        str(report),
                        "--logins",
                        str(logins),
                        "--passwords",
                        str(passwords),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertNotIn("not-printed", output.getvalue())
            self.assertEqual(json.loads(output.getvalue())["job_count"], 1)

    def test_plan_accepts_repeated_inline_logins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, passwords = self.make_inputs(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "plan",
                        "--report",
                        str(report),
                        "--login",
                        "alice",
                        "--login",
                        "bob",
                        "--passwords",
                        str(passwords),
                    ]
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(payload["login_count"], 2)
            self.assertNotIn("alice", output.getvalue())

    def test_plan_accepts_repeated_inline_passwords_without_printing_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "plan",
                        "--report",
                        str(report),
                        "--login",
                        "student",
                        "--password",
                        "wrong-password",
                        "--password",
                        "password123",
                    ]
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(payload["password_count"], 2)
            self.assertNotIn("wrong-password", output.getvalue())
            self.assertNotIn("password123", output.getvalue())

    def test_password_file_and_inline_password_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, passwords = self.make_inputs(directory)
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "plan",
                        "--report",
                        str(report),
                        "--login",
                        "student",
                        "--passwords",
                        str(passwords),
                        "--password",
                        "password123",
                    ]
                )
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("not allowed with argument", error.getvalue())

    def test_live_run_accepts_exact_url_instead_of_report(self) -> None:
        args = build_parser().parse_args(
            [
                "run",
                "--live",
                "--url",
                "http://127.0.0.1:8080/login",
                "--login",
                "student",
                "--password",
                "password123",
                "--proxy",
                "http://127.0.0.1:9090",
                "--audit",
                "audit.jsonl",
            ]
        )
        self.assertIsNone(args.report)
        self.assertEqual(args.url, "http://127.0.0.1:8080/login")

    def test_compact_live_output_has_one_summary_per_endpoint(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        admin_job = self.make_job("job-admin", "http://127.0.0.1:8080/admin")
        attempts = (
            ScheduledAttempt(
                login_job,
                Credential("student", "wrong"),
                Outcome(OutcomeStatus.FAILURE),
            ),
            ScheduledAttempt(
                login_job,
                Credential("student", "password123"),
                Outcome(OutcomeStatus.SUCCESS),
            ),
            ScheduledAttempt(
                admin_job,
                Credential("admin", "wrong"),
                Outcome(OutcomeStatus.FAILURE),
            ),
        )

        lines = _compact_live_lines(
            [login_job, admin_job],
            ScheduleResult(attempts, attempted_count=3, halt_reason=None),
        )

        self.assertEqual(
            lines,
            (
                "[УСПЕШНО] http://127.0.0.1:8080/login — "
                "логин: student — пароль: password123",
                "[НЕУСПЕШНО] http://127.0.0.1:8080/admin — попыток: 1",
            ),
        )

        summary_only = _compact_live_lines(
            [login_job, admin_job],
            ScheduleResult(attempts, attempted_count=3, halt_reason=None),
            show_success_credentials=False,
        )
        self.assertEqual(
            summary_only[0],
            "[УСПЕШНО] http://127.0.0.1:8080/login — попыток: 2; найдено пар: 1",
        )
        self.assertNotIn("password123", summary_only[0])

    def test_compact_output_escapes_terminal_control_characters(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempt = ScheduledAttempt(
            login_job,
            Credential("student", "safe\x1b[31m-looking"),
            Outcome(OutcomeStatus.SUCCESS),
        )

        lines = _compact_live_lines(
            [login_job],
            ScheduleResult((attempt,), attempted_count=1, halt_reason=None),
        )

        self.assertNotIn("\x1b", lines[0])
        self.assertIn(r"safe\u001b[31m-looking", lines[0])

    def test_compact_live_output_names_captcha_and_http_403(self) -> None:
        challenge_job = self.make_job("job-challenge", "http://127.0.0.1/challenge")
        forbidden_job = self.make_job("job-forbidden", "http://127.0.0.1/forbidden")
        attempts = (
            ScheduledAttempt(
                challenge_job,
                Credential("student", "secret"),
                Outcome(
                    OutcomeStatus.UNSUPPORTED,
                    "HTTP 403: получена CAPTCHA/защитная страница",
                    evidence={"reason": "challenge", "http_status": 403},
                ),
            ),
            ScheduledAttempt(
                forbidden_job,
                Credential("student", "secret"),
                Outcome(
                    OutcomeStatus.FAILURE,
                    "HTTP 403: доступ запрещён",
                    evidence={"reason": "http_403", "http_status": 403},
                ),
            ),
        )

        lines = _compact_live_lines(
            [challenge_job, forbidden_job],
            ScheduleResult(attempts, attempted_count=2, halt_reason=None),
        )

        self.assertIn("[ЗАЩИТА ОБНАРУЖЕНА]", lines[0])
        self.assertIn("CAPTCHA", lines[0])
        self.assertIn("[HTTP 403]", lines[1])
        self.assertIn("доступ запрещён", lines[1])

    def test_compact_unsupported_preflight_is_not_an_attempt(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempt = ScheduledAttempt(
            login_job,
            Credential("student", "secret"),
            Outcome(
                OutcomeStatus.UNSUPPORTED,
                "форма требует session/CSRF",
                evidence={"attempted": False},
            ),
        )

        lines = _compact_live_lines(
            [login_job],
            ScheduleResult((attempt,), attempted_count=0, halt_reason=None),
        )

        self.assertEqual(
            lines,
            (
                "[НЕ ПРОВЕРЕНО] http://127.0.0.1:8080/login — "
                "попыток: 0; проверок: 1; форма требует session/CSRF",
            ),
        )

    def test_compact_live_output_does_not_report_uncertainty_as_bad_credentials(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        cases = (
            ((OutcomeStatus.AMBIGUOUS,), "РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН"),
            ((OutcomeStatus.FAILURE, OutcomeStatus.AMBIGUOUS), "РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН"),
            ((OutcomeStatus.NETWORK_ERROR,), "ОШИБКА СЕТИ"),
            ((OutcomeStatus.FAILURE, OutcomeStatus.NETWORK_ERROR), "ОШИБКА СЕТИ"),
            ((OutcomeStatus.UNSUPPORTED,), "НЕ ПРОВЕРЕНО"),
            ((OutcomeStatus.SKIPPED,), "НЕ ПРОВЕРЕНО"),
            ((OutcomeStatus.UNSUPPORTED, OutcomeStatus.SKIPPED), "НЕ ПРОВЕРЕНО"),
            ((OutcomeStatus.FAILURE, OutcomeStatus.UNSUPPORTED), "ПРОВЕРЕНО ЧАСТИЧНО"),
            ((OutcomeStatus.FAILURE, OutcomeStatus.SKIPPED), "ПРОВЕРЕНО ЧАСТИЧНО"),
        )
        for statuses, label in cases:
            with self.subTest(statuses=statuses):
                attempts = tuple(
                    ScheduledAttempt(
                        login_job,
                        Credential("student", "secret"),
                        Outcome(status, "причина: " + status.value),
                    )
                    for status in statuses
                )
                line, = _compact_live_lines(
                    [login_job], ScheduleResult(attempts, attempted_count=1, halt_reason=None),
                )

                self.assertTrue(line.startswith(f"[{label}] "), line)
                self.assertNotIn("[НЕУСПЕШНО]", line)
                self.assertIn("причина: ", line)

    def test_compact_live_output_keeps_confirmed_failures_distinct(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempts = tuple(
            ScheduledAttempt(
                login_job, Credential("student", password), Outcome(OutcomeStatus.FAILURE),
            )
            for password in ("first-secret", "second-secret")
        )

        self.assertEqual(
            _compact_live_lines(
                [login_job], ScheduleResult(attempts, attempted_count=2, halt_reason=None),
            ),
            ("[НЕУСПЕШНО] http://127.0.0.1:8080/login — попыток: 2",),
        )

    def test_compact_output_reports_response_different_from_declared_failure(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempt = ScheduledAttempt(
            login_job, Credential("student", "private-secret"),
            Outcome(
                OutcomeStatus.AMBIGUOUS,
                "Ответ отличается от отказа из шаблона: POST 302, итоговый HTTP 200; "
                "для отказа ожидались POST 200 и заданный текст. Успешный вход не подтверждён",
                evidence={"reason": "template_response_differs", "post_status": 302, "http_status": 200},
            ),
        )
        line, = _compact_live_lines(
            [login_job], ScheduleResult((attempt,), attempted_count=1, halt_reason=None),
        )
        self.assertIn("[РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН]", line)
        self.assertIn("POST 302", line)
        self.assertIn("отличается от отказа", line)
        self.assertNotIn("private-secret", line)

    def test_compact_diagnostics_escape_controls_and_hide_failed_passwords(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempts = (
            ScheduledAttempt(
                login_job, Credential("student", "first-secret"), Outcome(OutcomeStatus.FAILURE),
            ),
            ScheduledAttempt(
                login_job,
                Credential("student", "second-secret"),
                Outcome(
                    OutcomeStatus.NETWORK_ERROR,
                    "таймаут: first-secret, second-secret\n\x1b[31m",
                ),
            ),
        )

        line, = _compact_live_lines(
            [login_job], ScheduleResult(attempts, attempted_count=2, halt_reason=None),
        )

        self.assertIn("[ОШИБКА СЕТИ]", line)
        self.assertIn("таймаут: <redacted>, <redacted>", line)
        self.assertIn(r"\n\u001b[31m", line)
        for secret in ("first-secret", "second-secret", "\n", "\x1b"):
            self.assertNotIn(secret, line)

    def test_compact_live_output_retains_success_and_protection_priorities(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        outcomes = (
            Outcome(OutcomeStatus.SUCCESS),
            Outcome(OutcomeStatus.UNSUPPORTED, "CAPTCHA", evidence={"reason": "challenge"}),
            Outcome(OutcomeStatus.FAILURE, "доступ запрещён", evidence={"reason": "http_403"}),
            Outcome(OutcomeStatus.RATE_LIMITED),
            Outcome(OutcomeStatus.LOCKED_OUT),
            Outcome(OutcomeStatus.MFA_REQUIRED),
            Outcome(OutcomeStatus.ERROR, "ошибка адаптера"),
            Outcome(OutcomeStatus.NETWORK_ERROR, "таймаут"),
            Outcome(OutcomeStatus.AMBIGUOUS, "недостаточно признаков"),
        )
        labels = (
            "УСПЕШНО", "ЗАЩИТА ОБНАРУЖЕНА", "HTTP 403", "ЛИМИТ ЗАПРОСОВ",
            "АККАУНТ ЗАБЛОКИРОВАН", "ТРЕБУЕТСЯ MFA", "ОШИБКА", "ОШИБКА СЕТИ",
            "РЕЗУЛЬТАТ НЕ ОПРЕДЕЛЁН",
        )
        for index, label in enumerate(labels):
            with self.subTest(label=label):
                attempts = tuple(
                    ScheduledAttempt(login_job, Credential("student", "secret"), outcome)
                    for outcome in outcomes[index:]
                )
                line, = _compact_live_lines(
                    [login_job], ScheduleResult(attempts, attempted_count=1, halt_reason=None),
                )

                self.assertTrue(line.startswith(f"[{label}] "), line)

    def test_compact_live_output_shows_pair_that_reached_mfa(self) -> None:
        login_job = self.make_job("job-login", "http://127.0.0.1:8080/login")
        attempt = ScheduledAttempt(
            login_job, Credential("student", "correct-secret"),
            Outcome(OutcomeStatus.MFA_REQUIRED, evidence={"reason": "otp", "attempted": True}),
        )
        line, = _compact_live_lines(
            [login_job], ScheduleResult((attempt,), attempted_count=1, halt_reason=None),
        )
        self.assertIn("[ТРЕБУЕТСЯ MFA]", line)
        self.assertIn("пара вызвала запрос кода: логин: student — пароль: correct-secret", line)
        self.assertIn("вход не завершён", line)

    def test_auto_browser_uses_plain_http_when_form_is_supported(self) -> None:
        report = parse_report(valid_report())
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_live", return_value=0) as run_live,
            patch("authchecker.cli._run_browser") as run_browser,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "http://127.0.0.1:8080/login",
                "--login", "student", "--password", "secret",
                "--audit", str(Path(directory, "audit.jsonl")),
            ])

        self.assertEqual(code, 0)
        run_browser.assert_not_called()
        self.assertIs(run_live.call_args.kwargs["report_override"], report)

    def test_auto_browser_uses_explicit_result_selectors_for_supported_form(self) -> None:
        report = parse_report(valid_report())
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_live") as run_live,
            patch("authchecker.cli._run_browser", return_value=0) as run_browser,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "http://127.0.0.1:8080/login",
                "--login", "student", "--password", "secret",
                "--success-selector", ".account-menu",
                "--audit", str(Path(directory, "audit.jsonl")),
            ])

        self.assertEqual(code, 0)
        run_live.assert_not_called()
        self.assertEqual(run_browser.call_args.args[0].success_selector, ".account-menu")

    def test_auto_browser_falls_back_for_get_password_form(self) -> None:
        finding = valid_finding(metadata={
            "page_url": "https://example.test/login",
            "form_action": "https://example.test/login",
            "form_method": "GET",
            "fields": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"},
            ],
        })
        report = parse_report(valid_report(findings=[finding]))
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_browser", return_value=0) as run_browser,
            patch("authchecker.cli._run_live") as run_live,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "https://example.test/login",
                "--scope-domain", "example.test",
                "--login", "student", "--password", "secret",
                "--audit", str(Path(directory, "audit.jsonl")),
            ])

        self.assertEqual(code, 0)
        run_live.assert_not_called()
        self.assertTrue(run_browser.call_args.args[0].browser_http)

    def test_auto_browser_falls_back_once_for_http_403(self) -> None:
        data = valid_report(findings=[])
        data["issues"] = [{
            "stage": "page_only", "target": "http://127.0.0.1:8080/login",
            "message": "HTTP 403: сервер запретил доступ", "fatal": False,
        }]
        report = parse_report(data)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_browser", return_value=0) as run_browser,
            patch("authchecker.cli._run_live") as run_live,
            redirect_stderr(io.StringIO()) as errors,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "http://127.0.0.1:8080/login",
                "--login", "student", "--password", "secret",
                "--audit", str(Path(directory, "audit.jsonl")), "--threads", "5",
            ])

        self.assertEqual(code, 0)
        run_live.assert_not_called()
        fallback_args = run_browser.call_args.args[0]
        self.assertTrue(fallback_args.browser_http)
        self.assertTrue(fallback_args._auto_browser_active)
        self.assertEqual(fallback_args.threads, 1)
        self.assertIn("один browser fallback", errors.getvalue())

    def test_auto_browser_falls_back_for_hidden_csrf_fields(self) -> None:
        finding = valid_finding(metadata={
            "page_url": "https://example.test/login",
            "form_action": "https://example.test/session",
            "form_method": "POST",
            "auth_fingerprint": "form-hidden-csrf",
            "fields": [
                {"name": "authenticity_token", "type": "hidden"},
                {"name": "login", "type": "text", "autocomplete": "username"},
                {"name": "password", "type": "password", "autocomplete": "current-password"},
            ],
        })
        report = parse_report(valid_report(findings=[finding]))
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_browser", return_value=0) as run_browser,
            patch("authchecker.cli._run_live") as run_live,
            redirect_stderr(io.StringIO()) as errors,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "https://example.test/login",
                "--scope-domain", "example.test",
                "--login", "student", "--password", "secret",
                "--audit", str(Path(directory, "audit.jsonl")),
            ])

        self.assertEqual(code, 0)
        run_live.assert_not_called()
        fallback_args = run_browser.call_args.args[0]
        self.assertTrue(fallback_args.browser_http)
        self.assertTrue(fallback_args._auto_browser_active)
        self.assertIn("session/CSRF", errors.getvalue())

    def test_auto_browser_falls_back_once_after_http_timeout(self) -> None:
        data = valid_report(findings=[])
        data["issues"] = [{
            "stage": "standard_paths",
            "target": "http://127.0.0.1:8080/login",
            "message": "The read operation timed out",
            "fatal": False,
        }]
        report = parse_report(data)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("authchecker.cli.discover_login_url", return_value=report),
            patch("authchecker.cli._run_browser", return_value=0) as run_browser,
            patch("authchecker.cli._run_live") as run_live,
            redirect_stderr(io.StringIO()) as errors,
        ):
            code = main([
                "run", "--live", "--auto-browser",
                "--url", "http://127.0.0.1:8080/login",
                "--login", "student", "--password", "secret",
                "--audit", str(Path(directory, "audit.jsonl")),
            ])

        self.assertEqual(code, 0)
        run_live.assert_not_called()
        fallback_args = run_browser.call_args.args[0]
        self.assertTrue(fallback_args.browser_http)
        self.assertTrue(fallback_args._auto_browser_active)
        self.assertIn("таймаут", errors.getvalue())

    def test_auto_browser_reports_captcha_as_protection_without_browser_or_password(self) -> None:
        data = valid_report(findings=[])
        data["issues"] = [{
            "stage": "page_only", "target": "http://127.0.0.1:8080/login",
            "message": "HTTP 403: получена CAPTCHA/защитная страница (challenge)",
            "fatal": False,
        }]
        report = parse_report(data)
        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory, "audit.jsonl")
            saved = Path(directory, "result.json")
            output = io.StringIO()
            with (
                patch("authchecker.cli.discover_login_url", return_value=report),
                patch("authchecker.cli._run_browser") as run_browser,
                patch("authchecker.cli._run_live") as run_live,
                redirect_stdout(output),
            ):
                code = main([
                    "run", "--live", "--auto-browser",
                    "--url", "http://127.0.0.1:8080/login",
                    "--login", "student", "--password", "private-secret",
                    "--audit", str(audit), "--save-report", str(saved), "--compact",
                ])

            self.assertEqual(code, 0)
            run_browser.assert_not_called()
            run_live.assert_not_called()
            self.assertIn("[ЗАЩИТА ОБНАРУЖЕНА]", output.getvalue())
            result = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(result["outcome"], "protected")
            self.assertEqual(result["halt_reason"], "protected:captcha")
            self.assertEqual(result["attempted_count"], 0)
            serialized = saved.read_text(encoding="utf-8") + audit.read_text(encoding="utf-8")
            self.assertNotIn("private-secret", serialized)

    def test_url_is_rejected_in_dry_run_because_discovery_needs_network(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            result = main(
                [
                    "run",
                    "--dry-run",
                    "--url",
                    "http://127.0.0.1:8080/login",
                    "--login",
                    "student",
                    "--password",
                    "password123",
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("--url requires --live", error.getvalue())

    def test_live_rejects_thread_count_above_hard_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(
                    [
                        "run",
                        "--live",
                        "--report",
                        str(report),
                        "--login",
                        "student",
                        "--password",
                        "password123",
                        "--proxy",
                        "http://127.0.0.1:9090",
                        "--audit",
                        str(Path(directory, "audit.jsonl")),
                        "--threads",
                        "11",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("--threads must be between 1 and 10", error.getvalue())

    def test_live_requires_audit_but_not_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, passwords = self.make_inputs(directory)
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(
                    [
                        "run",
                        "--live",
                        "--report",
                        str(report),
                        "--login",
                        "alice",
                        "--passwords",
                        str(passwords),
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("--audit is required", error.getvalue())

    def test_allow_subdomains_requires_explicit_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(
                    [
                        "run",
                        "--live",
                        "--report",
                        str(report),
                        "--login",
                        "student",
                        "--password",
                        "password123",
                        "--proxy",
                        "http://127.0.0.1:9090",
                        "--audit",
                        str(Path(directory, "audit.jsonl")),
                        "--allow-subdomains",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("--allow-subdomains requires --scope-domain", error.getvalue())

    def test_invalid_report_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory, "report.json")
            report.write_text("{}", encoding="utf-8")
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(["validate", str(report)])
            self.assertEqual(result, 2)
            self.assertIn("missing required", error.getvalue())

    def test_missing_input_file_is_rejected_during_argument_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_report = Path(directory, "missing-report.json")
            passwords = Path(directory, "passwords.txt")
            passwords.write_text("not-printed\n", encoding="utf-8")
            error = io.StringIO()

            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "plan",
                        "--report",
                        str(missing_report),
                        "--login",
                        "alice",
                        "--passwords",
                        str(passwords),
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("файл не найден", error.getvalue())
            self.assertIn(str(missing_report), error.getvalue())

    def test_directory_cannot_be_used_as_an_input_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            error = io.StringIO()

            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "plan",
                        "--report",
                        str(report),
                        "--login",
                        "alice",
                        "--passwords",
                        directory,
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("ожидался файл", error.getvalue())

    def test_omitted_required_file_option_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report, _, _ = self.make_inputs(directory)
            error = io.StringIO()

            with redirect_stderr(error), self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "plan",
                        "--report",
                        str(report),
                        "--login",
                        "alice",
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("--passwords", error.getvalue())


if __name__ == "__main__":
    unittest.main()
