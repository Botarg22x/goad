"""A list of exact login URLs delegates separate, bounded module-4 runs."""

from __future__ import annotations

import _support  # noqa: F401

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from urllib.parse import urlsplit, urlunsplit

from goad.direct_run import direct_run_main, is_direct_run


_URLS = (
    "https://auth.example.com/session/new",
    "https://portal.example.net:8443/login?next=%2Faccount#form",
)
_PASSWORD = "inline-private-password"


def _value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _safe_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


class TargetFileRunTests(TestCase):
    def targets(self, directory: str, content: str | None = None) -> Path:
        path = Path(directory, "targets.txt")
        path.write_text(content if content is not None else "\n".join(_URLS) + "\n", encoding="utf-8")
        return path

    def runner(self, calls, *, codes=(), sensitive_stdout=False, interrupted_at=None):
        def run(argv: list[str]) -> int:
            index = len(calls)
            calls.append(argv.copy())
            code = codes[index] if index < len(codes) else 0
            if isinstance(code, BaseException):
                raise code
            endpoint = _safe_url(_value(argv, "--url"))
            success = sensitive_stdout and code == 0
            payload = {
                "schema": "browser-check/1", "mode": "browser-http",
                "endpoint": endpoint, "final_url": endpoint,
                "outcome": "success" if success else "failure",
                "attempted_count": 1, "checked_count": 1,
                "outcomes": {"success" if success else "failure": 1},
                "fields": ["username", "password"],
            }
            if index == interrupted_at:
                payload.update(outcome="skipped", reason="interrupted", attempted_count=0, outcomes={"skipped": 1})
            report = Path(_value(argv, "--save-report"))
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(payload), encoding="utf-8")
            audit = Path(_value(argv, "--audit"))
            audit.parent.mkdir(parents=True, exist_ok=True)
            with audit.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"event": "attempt", "endpoint": endpoint}) + "\n")
            if "--compact" in argv:
                print(f"[НЕУСПЕШНО] {endpoint} — попыток: 1")
            else:
                if sensitive_stdout:
                    payload["successes"] = [{"endpoint": endpoint, "username": "student", "password": _PASSWORD}]
                    payload["cookies"] = {"session": "private-cookie-value"}
                    payload["body"] = "private-request-body"
                print(json.dumps(payload))
            return code
        return run

    def invoke(self, directory, argv, runner, *, credentials=None, sleeper=None):
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = direct_run_main(
                [*(credentials if credentials is not None else ["--login", "student", "--password", _PASSWORD]),
                 "--artifacts", str(Path(directory, "artifacts")), *argv],
                runner=runner,
                discover_runner=lambda _argv: self.fail("exact target files must bypass discovery"),
                login_runner=lambda _argv: self.fail("exact target files must bypass login search"),
                run_id="fixed-target-run", stdout=output, stderr=errors,
                **({"sleeper": sleeper} if sleeper is not None else {}),
            )
        return code, output.getvalue(), errors.getvalue()

    def test_targets_file_aliases_select_direct_mode(self) -> None:
        for flag in ("--targets-file", "--urls-file"):
            self.assertTrue(is_direct_run([flag, "targets.txt"]))
            self.assertTrue(is_direct_run([flag + "=targets.txt"]))
            with self.subTest(flag=flag), TemporaryDirectory() as directory:
                calls = []
                code, _, _ = self.invoke(directory, [flag, str(self.targets(directory))], self.runner(calls))
                self.assertEqual(code, 0)
                self.assertEqual(len(calls), 2)

    def test_slow_spaces_targets_and_caps_every_module_four_run(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            delays: list[float] = []
            code, _, errors = self.invoke(
                directory,
                [
                    "--targets-file", str(self.targets(directory)),
                    "--slow", "--rate", "9", "--threads", "6",
                ],
                self.runner(calls),
                sleeper=delays.append,
            )

            self.assertEqual(code, 0)
            self.assertEqual(delays, [15.0])
            self.assertIn("[SLOW] Пауза 15 с", errors)
            for delegated in calls:
                self.assertIn("--slow", delegated)
                self.assertEqual(float(_value(delegated, "--rate")), 1.0 / 15.0)
                self.assertEqual(_value(delegated, "--threads"), "1")

    def test_each_transport_gets_exact_urls_own_scope_limits_and_artifact_paths(self) -> None:
        for mode in (None, "--browser", "--browser-http", "--auto-browser"):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                calls = []
                argv = [
                    "--targets-file", str(self.targets(directory)),
                    "--rate", "2.5", "--threads", "3", "--max-total", "7", "--max-per-account", "2",
                    "--proxy", "http://127.0.0.1:9090", "--user-agent", "Target list integration test",
                ]
                if mode:
                    argv.extend((mode, "--headless", "--browser-timeout", "90"))
                code, _, _ = self.invoke(directory, argv, self.runner(calls))
                self.assertEqual(code, 0)
                self.assertEqual(len(calls), 2)
                root = Path(directory, "artifacts", "fixed-target-run").resolve()
                for index, (url, delegated) in enumerate(zip(_URLS, calls, strict=True), 1):
                    self.assertEqual(delegated[:4], ["run", "--live", "--url", url])
                    self.assertNotIn("--report", delegated)
                    self.assertEqual(_value(delegated, "--scope-domain"), urlsplit(url).hostname)
                    self.assertEqual(_value(delegated, "--audit"), str(root / f"{index:03d}" / "audit.jsonl"))
                    self.assertEqual(_value(delegated, "--save-report"), str(root / f"{index:03d}" / "report.json"))
                    for flag, value in (("--rate", "2.5"), ("--threads", "3"), ("--max-total", "7"), ("--max-per-account", "2"), ("--proxy", "http://127.0.0.1:9090"), ("--user-agent", "Target list integration test")):
                        self.assertEqual(_value(delegated, flag), value)
                    self.assertEqual("--browser" in delegated, mode == "--browser")
                    self.assertEqual("--browser-http" in delegated, mode == "--browser-http")
                    self.assertEqual("--auto-browser" in delegated, mode in (None, "--auto-browser"))
                    if mode in (None, "--auto-browser", "--browser", "--browser-http"):
                        self.assertIn("--headless", delegated)
                    if mode:
                        self.assertEqual(_value(delegated, "--browser-timeout"), "90.0")
                aggregate = json.loads((root / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(aggregate["schema"], "targets-run/1")
                self.assertEqual(len(aggregate["results"]), 2)

    def test_compact_mode_prints_child_status_lines_without_json_documents(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            code, output, _ = self.invoke(directory, ["--targets-file", str(self.targets(directory))], self.runner(calls))
            self.assertEqual(code, 0)
            self.assertTrue(all("--compact" in argv for argv in calls))
            self.assertEqual(output.splitlines(), [f"[НЕУСПЕШНО] {_safe_url(url)} — попыток: 1" for url in _URLS])

    def test_auto_browser_stops_later_urls_on_the_same_captcha_host(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            targets = self.targets(
                directory,
                "https://protected.example/login\n"
                "https://protected.example/admin/login\n"
                "https://other.example/login\n",
            )

            def protected_runner(argv: list[str]) -> int:
                calls.append(argv.copy())
                endpoint = _safe_url(_value(argv, "--url"))
                protected = urlsplit(endpoint).hostname == "protected.example"
                payload = {
                    "schema": "adaptive-check/1",
                    "mode": "auto_browser",
                    "endpoint": endpoint,
                    "outcome": "protected" if protected else "failure",
                    "reason": "challenge" if protected else None,
                    "protection_detected": protected,
                    "protection": "captcha" if protected else None,
                    "attempted_count": 0 if protected else 1,
                    "checked_count": 1,
                    "halt_reason": "protected:captcha" if protected else None,
                    "outcomes": {"protected" if protected else "failure": 1},
                }
                report = Path(_value(argv, "--save-report"))
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps(payload), encoding="utf-8")
                audit = Path(_value(argv, "--audit"))
                audit.parent.mkdir(parents=True, exist_ok=True)
                with audit.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"event": "finished", **payload}) + "\n")
                print(
                    f"[{'ЗАЩИТА ОБНАРУЖЕНА' if protected else 'НЕУСПЕШНО'}] "
                    f"{endpoint} — тест"
                )
                return 0

            code, output, _ = self.invoke(
                directory,
                ["--auto-browser", "--targets-file", str(targets)],
                protected_runner,
            )

            self.assertEqual(code, 0)
            self.assertEqual(
                [_value(argv, "--url") for argv in calls],
                ["https://protected.example/login", "https://other.example/login"],
            )
            self.assertIn(
                "[ЗАЩИТА ОБНАРУЖЕНА] https://protected.example/admin/login — "
                "хост protected.example уже остановлен после CAPTCHA; запросы не выполнялись",
                output,
            )
            root = Path(directory, "artifacts", "fixed-target-run").resolve()
            skipped = json.loads((root / "002" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(skipped["outcome"], "protected")
            self.assertEqual(skipped["attempted_count"], 0)
            self.assertEqual(skipped["halt_reason"], "protected:captcha")
            aggregate = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(aggregate["results"]), 3)
            self.assertTrue(aggregate["results"][1]["result"]["protection_detected"])

    def test_json_mode_keeps_url_query_and_redacts_password_fields(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            aggregate_file = Path(directory, "results", "combined.json")
            code, output, _ = self.invoke(
                directory,
                ["--targets-file", str(self.targets(directory)), "--browser-http", "--json", "--save-report", str(aggregate_file)],
                self.runner(calls, sensitive_stdout=True),
            )
            self.assertEqual(code, 0)
            self.assertTrue(all("--compact" not in argv for argv in calls))
            aggregate = json.loads(output)
            self.assertEqual(aggregate["schema"], "targets-run/1")
            self.assertEqual(aggregate["targets_count"], 2)
            self.assertEqual(aggregate["processed_count"], 2)
            self.assertEqual(aggregate["completed_count"], 2)
            self.assertEqual(aggregate["failed_count"], 0)
            self.assertEqual(aggregate["return_code"], 0)
            self.assertEqual([entry["target"] for entry in aggregate["results"]], [_safe_url(url) for url in _URLS])
            self.assertEqual(aggregate["results"][0]["result"]["successes"][0]["password"], _PASSWORD)
            artifact = aggregate_file.read_text(encoding="utf-8")
            for secret in (_PASSWORD, "private-cookie-value", "private-request-body", "#form"):
                self.assertNotIn(secret, artifact)
            self.assertIn("next=%2Faccount", artifact)
            self.assertEqual(json.loads(artifact)["schema"], "targets-run/1")

    def test_custom_audit_is_shared_but_each_target_keeps_its_own_report(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            audit = Path(directory, "custom", "shared-audit.jsonl")
            aggregate = Path(directory, "custom", "aggregate.json")
            code, _, _ = self.invoke(
                directory,
                ["--targets-file", str(self.targets(directory)), "--audit", str(audit), "--save-report", str(aggregate)],
                self.runner(calls),
            )
            self.assertEqual(code, 0)
            self.assertEqual([_value(argv, "--audit") for argv in calls], [str(audit.resolve())] * 2)
            child_reports = [_value(argv, "--save-report") for argv in calls]
            self.assertEqual(len(set(child_reports)), 2)
            self.assertNotIn(str(aggregate.resolve()), child_reports)
            self.assertTrue(all(Path(path).is_file() for path in child_reports))
            self.assertEqual(len(audit.read_text(encoding="utf-8").splitlines()), 2)
            self.assertEqual(len(json.loads(aggregate.read_text(encoding="utf-8"))["results"]), 2)

    def test_repeated_inline_credentials_are_forwarded_to_every_target(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            code, _, _ = self.invoke(
                directory,
                ["--targets-file", str(self.targets(directory)), "--login", "admin", "--password", "another-private-password"],
                self.runner(calls),
            )
            self.assertEqual(code, 0)
            for argv in calls:
                self.assertEqual([argv[i + 1] for i, value in enumerate(argv) if value == "--login"], ["student", "admin"])
                self.assertEqual([argv[i + 1] for i, value in enumerate(argv) if value == "--password"], [_PASSWORD, "another-private-password"])

    def test_credential_files_are_forwarded_to_every_target(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            logins = Path(directory, "users.txt")
            passwords = Path(directory, "passwords.txt")
            logins.write_text("student\nadmin\n", encoding="utf-8")
            passwords.write_text("one\ntwo\n", encoding="utf-8")
            code, _, _ = self.invoke(
                directory,
                ["--targets-file", str(self.targets(directory)), "--browser-http"],
                self.runner(calls),
                credentials=["--logins", str(logins), "--passwords", str(passwords)],
            )
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 2)
            for argv in calls:
                self.assertEqual(_value(argv, "--logins"), str(logins))
                self.assertEqual(_value(argv, "--passwords"), str(passwords))
                self.assertNotIn("--login", argv)
                self.assertNotIn("--password", argv)

    def test_invalid_target_files_are_rejected_before_any_delegate(self) -> None:
        invalid_contents = ("", "\n \n", "not a URL\n", "ftp://example.com/login\n", "https://\n", _URLS[0] + "\nnot a URL\n")
        for content in invalid_contents:
            with self.subTest(content=content), TemporaryDirectory() as directory:
                calls = []
                try:
                    code, _, _ = self.invoke(directory, ["--targets-file", str(self.targets(directory, content))], self.runner(calls))
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                self.assertEqual(calls, [])
        for kind in ("missing", "directory"):
            with self.subTest(kind=kind), TemporaryDirectory() as directory:
                path = Path(directory, "missing.txt") if kind == "missing" else Path(directory)
                calls = []
                try:
                    code, _, _ = self.invoke(directory, ["--targets-file", str(path)], self.runner(calls))
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                self.assertEqual(calls, [])

    def test_target_file_rejects_discovery_and_other_target_sources(self) -> None:
        for extra in (["-u", _URLS[0]], ["--target", _URLS[0]], ["-q"], ["--discover-only"], ["--find-logins"], ["--search-engine", "google"]):
            with self.subTest(extra=extra), TemporaryDirectory() as directory:
                calls = []
                try:
                    code, _, _ = self.invoke(directory, ["--targets-file", str(self.targets(directory)), *extra], self.runner(calls))
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                self.assertEqual(calls, [])

    def test_report_and_audit_cannot_overwrite_inputs_or_each_other(self) -> None:
        for collision in ("audit-targets", "report-targets", "audit-logins", "report-passwords", "same-outputs", "generated-child-report"):
            with self.subTest(collision=collision), TemporaryDirectory() as directory:
                targets = self.targets(directory)
                logins = Path(directory, "logins.txt")
                passwords = Path(directory, "passwords.txt")
                logins.write_text("student\n", encoding="utf-8")
                passwords.write_text("secret\n", encoding="utf-8")
                extra = []
                if collision == "audit-targets":
                    extra = ["--audit", str(targets)]
                elif collision == "report-targets":
                    extra = ["--save-report", str(targets)]
                elif collision == "audit-logins":
                    extra = ["--audit", str(logins)]
                elif collision == "report-passwords":
                    extra = ["--save-report", str(passwords)]
                elif collision == "same-outputs":
                    shared = Path(directory, "shared.json")
                    extra = ["--audit", str(shared), "--save-report", str(shared)]
                else:
                    targets = Path(directory, "artifacts", "fixed-target-run", "001", "report.json")
                    targets.parent.mkdir(parents=True, exist_ok=True)
                    targets.write_text("\n".join(_URLS), encoding="utf-8")
                before = {path: path.read_bytes() for path in (targets, logins, passwords)}
                calls = []
                try:
                    code, _, _ = self.invoke(
                        directory, ["--targets-file", str(targets), *extra], self.runner(calls),
                        credentials=["--logins", str(logins), "--passwords", str(passwords)],
                    )
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                self.assertEqual(calls, [])
                for path, original in before.items():
                    self.assertEqual(path.read_bytes(), original)

    def test_target_error_continues_to_next_url_and_returns_failure(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            code, output, _ = self.invoke(
                directory, ["--targets-file", str(self.targets(directory)), "--json"],
                self.runner(calls, codes=(2, 0)),
            )
            self.assertEqual(code, 2)
            self.assertEqual(len(calls), 2)
            data = json.loads(output)
            self.assertEqual([entry["return_code"] for entry in data["results"]], [2, 0])
            self.assertEqual(data["processed_count"], 2)
            self.assertEqual(data["completed_count"], 1)
            self.assertEqual(data["failed_count"], 1)
            self.assertEqual(data["results"][0]["result"]["schema"], "browser-check/1")

    def test_target_error_persists_safe_component_diagnostic(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            private = "do-not-store-this-password"

            def failing(argv: list[str]) -> int:
                calls.append(argv.copy())
                print(
                    f"authchecker: The read operation timed out; password={private}",
                    file=__import__("sys").stderr,
                )
                return 2

            code, output, _ = self.invoke(
                directory,
                ["--targets-file", str(self.targets(directory)), "--json"],
                failing,
                credentials=["--login", "student", "--password", private],
            )

            self.assertEqual(code, 2)
            self.assertEqual(len(calls), 2)
            result = json.loads(output)["results"][0]["result"]
            self.assertEqual(result["reason"], "timeout")
            self.assertIn("timed out", result["detail"])
            root = Path(directory, "artifacts", "fixed-target-run")
            child = json.loads((root / "001" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(child["schema"], "target-error/1")
            combined = (
                output
                + (root / "report.json").read_text(encoding="utf-8")
                + (root / "001" / "report.json").read_text(encoding="utf-8")
            )
            self.assertNotIn(private, combined)

    def test_hard_link_outputs_cannot_modify_any_input(self) -> None:
        for output_flag in ("--audit", "--save-report"):
            for source_name in ("targets", "logins", "passwords"):
                with self.subTest(output_flag=output_flag, source=source_name), TemporaryDirectory() as directory:
                    sources = {"targets": self.targets(directory), "logins": Path(directory, "logins.txt"), "passwords": Path(directory, "passwords.txt")}
                    sources["logins"].write_text("student\n")
                    sources["passwords"].write_text("private-password\n")
                    output = Path(directory, "linked-output.json")
                    try:
                        output.hardlink_to(sources[source_name])
                    except OSError:
                        self.skipTest("hard links unavailable")
                    before = {path: path.read_bytes() for path in sources.values()}
                    calls = []
                    code, _, _ = self.invoke(
                        directory, ["--targets-file", str(sources["targets"]), output_flag, str(output)], self.runner(calls),
                        credentials=["--logins", str(sources["logins"]), "--passwords", str(sources["passwords"])],
                    )
                    self.assertEqual(code, 2)
                    self.assertEqual(calls, [])
                    for path, content in before.items():
                        self.assertEqual(path.read_bytes(), content)

    def test_hard_link_outputs_cannot_overwrite_other_reports(self) -> None:
        with TemporaryDirectory() as directory:
            targets = self.targets(directory)
            audit = Path(directory, "audit.jsonl")
            audit.write_text("original audit\n")
            aggregate = Path(directory, "aggregate.json")
            try:
                aggregate.hardlink_to(audit)
            except OSError:
                self.skipTest("hard links unavailable")
            calls = []
            code, _, _ = self.invoke(
                directory, ["--targets-file", str(targets), "--audit", str(audit), "--save-report", str(aggregate)], self.runner(calls),
            )
            self.assertEqual(code, 2)
            self.assertEqual(calls, [])
            self.assertEqual(audit.read_text(), "original audit\n")

    def test_unavailable_component_stops_remaining_targets(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            path = self.targets(directory, "\n".join((*_URLS, "https://third.example.org/login")))
            code, _, _ = self.invoke(directory, ["--targets-file", str(path)], self.runner(calls, codes=(0, 127, 0)))
            self.assertEqual(code, 127)
            self.assertEqual(len(calls), 2)

    def test_keyboard_interrupt_stops_remaining_targets_with_130(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            path = self.targets(directory, "\n".join((*_URLS, "https://third.example.org/login")))
            code, _, _ = self.invoke(directory, ["--targets-file", str(path)], self.runner(calls, codes=(0, KeyboardInterrupt(), 0)))
            self.assertEqual(code, 130)
            self.assertEqual(len(calls), 2)

    def test_reported_interruption_stops_batch_even_if_component_returns_zero(self) -> None:
        with TemporaryDirectory() as directory:
            calls = []
            path = self.targets(directory, "\n".join((*_URLS, "https://third.example.org/login")))
            code, output, _ = self.invoke(
                directory, ["--targets-file", str(path), "--json"],
                self.runner(calls, interrupted_at=1),
            )
            self.assertEqual(code, 130)
            self.assertEqual(len(calls), 2)
            payload = json.loads(output)
            self.assertEqual(payload["targets_count"], 3)
            self.assertEqual(payload["processed_count"], 2)
            self.assertEqual(payload["return_code"], 130)
            self.assertEqual(payload["results"][1]["return_code"], 130)
            self.assertEqual(payload["results"][1]["result"]["reason"], "interrupted")
