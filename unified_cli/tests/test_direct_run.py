from __future__ import annotations

import _support  # noqa: F401

from pathlib import Path
from stat import S_IMODE
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import io
import json
import sys
from contextlib import redirect_stderr

from goad.direct_run import (
    DEFAULT_USER_AGENT,
    _load_run_help,
    _find_and_select_logins,
    _valid_mail_domain,
    build_parser,
    direct_run_main,
    is_direct_run,
)


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class DirectRunTests(TestCase):
    def test_password_values_are_saved_separately_with_private_permissions(self) -> None:
        with TemporaryDirectory() as directory:
            checked: list[list[str]] = []
            code = direct_run_main(
                ["--target", "https://example.test/login", "--login", "student",
                 "--password", "first", "--password", "second", "-s", directory],
                runner=lambda argv: checked.append(argv) or 0,
                run_id="separate-passwords", stdout=io.StringIO(), stderr=io.StringIO(),
            )
            saved = Path(directory) / "separate-passwords" / "password-candidates.txt"
            self.assertEqual(code, 0)
            self.assertEqual(saved.read_text(encoding="utf-8"), "first\nsecond\n")
            self.assertEqual(S_IMODE(saved.stat().st_mode), 0o600)
            self.assertEqual(
                [checked[0][index + 1] for index, value in enumerate(checked[0]) if value == "--password"],
                ["first", "second"],
            )

    def test_password_file_is_copied_without_changing_authentication_input(self) -> None:
        with TemporaryDirectory() as directory:
            original = Path(directory) / "generated-passwords.txt"
            original.write_bytes(b"first\nsecond\n")
            checked: list[list[str]] = []
            code = direct_run_main(
                ["--target", "https://example.test/login", "--login", "student",
                 "--passwords", str(original), "-s", directory],
                runner=lambda argv: checked.append(argv) or 0,
                run_id="copied-passwords", stdout=io.StringIO(), stderr=io.StringIO(),
            )
            saved = Path(directory) / "copied-passwords" / "password-candidates.txt"
            self.assertEqual(code, 0)
            self.assertEqual(saved.read_bytes(), original.read_bytes())
            self.assertEqual(S_IMODE(saved.stat().st_mode), 0o600)
            self.assertEqual(checked[0][checked[0].index("--passwords") + 1], str(original))

    def test_interrupted_login_collection_keeps_run_folder_and_exit_code(self) -> None:
        with TemporaryDirectory() as directory:
            diagnostics = io.StringIO()
            code = direct_run_main(
                ["--collect-logins", "--mail-domain", "example.ru",
                 "--email-source", "search", "-s", directory],
                login_runner=lambda _argv: 130,
                discover_runner=lambda _argv: self.fail("discovery must not run"),
                runner=lambda _argv: self.fail("authentication must not run"),
                stderr=diagnostics,
                run_id="interrupted-collection",
            )

        self.assertEqual(code, 130)
        self.assertIn("[ОСТАНОВЛЕНО]", diagnostics.getvalue())
        self.assertIn("[РЕЗУЛЬТАТЫ] Папка запуска:", diagnostics.getvalue())
        self.assertNotIn("Traceback", diagnostics.getvalue())

    def test_search_only_collection_uses_mail_domain_without_site_url(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            diagnostics = io.StringIO()

            result = direct_run_main(
                ["--collect-logins", "--mail-domain", "example.ru",
                 "--email-source", "search", "--search-engine", "yandex,google",
                 "--people-source", "search,setka", "--slow", "-s", directory],
                login_runner=lambda argv: calls.append(argv) or 0,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="search-only", stdout=io.StringIO(), stderr=diagnostics,
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertEqual(argv[argv.index("--domain") + 1], "example.ru")
        self.assertEqual(argv[argv.index("--company") + 1], "example")
        self.assertNotIn("--url", argv)
        self.assertEqual(
            [argv[index + 1] for index, value in enumerate(argv) if value == "--search-engine"],
            ["yandex", "google"],
        )
        self.assertIn("только внешние источники", diagnostics.getvalue())
        self.assertIn(
            f"[РЕЗУЛЬТАТЫ] Папка запуска: {Path(directory) / 'search-only'}",
            diagnostics.getvalue(),
        )

    def test_no_url_collection_rejects_site_source(self) -> None:
        with redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as raised:
                direct_run_main(["--collect-logins", "--mail-domain", "example.ru"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("сбор с сайта недоступен", errors.getvalue())

    def test_collection_lists_accept_commas_and_repeated_flags(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def collect(argv: list[str]) -> int:
                calls.append(argv)
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--collect-only",
                 "--email-source", "site,search", "--email-source", "search",
                 "--people-source", "site,setka", "--people-source", "site",
                 "--search-engine", "yandex,google", "--search-engine", "google",
                 "-s", directory],
                login_runner=collect,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="comma-options", stdout=io.StringIO(), stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        argv = calls[0]
        self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "--email-source"], ["site", "search"])
        self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "--people-source"], ["site", "setka"])
        self.assertEqual([argv[index + 1] for index, value in enumerate(argv) if value == "--search-engine"], ["yandex", "google"])

    def test_generate_opens_interactive_pattern_and_format_selection_without_auth(self) -> None:
        with TemporaryDirectory() as directory:
            args = build_parser().parse_args([
                "-u", "https://example.test/", "--collect-logins", "-g",
            ])
            forwarded: list[str] = []

            def collect(argv: list[str]) -> int:
                forwarded.extend(argv)
                return 0

            _find_and_select_logins(
                args, Path(directory), TtyInput("\n"), io.StringIO(), io.StringIO(),
                collect, require_candidates=False,
            )

            self.assertIn("--prompt-inferred-patterns", forwarded)
            self.assertNotIn("--no-pattern-prompt", forwarded)
            self.assertEqual(forwarded[forwarded.index("--kind") + 1], "login")

    def test_mail_domain_is_separate_from_site_scope(self) -> None:
        self.assertTrue(_valid_mail_domain("magnit-info.ru"))
        self.assertFalse(_valid_mail_domain("https://magnit-info.ru/path"))
        with TemporaryDirectory() as directory:
            args = build_parser().parse_args([
                "-u", "https://example.test/", "--collect-logins",
                "--mail-domain", "magnit-info.ru",
            ])
            forwarded: list[str] = []

            def collect(argv: list[str]) -> int:
                forwarded.extend(argv)
                return 0

            _find_and_select_logins(
                args, Path(directory), io.StringIO(), io.StringIO(), io.StringIO(),
                collect, require_candidates=False,
            )

            self.assertEqual(forwarded[forwarded.index("--domain") + 1], "magnit-info.ru")
            self.assertEqual(forwarded[forwarded.index("--url") + 1], "https://example.test/")
            self.assertEqual(forwarded[forwarded.index("--evidence-output") + 1], str(Path(directory) / "evidence.jsonl"))

    def test_explicit_company_name_is_forwarded_to_collection(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            diagnostics = io.StringIO()

            result = direct_run_main(
                ["--collect-logins", "--mail-domain", "micran.ru",
                 "--company", "Микран", "--people-source", "setka", "-s", directory],
                login_runner=lambda argv: calls.append(argv) or 0,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="company-name", stdout=io.StringIO(), stderr=diagnostics,
            )

        self.assertEqual(result, 0)
        self.assertEqual(calls[0][calls[0].index("--company") + 1], "Микран")
        self.assertEqual(calls[0][calls[0].index("--domain") + 1], "micran.ru")
        self.assertIn("Компания для поиска:  Микран", diagnostics.getvalue())
        self.assertEqual(
            build_parser().parse_args(["--company-name", "Микран"]).company_name,
            "Микран",
        )

    def test_setka_page_limit_is_forwarded_and_shown_in_plan(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            diagnostics = io.StringIO()
            code = direct_run_main(
                ["--collect-logins", "--mail-domain", "micran.ru", "--company", "Микран",
                 "--people-source", "setka", "--setka-max-pages", "2", "-s", directory],
                login_runner=lambda argv: calls.append(argv) or 0,
                discover_runner=lambda argv: self.fail("discovery must not run"),
                runner=lambda argv: self.fail("authentication must not run"),
                run_id="setka-limit", stdout=io.StringIO(), stderr=diagnostics,
            )

        self.assertEqual(code, 0)
        self.assertEqual(calls[0][calls[0].index("--setka-max-pages") + 1], "2")
        self.assertIn("до 2 страниц списков групп и 2 страниц участников", diagnostics.getvalue())

    def test_setka_page_limit_requires_positive_value_and_source(self) -> None:
        for argv in (
            ["--collect-logins", "--mail-domain", "micran.ru", "--people-source", "setka", "--setka-max-pages", "0"],
            ["--collect-logins", "--mail-domain", "micran.ru", "--people-source", "search", "--setka-max-pages", "2"],
        ):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as raised:
                    direct_run_main(argv)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("--setka-max-pages", errors.getvalue())

    def test_page_only_prints_only_confirmed_login_urls(self) -> None:
        with TemporaryDirectory() as directory:
            output = io.StringIO()
            errors = io.StringIO()

            def discover(argv: list[str]) -> int:
                print("[ERROR] HTTP https://app.example.test/: timed out")
                print("[FOUND] js_login https://other.example.test/sign-in")
                print("[FOUND] password_form https://example.test/login")
                print("[FOUND] password_form https://example.test/login")
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                    }], "issues": [{"target": "https://app.example.test/", "message": "timed out"}], "config": {"page_only_results": [
                        {"url": "https://example.test/", "final_url": "https://example.test/login", "status": "found",
                         "auth_types": ["password_form"]},
                        {"url": "https://app.example.test/", "status": "unverified",
                         "detail": "timed out"},
                    ]}}), encoding="utf-8",
                )
                return 3

            result = direct_run_main(
                ["-u", "https://example.test/login", "--page-only", "-s", directory],
                discover_runner=discover, run_id="page-status",
                stdout=output, stderr=errors,
            )
            run_log = (Path(directory) / "page-status" / "run.log").read_text(encoding="utf-8")

        self.assertEqual(result, 3)
        self.assertEqual(output.getvalue().count("[НАЙДЕНО] https://example.test/login"), 1)
        self.assertNotIn("[ERROR]", output.getvalue() + errors.getvalue())
        self.assertNotIn("[НЕ ПРОВЕРЕНО]", output.getvalue())
        self.assertNotIn("[НАЙДЕНО] https://other.example.test/sign-in", output.getvalue())
        self.assertIn("проблем: 1", output.getvalue())
        self.assertIn("[ERROR] HTTP https://app.example.test/: timed out", run_log)

    def test_page_only_shows_found_url_before_interruption(self) -> None:
        with TemporaryDirectory() as directory:
            output = io.StringIO()

            def discover(_argv: list[str]) -> int:
                print("[FOUND] password_form https://example.test/login")
                print("[ERROR] HTTP https://app.example.test/: timed out")
                raise KeyboardInterrupt

            result = direct_run_main(
                ["-u", "https://example.test/", "--page-only", "-s", directory],
                discover_runner=discover, run_id="page-interrupted",
                stdout=output, stderr=io.StringIO(),
            )

        self.assertEqual(result, 130)
        self.assertIn("[НАЙДЕНО] https://example.test/login", output.getvalue())
        self.assertNotIn("[ERROR]", output.getvalue())

    def test_page_only_verbose_keeps_diagnostics(self) -> None:
        with TemporaryDirectory() as directory:
            output = io.StringIO()

            def discover(argv: list[str]) -> int:
                print("[ERROR] HTTP https://app.example.test/: timed out")
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [], "issues": [], "config": {
                        "page_only_results": [{
                            "url": "https://app.example.test/", "status": "not_found",
                        }],
                    }}), encoding="utf-8",
                )
                return 0

            result = direct_run_main(
                ["-u", "https://example.test/", "--page-only", "-v", "-s", directory],
                discover_runner=discover, run_id="page-verbose",
                stdout=output, stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertIn("[ERROR] HTTP https://app.example.test/: timed out", output.getvalue())
        self.assertIn("[НЕ НАЙДЕНО] https://app.example.test/", output.getvalue())

    def test_page_only_accepts_mixed_discovery_file_without_katana(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "targets.txt")
            targets.write_text("https://example.test/login\n192.0.2.10\n", encoding="utf-8")
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [], "issues": []}), encoding="utf-8",
                )
                return 0

            result = direct_run_main(
                ["--discovery-file", str(targets), "--page-only", "--subfinder",
                 "-s", directory],
                discover_runner=discover, run_id="page-only-file",
                stdout=io.StringIO(), stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertIn("--page-only", calls[0])
        self.assertIn("subfinder", calls[0][calls[0].index("--tools") + 1])
        self.assertNotIn("katana", calls[0][calls[0].index("--tools") + 1])
        self.assertIn("http://192.0.2.10/", calls[0])

    def test_discovered_collection_runs_subfinder_once_then_collects_hosts(self) -> None:
        with TemporaryDirectory() as directory:
            order: list[str] = []
            login_calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                order.append("discover")
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [], "issues": [], "config": {
                        "subfinder": {"discovered_subdomains": ["app.example.test"]},
                    }}), encoding="utf-8",
                )
                return 0

            def collect(argv: list[str]) -> int:
                order.append("collect")
                login_calls.append(argv)
                return 0

            result = direct_run_main(
                ["-u", "https://example.test/", "--collect-logins", "--subfinder",
                 "--email-source", "site", "-s", directory],
                discover_runner=discover, login_runner=collect,
                run_id="discovered-collect", stdout=io.StringIO(), stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertEqual(order, ["discover", "collect"])
        self.assertIn("--extra-url", login_calls[0])
        self.assertIn("https://app.example.test/", login_calls[0])
        self.assertIn("--exact-hosts", login_calls[0])

    def test_collect_scope_option_is_removed_from_help(self) -> None:
        self.assertNotIn("--collect-scope", build_parser().format_help())

    def test_seed_collection_accepts_discovery_file_without_subfinder(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "targets.txt")
            targets.write_text(
                "https://example.test/\nhttps://app.example.test/login\n",
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [], "issues": []}), encoding="utf-8",
                )
                return 0

            def collect(argv: list[str]) -> int:
                calls.append(argv)
                return 0

            result = direct_run_main(
                ["--discovery-file", str(targets), "--collect-logins", "--page-only",
                 "--email-source", "site", "-s", directory],
                discover_runner=discover, login_runner=collect,
                run_id="file-collect", stdout=io.StringIO(), stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertIn("https://app.example.test/login", calls[0])
        self.assertIn("--exact-hosts", calls[0])

    def test_short_save_directory_contains_run_files(self) -> None:
        with TemporaryDirectory() as directory:
            save_root = Path(directory, "saved results")

            def discover(argv: list[str]) -> int:
                report = Path(argv[argv.index("--output") + 1])
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--collect-points", "-s", str(save_root)],
                discover_runner=discover,
                run_id="short-save-option",
            )

            run_dir = save_root / "short-save-option"
            self.assertEqual(result, 0)
            self.assertTrue((run_dir / "report.json").is_file())
            self.assertTrue((run_dir / "run.log").is_file())
            self.assertTrue(is_direct_run(["-s", str(save_root)]))

    def test_default_console_shows_full_plan_but_keeps_component_details_in_log(self) -> None:
        with TemporaryDirectory() as directory:
            output, diagnostics = io.StringIO(), io.StringIO()

            def discover(argv: list[str]) -> int:
                print("[KATANA] GET https://example.test/")
                report = Path(argv[argv.index("--output") + 1])
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--discover-only",
                 "--artifacts", directory],
                discover_runner=discover, stdout=output, stderr=diagnostics,
                run_id="quiet-run",
            )
            log_path = Path(directory, "quiet-run", "run.log")
            log_text = log_path.read_text(encoding="utf-8")
            mode = S_IMODE(log_path.stat().st_mode)

        self.assertEqual(result, 0)
        self.assertIn("[ПЛАН ЗАПУСКА]", diagnostics.getvalue())
        self.assertIn("Скорость поиска:", diagnostics.getvalue())
        self.assertIn("[ЛОГ]", diagnostics.getvalue())
        self.assertNotIn("[KATANA] GET", diagnostics.getvalue() + output.getvalue())
        self.assertIn("[KATANA] GET https://example.test/", log_text)
        self.assertIn("[ПЛАН ЗАПУСКА]", log_text)
        self.assertEqual(mode, 0o600)

    def test_collection_results_are_shown_once_without_duplicate_file_lines(self) -> None:
        with TemporaryDirectory() as directory:
            for interactive in (False, True):
                with self.subTest(interactive=interactive):
                    output, diagnostics = io.StringIO(), io.StringIO()
                    run_id = "interactive" if interactive else "noninteractive"

                    def collect(argv: list[str]) -> int:
                        found = Path(argv[argv.index("--emails-output") + 1])
                        people = Path(argv[argv.index("--people-output") + 1])
                        collection_log = Path(argv[argv.index("--auto-log") + 1])
                        for path in (found, people, collection_log):
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_text("", encoding="utf-8")
                        print(f"[СБОР] Подробный журнал: {collection_log}", file=sys.stderr)
                        print(f"[РЕЗУЛЬТАТ] E-mail: {found}")
                        print(f"[РЕЗУЛЬТАТ] ФИО: {people}")
                        print("[РЕЗУЛЬТАТ] Генерация логинов: пропущена (--collect-only)")
                        return 0

                    result = direct_run_main(
                        ["-u", "https://example.test", "--collect-logins",
                         "--artifacts", directory],
                        stdin=TtyInput() if interactive else io.StringIO(),
                        stdout=output, stderr=diagnostics,
                        login_runner=collect, run_id=run_id,
                    )
                    terminal = output.getvalue() + diagnostics.getvalue()
                    run_log = Path(directory, run_id, "run.log").read_text(encoding="utf-8")

                    self.assertEqual(result, 0)
                    self.assertIn("[ПЛАН ЗАПУСКА]", diagnostics.getvalue())
                    self.assertEqual(terminal.count("[РЕЗУЛЬТАТ] E-mail:"), 1)
                    self.assertEqual(terminal.count("[РЕЗУЛЬТАТ] ФИО:"), 1)
                    self.assertEqual(terminal.count("[РЕЗУЛЬТАТ] Генерация логинов:"), 1)
                    self.assertNotIn("[ФАЙЛ] ФИО:", terminal)
                    self.assertNotIn("[ФАЙЛ] Найденные e-mail:", terminal)
                    self.assertNotIn("[ФАЙЛ] Подробный журнал сбора:", terminal)
                    self.assertNotIn("[СБОР] Подробный журнал:", terminal)
                    self.assertIn("[СБОР] Подробный журнал:", run_log)

    def test_verbose_console_shows_component_details(self) -> None:
        with TemporaryDirectory() as directory:
            output, diagnostics = io.StringIO(), io.StringIO()

            def discover(argv: list[str]) -> int:
                print("[KATANA] GET https://example.test/")
                report = Path(argv[argv.index("--output") + 1])
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--discover-only", "-v",
                 "--artifacts", directory],
                discover_runner=discover, stdout=output, stderr=diagnostics,
                run_id="verbose-run",
            )

        self.assertEqual(result, 0)
        self.assertIn("[ПЛАН ЗАПУСКА]", diagnostics.getvalue())
        self.assertIn("[KATANA] GET", output.getvalue())

    def test_compact_auth_result_remains_visible_without_verbose(self) -> None:
        with TemporaryDirectory() as directory:
            output, diagnostics = io.StringIO(), io.StringIO()

            def check(_argv: list[str]) -> int:
                print("[HTTP] Получаю страницу входа", file=sys.stderr)
                print("[НЕУСПЕШНО] https://example.test/login — попыток: 1")
                return 0

            result = direct_run_main(
                ["--target", "https://example.test/login", "--login", "student",
                 "--password", "wrong", "--artifacts", directory],
                runner=check, stdout=output, stderr=diagnostics,
                run_id="auth-run",
            )
            log_text = Path(directory, "auth-run", "run.log").read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertIn("[НЕУСПЕШНО]", output.getvalue())
        self.assertNotIn("[HTTP] Получаю", diagnostics.getvalue())
        self.assertIn("[HTTP] Получаю", log_text)

    def test_targets_file_uses_the_same_quiet_console_and_full_log(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "targets.txt")
            targets.write_text("https://example.test/login\n", encoding="utf-8")
            output, diagnostics = io.StringIO(), io.StringIO()

            def check(_argv: list[str]) -> int:
                print("[HTTP] Обновляю страницу входа", file=sys.stderr)
                print("[НЕУСПЕШНО] https://example.test/login — попыток: 1")
                return 0

            result = direct_run_main(
                ["--targets-file", str(targets), "--login", "student",
                 "--password", "wrong", "--artifacts", directory],
                runner=check, stdout=output, stderr=diagnostics,
                run_id="batch-run",
            )
            log_text = Path(directory, "batch-run", "run.log").read_text(encoding="utf-8")

        self.assertEqual(result, 0)
        self.assertIn("[НЕУСПЕШНО]", output.getvalue())
        self.assertNotIn("[HTTP] Обновляю", diagnostics.getvalue())
        self.assertIn("[HTTP] Обновляю", log_text)

    def test_proxy_ignores_persistent_ca_and_warns_about_tls(self) -> None:
        with TemporaryDirectory() as directory:
            certificate = Path(directory, "proxy-ca.pem")
            certificate.write_text("test certificate", encoding="utf-8")
            calls: list[list[str]] = []
            errors = io.StringIO()

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({
                    "findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                    }],
                }), encoding="utf-8")
                return 0

            with patch.dict(
                "os.environ",
                {"GOAD_CA_CERT": str(certificate)},
            ):
                result = direct_run_main(
                    [
                        "-u", "https://example.test", "--discover-only", "-y", "-v",
                        "--proxy", "http://127.0.0.1:9090",
                        "--artifacts", directory,
                    ],
                    discover_runner=discover,
                    stderr=errors,
                )

            self.assertEqual(result, 0)
            self.assertNotIn("--ca-cert", calls[0])
            self.assertIn("Сертификат HTTPS через прокси не проверяется", errors.getvalue())

    def test_persistent_ca_is_ignored_without_proxy(self) -> None:
        with TemporaryDirectory() as directory:
            certificate = Path(directory, "proxy-ca.pem")
            certificate.write_text("test certificate", encoding="utf-8")
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            with patch.dict(
                "os.environ",
                {"GOAD_CA_CERT": str(certificate)},
            ):
                result = direct_run_main(
                    [
                        "-u", "https://example.test", "--discover-only", "-y",
                        "--artifacts", directory,
                    ],
                    discover_runner=discover,
                )

            self.assertEqual(result, 0)
            self.assertNotIn("--ca-cert", calls[0])

    def test_missing_persistent_ca_does_not_block_proxy(self) -> None:
        errors = io.StringIO()
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            with patch.dict(
                "os.environ",
                {"GOAD_CA_CERT": "/missing/goad-proxy-ca.pem"},
            ):
                result = direct_run_main([
                    "-u", "https://example.test", "--discover-only",
                    "--proxy", "http://127.0.0.1:9090", "--artifacts", directory,
                ], discover_runner=discover, stderr=errors)

            self.assertEqual(result, 0)
            self.assertNotIn("--ca-cert", calls[0])

    def test_explicit_ca_still_enables_verification(self) -> None:
        with TemporaryDirectory() as directory:
            certificate = Path(directory, "proxy-ca.pem")
            certificate.write_text("test certificate", encoding="utf-8")
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main([
                "-u", "https://example.test", "--discover-only",
                "--proxy", "http://127.0.0.1:9090", "--ca-cert", str(certificate),
                "--artifacts", directory,
            ], discover_runner=discover)

            self.assertEqual(result, 0)
            self.assertEqual(calls[0][calls[0].index("--ca-cert") + 1], str(certificate.resolve()))

    def test_fast_profile_is_forwarded_to_discovery(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                    }]}),
                    encoding="utf-8",
                )
                return 0

            code = direct_run_main(
                [
                    "-u", "https://example.test", "--fast",
                    "--discover-only", "-y", "--artifacts", directory,
                ],
                discover_runner=discover,
                stderr=io.StringIO(),
            )

        self.assertEqual(code, 0)
        delegated = calls[0]
        self.assertIn("--fast", delegated)
        for flag in (
            "--katana-rate-limit", "--katana-parallelism",
            "--katana-concurrency", "--paths-concurrency",
        ):
            self.assertNotIn(flag, delegated)

    def test_speed_profile_flags_are_exclusive(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "-u", "https://example.test", "--slow", "--fast",
                "--discover-only",
            ])

        self.assertEqual(raised.exception.code, 2)

    def test_keyboard_interrupt_during_discovery_is_reported_without_traceback(self) -> None:
        with TemporaryDirectory() as directory:
            diagnostics = io.StringIO()

            def interrupted(_argv: list[str]) -> int:
                raise KeyboardInterrupt

            code = direct_run_main(
                [
                    "-u", "https://example.test", "--discover-only",
                    "--artifacts", directory,
                ],
                discover_runner=interrupted,
                stderr=diagnostics,
                run_id="interrupted-discovery",
            )

        self.assertEqual(code, 130)
        message = diagnostics.getvalue()
        self.assertIn("[ОСТАНОВЛЕНО]", message)
        self.assertIn("Запуск прерван пользователем", message)
        self.assertNotIn("Traceback", message)

    def test_discovery_file_sends_urls_domains_and_ips_to_katana(self) -> None:
        with TemporaryDirectory() as directory:
            inputs = Path(directory, "discovery.txt")
            inputs.write_text(
                "https://example.test/start\nadmin.example.test\n192.0.2.10\n",
                encoding="utf-8",
            )
            calls: list[list[str]] = []
            diagnostics = io.StringIO()

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                    }]}),
                    encoding="utf-8",
                )
                return 0

            result = direct_run_main(
                [
                    "--discovery-file", str(inputs), "--discover-only", "-y",
                    "--katana-depth", "2", "-v", "--artifacts", directory,
                ],
                discover_runner=discover,
                runner=lambda argv: self.fail("module 4 must not run"),
                stderr=diagnostics,
                run_id="discovery-file",
            )

        self.assertEqual(result, 0)
        delegated = calls[0]
        self.assertEqual(delegated[delegated.index("--tools") + 1], "katana")
        goals = [delegated[index + 1] for index, value in enumerate(delegated) if value == "-u"]
        self.assertEqual(goals, [
            "https://example.test/start",
            "https://admin.example.test/",
            "http://admin.example.test/",
            "https://192.0.2.10/",
            "http://192.0.2.10/",
        ])
        plan = diagnostics.getvalue()
        self.assertIn("[ПЛАН ЗАПУСКА]", plan)
        self.assertIn("Katana:                включена, глубина 2", plan)
        self.assertIn("Nmap:                  отключён", plan)

    def test_discovery_file_cidr_requires_and_uses_nmap(self) -> None:
        with TemporaryDirectory() as directory:
            inputs = Path(directory, "networks.txt")
            inputs.write_text("192.0.2.0/30\n", encoding="utf-8")
            calls: list[list[str]] = []

            without_nmap = direct_run_main(
                ["--discovery-file", str(inputs), "--discover-only", "--artifacts", directory],
                discover_runner=lambda argv: self.fail("invalid CIDR must fail before module 3"),
                stderr=io.StringIO(),
                run_id="cidr-no-nmap",
            )

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{
                        "endpoint": "http://192.0.2.1/login",
                        "auth_type": "password_form",
                    }]}),
                    encoding="utf-8",
                )
                return 0

            with_nmap = direct_run_main(
                [
                    "--discovery-file", str(inputs), "--with-nmap",
                    "--discover-only", "-y", "--artifacts", directory,
                ],
                discover_runner=discover,
                run_id="cidr-with-nmap",
            )

        self.assertEqual(without_nmap, 2)
        self.assertEqual(with_nmap, 0)
        self.assertEqual(calls[0][calls[0].index("--tools") + 1], "katana,nmap")
        self.assertIn("192.0.2.0/30", calls[0])
        self.assertEqual(calls[0][calls[0].index("--top-ports") + 1], "100")

    def test_run_help_is_loaded_from_editable_module_three_style_file(self) -> None:
        help_text = build_parser().format_help()

        self.assertEqual(help_text, _load_run_help().rstrip() + "\n")
        self.assertIn("# ==================== ОСНОВНОЕ", help_text)
        self.assertIn("# ==================== ЦЕЛЬ И ЭТАПЫ", help_text)
        self.assertIn("# ==================== НАСТРОЙКА ПОИСКА", help_text)
        self.assertIn("--collect-points", help_text)
        self.assertIn("--subfinder", help_text)
        self.assertIn("--katana", help_text)
        self.assertIn("--standard-path", help_text)
        self.assertNotIn("--standart-path", help_text)
        self.assertNotIn("--login VALUE", help_text)
        self.assertNotIn("--logins FILE", help_text)
        self.assertNotIn("--password VALUE", help_text)
        self.assertNotIn("--passwords FILE", help_text)
        self.assertIn("--nmap", help_text)
        self.assertIn("# ==================== ЦЕЛЬ И ЭТАПЫ", help_text)
        self.assertIn("--collect-logins", help_text)
        self.assertIn("-g, --generate", help_text)
        self.assertIn("# ==================== ПРОВЕРКА И СКОРОСТЬ", help_text)
        self.assertIn("--fast", help_text)
        self.assertNotIn("--speed", help_text)

    def test_only_correct_standard_path_spelling_is_accepted(self) -> None:
        parser = build_parser()
        self.assertTrue(parser.parse_args(["-u", "https://example.test", "--standard-path"]).standard_path)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            parser.parse_args(["-u", "https://example.test", "--standart-path"])
        self.assertEqual(error.exception.code, 2)

    def test_collect_points_defaults_to_katana_and_standard_paths(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--collect-points",
                    "--artifacts", directory,
                ],
                discover_runner=discover,
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="collect-points-default",
            )

        self.assertEqual(result, 0)
        self.assertEqual(calls[0][calls[0].index("--tools") + 1], "katana")
        self.assertIn("--standard-paths", calls[0])

    def test_collect_points_runs_only_selected_methods(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--collect-points",
                    "--nmap", "--standard-path", "--artifacts", directory,
                ],
                discover_runner=discover,
                run_id="collect-points-selected",
            )

        self.assertEqual(result, 0)
        self.assertEqual(calls[0][calls[0].index("--tools") + 1], "nmap")
        self.assertIn("--standard-paths", calls[0])
        self.assertNotIn("katana", calls[0])
        self.assertEqual(calls[0][calls[0].index("--top-ports") + 1], "100")

    def test_subfinder_alone_adds_katana_to_check_discovered_hosts(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--subfinder",
                    "--artifacts", directory,
                ],
                discover_runner=discover,
                run_id="subfinder-check",
            )

        self.assertEqual(result, 0)
        self.assertEqual(
            calls[0][calls[0].index("--tools") + 1], "katana,subfinder"
        )
        self.assertIn("--no-standard-paths", calls[0])

    def test_collect_logins_and_generate_are_independent_stage_controls(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def collect(argv: list[str]) -> int:
                calls.append(argv)
                for flag in ("--emails-output", "--people-output", "--output"):
                    output = Path(argv[argv.index(flag) + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text("", encoding="utf-8")
                return 0

            plain = direct_run_main(
                [
                    "-u", "https://example.test", "--collect-logins",
                    "--artifacts", directory,
                ],
                login_runner=collect,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="collect-logins",
            )
            generated = direct_run_main(
                [
                    "-u", "https://example.test", "-g",
                    "--artifacts", directory,
                ],
                login_runner=collect,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="generate-logins",
            )

        self.assertEqual((plain, generated), (0, 0))
        self.assertIn("--collect-only", calls[0])
        self.assertNotIn("--collect-only", calls[1])
        self.assertEqual(calls[1][calls[1].index("--kind") + 1], "login")

    def test_new_collection_and_discovery_stages_compose_before_auth(self) -> None:
        with TemporaryDirectory() as directory:
            order: list[str] = []
            checks: list[list[str]] = []
            selected_candidates: list[str] = []

            def collect(argv: list[str]) -> int:
                order.append("collect")
                found = Path(argv[argv.index("--emails-output") + 1])
                generated = Path(argv[argv.index("--output") + 1])
                found.parent.mkdir(parents=True, exist_ok=True)
                found.write_text("student@example.test\n", encoding="utf-8")
                generated.write_text("student\n", encoding="utf-8")
                return 0

            def discover(argv: list[str]) -> int:
                order.append("discover")
                report = Path(argv[argv.index("--output") + 1])
                report.write_text(json.dumps({
                    "findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                        "metadata": {"identifier_kind": "username"},
                    }],
                }), encoding="utf-8")
                return 0

            def check(argv: list[str]) -> int:
                order.append("check")
                checks.append(argv)
                path = Path(argv[argv.index("--logins") + 1])
                selected_candidates.append(path.read_text(encoding="utf-8"))
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test",
                    "--collect-logins", "-g",
                    "--collect-points", "--katana",
                    "--password", "secret", "-y",
                    "--artifacts", directory,
                ],
                login_runner=collect,
                discover_runner=discover,
                runner=check,
                run_id="composed-stages",
            )

        self.assertEqual(result, 0)
        self.assertEqual(order, ["collect", "discover", "check"])
        self.assertIn("--auto-login-candidates", checks[0])
        self.assertEqual(selected_candidates, ["student\n"])

    def test_collect_only_selects_independent_sources_inside_run(self) -> None:
        with TemporaryDirectory() as directory:
            login_calls: list[list[str]] = []
            diagnostics = io.StringIO()

            def collect(argv: list[str]) -> int:
                login_calls.append(argv)
                for flag in ("--emails-output", "--people-output"):
                    output = Path(argv[argv.index(flag) + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text("", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--collect-only",
                    "--email-source", "search", "--people-source", "setka",
                    "--search-engine", "yandex", "--artifacts", directory, "--no-documents",
                ],
                login_runner=collect,
                discover_runner=lambda argv: self.fail("module 3 must not run"),
                runner=lambda argv: self.fail("module 4 must not run"),
                run_id="collect-only",
                stderr=diagnostics,
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(login_calls), 1)
        delegated = login_calls[0]
        self.assertIn("--no-documents", delegated)
        self.assertNotIn("--url", delegated)
        self.assertEqual(
            delegated[delegated.index("--email-source") + 1], "search"
        )
        self.assertEqual(
            delegated[delegated.index("--people-source") + 1], "setka"
        )
        self.assertEqual(
            delegated[delegated.index("--search-engine") + 1], "yandex"
        )
        self.assertEqual(
            delegated[delegated.index("--request-delay") + 1], "3.0"
        )
        self.assertIn("Обход сайта (сбор):    отключён", diagnostics.getvalue())
        self.assertIn("пауза между открытием страниц/PDF: 3 с", diagnostics.getvalue())
        self.assertIn("Setka, лимиты:        не чаще 1 открытия страницы за 15 с", diagnostics.getvalue())

    def test_browser_crawl_is_forwarded_to_collection_and_shown_in_plan(self) -> None:
        with TemporaryDirectory() as directory:
            login_calls: list[list[str]] = []
            diagnostics = io.StringIO()

            def collect(argv: list[str]) -> int:
                login_calls.append(argv)
                for flag in ("--emails-output", "--people-output"):
                    output = Path(argv[argv.index(flag) + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text("", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--collect-only",
                    "--browser-crawl", "-v", "--artifacts", directory,
                ],
                login_runner=collect,
                stderr=diagnostics,
            )

        self.assertEqual(result, 0)
        self.assertIn("--browser-crawl", login_calls[0])
        self.assertIn("Обход сайта (сбор):    Chromium с JavaScript", diagnostics.getvalue())

    def test_collection_can_run_before_explicit_login_check(self) -> None:
        with TemporaryDirectory() as directory:
            stage_order: list[str] = []
            login_calls: list[list[str]] = []
            check_calls: list[list[str]] = []

            def collect(argv: list[str]) -> int:
                stage_order.append("collect")
                login_calls.append(argv)
                for flag in ("--emails-output", "--people-output"):
                    output = Path(argv[argv.index(flag) + 1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text("", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "--target", "https://example.test/login", "--collect-info",
                    "--people-source", "setka", "--login", "student",
                    "--password", "secret", "--artifacts", directory,
                ],
                login_runner=collect,
                runner=lambda argv: stage_order.append("check") or check_calls.append(argv) or 0,
                run_id="collect-and-check",
            )

        self.assertEqual(result, 0)
        self.assertEqual(stage_order, ["collect", "check"])
        self.assertEqual(login_calls[0][login_calls[0].index("--people-source") + 1], "setka")
        self.assertNotIn("--email-source", login_calls[0])
        self.assertEqual(check_calls[0][check_calls[0].index("--login") + 1], "student")

    def test_browser_http_forwards_transport_and_browser_options(self) -> None:
        calls: list[list[str]] = []
        code = direct_run_main([
            "--browser-http", "--target", "https://example.test/login",
            "--login", "student", "--password", "one", "--password", "two",
            "--headless", "--browser-timeout", "90", "--timeout", "20",
            "--success-selector", ".account", "--failure-selector", ".error",
            "--threads", "3", "--rate", "2.5", "--max-total", "7", "--max-per-account", "2",
        ], runner=lambda args: calls.append(args) or 0,
            discover_runner=lambda args: self.fail("browser bootstrap must bypass PointFinder"))
        self.assertEqual(code, 0)
        delegated = calls[0]
        self.assertIn("--browser-http", delegated)
        self.assertNotIn("--browser", delegated)
        self.assertIn("--headless", delegated)
        self.assertEqual(delegated.count("--password"), 2)
        for flag, value in (("--url", "https://example.test/login"), ("--browser-timeout", "90.0"), ("--timeout", "20.0"), ("--success-selector", ".account"), ("--failure-selector", ".error"), ("--threads", "3"), ("--rate", "2.5"), ("--max-total", "7"), ("--max-per-account", "2")):
            self.assertEqual(delegated[delegated.index(flag) + 1], value)

    def test_browser_transports_are_exclusive(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "--browser", "--browser-http", "--target", "https://example.test/login",
                "--login", "student", "--password", "secret",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_auto_browser_is_forwarded_without_eager_discovery(self) -> None:
        calls: list[list[str]] = []
        code = direct_run_main([
            "--auto-browser", "--target", "https://example.test/login",
            "--login", "student", "--password", "secret",
            "--browser-timeout", "90", "--threads", "4",
        ], runner=lambda args: calls.append(args) or 0,
            discover_runner=lambda args: self.fail("auto mode discovery belongs to module 4"))

        self.assertEqual(code, 0)
        self.assertIn("--auto-browser", calls[0])
        self.assertIn("--headless", calls[0])
        self.assertNotIn("--browser", calls[0])
        self.assertNotIn("--browser-http", calls[0])
        self.assertEqual(calls[0][calls[0].index("--threads") + 1], "4")

    def test_exact_target_enables_auto_browser_without_flag(self) -> None:
        calls: list[list[str]] = []
        diagnostics = io.StringIO()
        code = direct_run_main([
            "--target", "https://example.test/login",
            "--login", "student", "--password", "secret",
        ], runner=lambda argv: calls.append(argv) or 0,
            discover_runner=lambda argv: self.fail("exact target must not crawl"),
            stderr=diagnostics)

        self.assertEqual(code, 0)
        self.assertIn("--auto-browser", calls[0])
        self.assertIn("--headless", calls[0])
        self.assertNotIn("--browser-http", calls[0])
        self.assertNotIn("--report", calls[0])
        self.assertIn("Browser авторизации:   автоматически", diagnostics.getvalue())
        self.assertIn("Окно Chromium:         скрыто (headless)", diagnostics.getvalue())

    def test_show_browser_keeps_automatic_http_first_mode_visible(self) -> None:
        calls: list[list[str]] = []
        diagnostics = io.StringIO()
        code = direct_run_main([
            "--target", "https://example.test/login",
            "--login", "student", "--password", "secret", "--show-browser",
        ], runner=lambda argv: calls.append(argv) or 0,
            discover_runner=lambda argv: self.fail("exact target must not crawl"),
            stderr=diagnostics)

        self.assertEqual(code, 0)
        self.assertIn("--auto-browser", calls[0])
        self.assertNotIn("--headless", calls[0])
        self.assertIn("Окно Chromium:         видимое", diagnostics.getvalue())

    def test_show_browser_and_headless_are_exclusive(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "--target", "https://example.test/login", "--login", "student",
                "--password", "secret", "--show-browser", "--headless",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_show_browser_requires_browser_fallback(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "--target", "https://example.test/login", "--login", "student",
                "--password", "secret", "--no-auto-browser", "--show-browser",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_targets_file_enables_auto_browser_for_each_page(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "targets.txt")
            targets.write_text("https://example.test/login\n", encoding="utf-8")
            calls: list[list[str]] = []
            diagnostics = io.StringIO()
            code = direct_run_main([
                "--targets-file", str(targets),
                "--login", "student", "--password", "secret",
                "-s", directory,
            ], runner=lambda argv: calls.append(argv) or 0,
                discover_runner=lambda argv: self.fail("ready pages must not crawl"),
                stdout=io.StringIO(), stderr=diagnostics)

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("--auto-browser", calls[0])
        self.assertNotIn("--max-total", calls[0])
        self.assertIn("общий лимит попыток не задан", diagnostics.getvalue())

    def test_direct_target_has_no_implicit_total_attempt_limit(self) -> None:
        calls: list[list[str]] = []
        code = direct_run_main([
            "--target", "https://example.test/login", "-l", "student",
            "-p", "secret",
        ], runner=lambda argv: calls.append(argv) or 0,
            stdout=io.StringIO(), stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertNotIn("--max-total", calls[0])

    def test_plan_shows_effective_limits_for_each_discovery_tool(self) -> None:
        expected = {
            "slow": ("до 1 запрос/с", "процессов: 1", "потоков/процесс: 1",
                     "потоков: 1; пауза между стартами: 1 с", "-T2"),
            "normal": ("до 10 запрос/с", "процессов: 2", "потоков/процесс: 5",
                       "потоков: 5; пауза между стартами: 0 с", "-T3"),
            "fast": ("до 50 запрос/с", "процессов: 4", "потоков/процесс: 10",
                     "потоков: 10; пауза между стартами: 0 с", "-T4"),
        }
        with TemporaryDirectory() as directory:
            for profile, fragments in expected.items():
                with self.subTest(profile=profile):
                    diagnostics = io.StringIO()

                    def discover(argv: list[str]) -> int:
                        Path(argv[argv.index("--output") + 1]).write_text(
                            json.dumps({"findings": [], "issues": []}), encoding="utf-8"
                        )
                        return 0

                    code = direct_run_main([
                        "-u", "https://example.test", "--collect-points", "--subfinder",
                        "--katana", "--standard-path", "--nmap", f"--{profile}",
                        "-s", directory,
                    ], discover_runner=discover, run_id=f"limits-{profile}",
                        stdout=io.StringIO(), stderr=diagnostics)

                    self.assertEqual(code, 0)
                    plan = diagnostics.getvalue()
                    for fragment in fragments:
                        self.assertIn(fragment, plan)
                    self.assertIn("Subfinder, лимиты:", plan)
                    self.assertIn("Katana, лимиты:", plan)
                    self.assertIn("HTTP точек, лимиты:", plan)
                    self.assertIn("Nmap, лимиты:", plan)

    def test_auto_browser_with_url_discovers_then_checks_exact_pages(self) -> None:
        with TemporaryDirectory() as directory:
            discovery_calls: list[list[str]] = []
            check_calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                discovery_calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({
                    "findings": [{
                        "kind": "web_login_page",
                        "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                    }],
                    "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "--auto-browser", "-u", "https://example.test",
                "--login", "student", "--password", "secret", "-y",
                "--artifacts", directory,
            ], discover_runner=discover, runner=lambda argv: check_calls.append(argv) or 0)

        self.assertEqual(code, 0)
        self.assertEqual(len(discovery_calls), 1)
        self.assertEqual(len(check_calls), 1)
        self.assertIn("--auto-browser", check_calls[0])
        self.assertNotIn("--report", check_calls[0])
        self.assertEqual(
            check_calls[0][check_calls[0].index("--url") + 1],
            "https://example.test/login",
        )

    def test_short_url_with_credentials_explains_implicit_discovery(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            check_calls: list[list[str]] = []
            diagnostics = io.StringIO()

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                Path(argv[argv.index("--output") + 1]).write_text(
                    json.dumps({"findings": [{
                        "kind": "web_login_page", "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                    }], "issues": []}), encoding="utf-8",
                )
                return 0

            code = direct_run_main([
                "-u", "https://example.test", "--login", "student",
                "--password", "secret", "-y", "-s", directory,
            ], discover_runner=discover,
                runner=lambda argv: check_calls.append(argv) or 0,
                stdout=io.StringIO(), stderr=diagnostics)

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("katana", calls[0][calls[0].index("--tools") + 1])
        self.assertIn("--standard-paths", calls[0])
        self.assertIn("Поиск точек:           включён автоматически", diagnostics.getvalue())
        self.assertEqual(len(check_calls), 1)
        self.assertIn("--auto-browser", check_calls[0])
        self.assertNotIn("--report", check_calls[0])

    def test_discovery_file_defaults_to_auto_browser_for_authentication(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "seeds.txt")
            targets.write_text("https://example.test\n", encoding="utf-8")
            checks: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps({
                    "findings": [{
                        "kind": "web_login_page", "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                    }], "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "--discovery-file", str(targets), "--login", "student",
                "--password", "secret", "-y", "-s", directory,
            ], discover_runner=discover,
                runner=lambda argv: checks.append(argv) or 0,
                stdout=io.StringIO(), stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(len(checks), 1)
        self.assertIn("--auto-browser", checks[0])

    def test_no_auto_browser_keeps_exact_target_on_http(self) -> None:
        calls: list[list[str]] = []
        diagnostics = io.StringIO()
        code = direct_run_main([
            "--target", "https://example.test/login", "--login", "student",
            "--password", "secret", "--no-auto-browser",
        ], runner=lambda argv: calls.append(argv) or 0,
            discover_runner=lambda argv: self.fail("exact target must not crawl"),
            stderr=diagnostics)

        self.assertEqual(code, 0)
        self.assertNotIn("--auto-browser", calls[0])
        self.assertNotIn("--browser", calls[0])
        self.assertIn("отключён (--no-auto-browser; только HTTP-авторизация)", diagnostics.getvalue())

    def test_no_auto_browser_keeps_discovered_form_on_http(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps({
                    "findings": [{
                        "kind": "web_login_page", "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                        "metadata": {"form_method": "GET"},
                    }], "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "-u", "https://example.test", "--login", "student",
                "--password", "secret", "--no-auto-browser", "-y", "-s", directory,
            ], discover_runner=discover,
                runner=lambda argv: calls.append(argv) or 0,
                stdout=io.StringIO(), stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("--report", calls[0])
        self.assertNotIn("--auto-browser", calls[0])

    def test_no_auto_browser_conflicts_with_forced_browser_modes(self) -> None:
        for flag in ("--auto-browser", "--browser", "--browser-http"):
            with self.subTest(flag=flag), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                direct_run_main([
                    "--target", "https://example.test/login", "--login", "student",
                    "--password", "secret", "--no-auto-browser", flag,
                ])
            self.assertEqual(raised.exception.code, 2)

    def test_no_auto_browser_requires_authentication(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "-u", "https://example.test", "--discover-only", "--no-auto-browser",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_no_auto_browser_is_forwarded_to_each_ready_page(self) -> None:
        with TemporaryDirectory() as directory:
            targets = Path(directory, "pages.txt")
            targets.write_text("https://example.test/login\n", encoding="utf-8")
            calls: list[list[str]] = []
            code = direct_run_main([
                "--targets-file", str(targets), "--login", "student",
                "--password", "secret", "--no-auto-browser", "-s", directory,
            ], runner=lambda argv: calls.append(argv) or 0,
                stdout=io.StringIO(), stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--auto-browser", calls[0])

    def test_quick_mode_allows_http_only_authentication_override(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def collect(argv: list[str]) -> int:
                Path(argv[argv.index("--emails-output") + 1]).write_text(
                    "student@example.test\n", encoding="utf-8"
                )
                return 0

            def discover(argv: list[str]) -> int:
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps({
                    "findings": [{
                        "kind": "web_login_page", "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                    }], "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "-q", "-u", "https://example.test", "--password", "secret",
                "--no-auto-browser", "-y", "-s", directory,
            ], login_runner=collect, discover_runner=discover,
                runner=lambda argv: calls.append(argv) or 0,
                stdout=io.StringIO(), stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("--report", calls[0])
        self.assertNotIn("--auto-browser", calls[0])

    def test_default_auto_browser_skips_unsupported_passwordless_and_sso_findings(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            output = io.StringIO()

            def discover(argv: list[str]) -> int:
                Path(argv[argv.index("--output") + 1]).write_text(json.dumps({
                    "findings": [
                        {"kind": "web_login_page", "auth_type": "password_form",
                         "endpoint": "https://example.test/login"},
                        {"kind": "web_login_page", "auth_type": "passwordless_form",
                         "endpoint": "https://example.test/email"},
                        {"kind": "sso_entry", "auth_type": "oauth2",
                         "endpoint": "https://example.test/sso"},
                    ], "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "-u", "https://example.test", "--login", "student",
                "--password", "secret", "-y", "-s", directory,
            ], discover_runner=discover,
                runner=lambda argv: calls.append(argv) or 0,
                stdout=output, stderr=io.StringIO())

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][calls[0].index("--url") + 1], "https://example.test/login")
        self.assertNotIn("https://example.test/email", output.getvalue())
        self.assertNotIn("https://example.test/sso", output.getvalue())

    def test_non_post_discovered_form_switches_to_browser_without_flag(self) -> None:
        with TemporaryDirectory() as directory:
            check_calls: list[list[str]] = []
            errors = io.StringIO()

            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps({
                    "findings": [{
                        "kind": "web_login_page",
                        "auth_type": "password_form",
                        "endpoint": "https://example.test/login",
                        "metadata": {"form_method": "GET"},
                    }],
                    "issues": [],
                }), encoding="utf-8")
                return 0

            code = direct_run_main([
                "-u", "https://example.test/login",
                "--login", "student", "--password", "secret", "-y",
                "--artifacts", directory,
            ], discover_runner=discover,
                runner=lambda argv: check_calls.append(argv) or 0,
                stderr=errors)

        self.assertEqual(code, 0)
        self.assertEqual(len(check_calls), 1)
        self.assertIn("--auto-browser", check_calls[0])
        self.assertNotIn("--report", check_calls[0])
        self.assertEqual(
            check_calls[0][check_calls[0].index("--url") + 1],
            "https://example.test/login",
        )
        self.assertIn("Browser авторизации:   автоматически", errors.getvalue())

    def test_browser_mode_forwards_flags_without_discovery(self) -> None:
        calls: list[list[str]] = []
        code = direct_run_main([
            "--browser", "--target", "https://example.test/login",
            "--login", "student", "--password", "secret", "--headless",
            "--browser-timeout", "90", "--success-selector", ".account",
            "--failure-selector", ".error", "--proxy", "http://127.0.0.1:9090",
        ], runner=lambda args: calls.append(args) or 0,
            discover_runner=lambda args: self.fail("browser mode must bypass PointFinder"))
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("--browser", calls[0])
        self.assertIn("--headless", calls[0])
        self.assertNotIn("--report", calls[0])
        self.assertEqual(calls[0][calls[0].index("--url") + 1], "https://example.test/login")
        self.assertEqual(calls[0][calls[0].index("--browser-timeout") + 1], "90.0")
        self.assertEqual(calls[0][calls[0].index("--success-selector") + 1], ".account")
        self.assertEqual(calls[0][calls[0].index("--failure-selector") + 1], ".error")

    def test_browser_mode_forwards_inline_lists_and_existing_limits(self) -> None:
        calls: list[list[str]] = []
        code = direct_run_main([
            "--browser", "--target", "http://127.0.0.1:8080/login",
            "--login", "student", "--login", "admin",
            "--password", "one", "--password", "two",
            "--threads", "3", "--rate", "2.5",
            "--max-total", "7", "--max-per-account", "2",
        ], runner=lambda argv: calls.append(argv) or 0)
        self.assertEqual(code, 0)
        delegated = calls[0]
        self.assertEqual([delegated[i + 1] for i, value in enumerate(delegated) if value == "--login"], ["student", "admin"])
        self.assertEqual([delegated[i + 1] for i, value in enumerate(delegated) if value == "--password"], ["one", "two"])
        for flag, value in (("--threads", "3"), ("--rate", "2.5"), ("--max-total", "7"), ("--max-per-account", "2")):
            self.assertEqual(delegated[delegated.index(flag) + 1], value)

    def test_browser_mode_forwards_files_without_loading_them_for_validation(self) -> None:
        with TemporaryDirectory() as directory:
            logins = Path(directory, "logins.txt")
            passwords = Path(directory, "passwords.txt")
            logins.write_text("student\nadmin\n", encoding="utf-8")
            passwords.write_text("one\ntwo\n", encoding="utf-8")
            calls: list[list[str]] = []
            with patch.object(Path, "read_text", side_effect=AssertionError("credential files must be streamed by module 4")):
                code = direct_run_main([
                    "--browser", "--target", "http://127.0.0.1:8080/login",
                    "--logins", str(logins), "--passwords", str(passwords), "--threads", "4",
                ], runner=lambda argv: calls.append(argv) or 0)
            self.assertEqual(code, 0)
            delegated = calls[0]
            self.assertEqual(delegated[delegated.index("--logins") + 1], str(logins))
            self.assertEqual(delegated[delegated.index("--passwords") + 1], str(passwords))
            self.assertEqual(delegated[delegated.index("--threads") + 1], "4")

    def test_browser_mode_rejects_discovery_flags(self) -> None:
        for mode in ("--browser", "--browser-http"):
            for extra in (["-u", "https://example.test"], ["--target", "https://example.test/login", "-q"], ["--target", "https://example.test/login", "--discover-only"]):
                with self.subTest(mode=mode, extra=extra), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    direct_run_main([mode, "--login", "student", "--password", "secret", *extra])
                self.assertEqual(raised.exception.code, 2)

    def test_mode_detection_preserves_toml_pipeline(self) -> None:
        self.assertTrue(is_direct_run([]))
        self.assertTrue(is_direct_run(["--help"]))
        self.assertTrue(is_direct_run(["--login", "student"]))
        self.assertTrue(is_direct_run(["--browser-http"]))
        self.assertTrue(is_direct_run(["--target=http://127.0.0.1:8080/login"]))
        self.assertTrue(is_direct_run(["-q", "-u", "http://127.0.0.1:8080"]))
        self.assertFalse(is_direct_run(["pipeline.toml"]))
        self.assertFalse(is_direct_run(["--validate-only", "pipeline.toml"]))

    def test_short_command_delegates_to_check_with_safe_defaults(self) -> None:
        with TemporaryDirectory() as directory:
            artifacts = Path(directory, "artifacts")
            calls: list[list[str]] = []
            result = direct_run_main(
                [
                    "--target",
                    "http://127.0.0.1:8080/login",
                    "--login",
                    "student",
                    "--password",
                    "password123",
                    "--rate",
                    "4",
                    "--threads",
                    "3",
                    "--artifacts",
                    str(artifacts),
                ],
                runner=lambda argv: calls.append(argv) or 7,
                run_id="fixed-run",
            )

        self.assertEqual(result, 7)
        self.assertEqual(len(calls), 1)
        delegated = calls[0]
        self.assertEqual(delegated[:4], ["run", "--live", "--url", "http://127.0.0.1:8080/login"])
        self.assertNotIn("--proxy", delegated)
        self.assertEqual(delegated[delegated.index("--login") + 1], "student")
        self.assertEqual(delegated[delegated.index("--password") + 1], "password123")
        self.assertEqual(
            delegated[delegated.index("--user-agent") + 1], DEFAULT_USER_AGENT
        )
        self.assertTrue(DEFAULT_USER_AGENT.startswith("Mozilla/5.0 "))
        self.assertNotIn("goad", DEFAULT_USER_AGENT)
        self.assertEqual(delegated[delegated.index("--rate") + 1], "4.0")
        self.assertEqual(delegated[delegated.index("--threads") + 1], "3")
        self.assertEqual(
            delegated[delegated.index("--scope-domain") + 1], "127.0.0.1"
        )
        self.assertIn("--allow-subdomains", delegated)
        self.assertIn("--compact", delegated)
        self.assertEqual(
            delegated[delegated.index("--audit") + 1],
            str((artifacts / "fixed-run" / "audit.jsonl").resolve()),
        )
        self.assertEqual(
            delegated[delegated.index("--save-report") + 1],
            str((artifacts / "fixed-run" / "report.json").resolve()),
        )

    def test_slow_is_a_global_profile_and_caps_module_four(self) -> None:
        calls: list[list[str]] = []
        result = direct_run_main(
            [
                "--target", "https://example.test/login",
                "--login", "student", "--password", "secret",
                "--slow", "--rate", "8", "--threads", "7",
            ],
            runner=lambda argv: calls.append(argv) or 0,
        )

        self.assertEqual(result, 0)
        delegated = calls[0]
        self.assertIn("--slow", delegated)
        self.assertEqual(
            float(delegated[delegated.index("--rate") + 1]), 1.0 / 15.0
        )
        self.assertEqual(delegated[delegated.index("--threads") + 1], "1")

    def test_fast_is_a_global_profile_for_module_four(self) -> None:
        calls: list[list[str]] = []
        result = direct_run_main(
            [
                "--target", "https://example.test/login",
                "--login", "student", "--password", "secret", "--fast",
            ],
            runner=lambda argv: calls.append(argv) or 0,
        )

        self.assertEqual(result, 0)
        delegated = calls[0]
        self.assertNotIn("--slow", delegated)
        self.assertEqual(delegated[delegated.index("--rate") + 1], "5.0")
        self.assertEqual(delegated[delegated.index("--threads") + 1], "5")

    def test_file_inputs_and_overrides_are_forwarded(self) -> None:
        with TemporaryDirectory() as directory:
            logins = Path(directory, "users.txt")
            passwords = Path(directory, "secrets.txt")
            logins.write_text("student\n", encoding="utf-8")
            passwords.write_text("password123\n", encoding="utf-8")
            calls: list[list[str]] = []
            result = direct_run_main(
                [
                    "--target",
                    "http://127.0.0.1:8081/admin/basic",
                    "--logins",
                    str(logins),
                    "--passwords",
                    str(passwords),
                    "--proxy",
                    "http://127.0.0.1:9999",
                    "--audit",
                    "custom-audit.jsonl",
                    "--save-report",
                    "custom-report.json",
                ],
                runner=lambda argv: calls.append(argv) or 0,
                run_id="ignored-for-overrides",
            )

        self.assertEqual(result, 0)
        delegated = calls[0]
        self.assertEqual(delegated[delegated.index("--logins") + 1], str(logins))
        self.assertEqual(delegated[delegated.index("--passwords") + 1], str(passwords))
        self.assertIn("http://127.0.0.1:9999", delegated)
        self.assertTrue(delegated[delegated.index("--audit") + 1].endswith("custom-audit.jsonl"))
        self.assertTrue(delegated[delegated.index("--save-report") + 1].endswith("custom-report.json"))

    def test_json_option_keeps_detailed_module_output(self) -> None:
        calls: list[list[str]] = []
        result = direct_run_main(
            [
                "--target",
                "http://127.0.0.1:8080/login",
                "--login",
                "student",
                "--password",
                "password123",
                "--json",
            ],
            runner=lambda argv: calls.append(argv) or 0,
            run_id="json-run",
        )

        self.assertEqual(result, 0)
        self.assertNotIn("--compact", calls[0])

    def test_short_flags_accept_comma_lists_and_forward_user_agent(self) -> None:
        calls: list[list[str]] = []
        result = direct_run_main(
            [
                "--target", "http://127.0.0.1:8080/login",
                "-l", "admin,student", "-p", "one,two",
                "--user-agent", "My audit client",
            ],
            runner=lambda argv: calls.append(argv) or 0,
        )

        self.assertEqual(result, 0)
        self.assertEqual(calls[0].count("--login"), 2)
        self.assertEqual(calls[0].count("--password"), 2)
        self.assertEqual(calls[0][calls[0].index("--user-agent") + 1], "My audit client")

    def test_url_discovery_prints_and_filters_selected_endpoint(self) -> None:
        class TtyInput(io.StringIO):
            def isatty(self) -> bool:
                return True

        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            discovery_calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                discovery_calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "schema_version": "2.0",
                            "findings": [
                                {"endpoint": "http://127.0.0.1:8080/login", "auth_type": "password_form"},
                                {"endpoint": "http://127.0.0.1:8080/basic", "auth_type": "http_basic"},
                                {"endpoint": "http://127.0.0.1:8080/sso", "auth_type": "sso"},
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return 0

            output = io.StringIO()
            result = direct_run_main(
                ["-u", "http://127.0.0.1:8080", "--katana-depth", "2", "--katana-max-total-pages", "12", "--katana-max-dom-mb", "4", "--no-standard-paths", "-l", "student", "-p", "password123", "--artifacts", directory],
                stdin=TtyInput("2\n"),
                stdout=output,
                discover_runner=discover,
                runner=lambda argv: calls.append(argv) or 0,
                run_id="selection",
            )

            selected = Path(directory, "selection", "selected-report.json")
            payload = json.loads(selected.read_text(encoding="utf-8"))

        self.assertEqual(result, 0)
        self.assertIn("Найдены точки авторизации", output.getvalue())
        self.assertIn("--include-subdomains", discovery_calls[0])
        self.assertIn("--no-standard-paths", discovery_calls[0])
        self.assertNotIn("--standard-paths", discovery_calls[0])
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--katana-depth") + 1],
            "2",
        )
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--katana-max-total-pages") + 1],
            "12",
        )
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--katana-max-dom-mb") + 1],
            "4",
        )
        self.assertEqual([item["endpoint"] for item in payload["findings"]], ["http://127.0.0.1:8080/basic"])
        self.assertIn("--auto-browser", calls[0])
        self.assertNotIn("--report", calls[0])
        self.assertEqual(calls[0][calls[0].index("--url") + 1], "http://127.0.0.1:8080/basic")

    def test_katana_depth_requires_url_and_valid_range(self) -> None:
        invalid_commands = (
            ["-u", "https://example.test", "--katana-depth", "-1", "--discover-only"],
            ["-u", "https://example.test", "--katana-depth", "11", "--discover-only"],
            ["--target", "https://example.test/login", "--katana-depth", "2", "--login", "student", "--password", "secret"],
            ["--target", "https://example.test/login", "--no-standard-paths", "--login", "student", "--password", "secret"],
            ["-u", "https://example.test", "--katana-max-total-pages", "0", "--discover-only"],
            ["--target", "https://example.test/login", "--katana-max-total-pages", "10", "--login", "student", "--password", "secret"],
            ["-u", "https://example.test", "--katana-max-dom-mb", "0", "--discover-only"],
            ["-u", "https://example.test", "--katana-max-dom-mb", "33", "--discover-only"],
            ["--target", "https://example.test/login", "--katana-max-dom-mb", "2", "--login", "student", "--password", "secret"],
        )
        for command in invalid_commands:
            with self.subTest(command=command), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                direct_run_main(command)
            self.assertEqual(raised.exception.code, 2)

    def test_katana_depth_zero_maps_to_seed_only(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            diagnostics = io.StringIO()

            def discover(argv: list[str]) -> int:
                calls.append(argv)
                report = Path(argv[argv.index("--output") + 1])
                report.write_text(json.dumps({"findings": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--katana-depth", "0",
                 "--discover-only", "-v", "-s", directory],
                discover_runner=discover, run_id="depth-zero", stderr=diagnostics,
            )

            self.assertEqual(result, 0)
            self.assertEqual(calls[0][calls[0].index("--katana-depth") + 1], "1")
            self.assertIn("только стартовая страница (0)", diagnostics.getvalue())

    def test_missing_smart_file_is_reported(self) -> None:
        error = io.StringIO()
        result = direct_run_main(
            ["--target", "http://127.0.0.1:8080/login", "-l", "missing.txt", "-p", "password123"],
            stderr=error,
        )
        self.assertEqual(result, 2)
        self.assertIn("файл логинов не найден", error.getvalue())

    def test_browser_discovery_failure_is_visible_when_no_form_found(self) -> None:
        with TemporaryDirectory() as directory:
            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(
                        {
                            "findings": [],
                            "issues": [
                                {
                                    "stage": "katana_headless",
                                    "message": "Chromium certificate is not trusted",
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return 0

            error = io.StringIO()
            result = direct_run_main(
                ["-u", "https://example.test", "--discover-only", "--artifacts", directory],
                discover_runner=discover,
                stderr=error,
            )

        self.assertEqual(result, 3)
        self.assertIn("Chromium certificate is not trusted", error.getvalue())

    def test_discover_only_does_not_require_credentials(self) -> None:
        with TemporaryDirectory() as directory:
            check_calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{"endpoint": "http://127.0.0.1:8080/login", "auth_type": "password_form"}]}),
                    encoding="utf-8",
                )
                return 0

            result = direct_run_main(
                ["-u", "http://127.0.0.1:8080", "--discover-only", "-y", "--artifacts", directory],
                discover_runner=discover,
                runner=lambda argv: check_calls.append(argv) or 0,
            )

        self.assertEqual(result, 0)
        self.assertEqual(check_calls, [])

    def test_discover_only_empty_result_succeeds_without_tty_prompt(self) -> None:
        class NoPromptInput(TtyInput):
            def readline(self, *args: object, **kwargs: object) -> str:
                raise AssertionError("discover-only must not ask for authentication selection")

        with TemporaryDirectory() as directory:
            output = io.StringIO()
            errors = io.StringIO()

            def discover(argv: list[str]) -> int:
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": [], "issues": []}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--discover-only", "--artifacts", directory],
                discover_runner=discover,
                runner=lambda argv: self.fail("module 4 must not run"),
                stdin=NoPromptInput(),
                stdout=output,
                stderr=errors,
                run_id="empty-discovery",
            )

            self.assertFalse(Path(directory, "empty-discovery", "selected-report.json").exists())

        self.assertEqual(result, 0)
        self.assertIn("Точки авторизации не обнаружены", output.getvalue())
        self.assertIn("найдено точек 0", output.getvalue())
        self.assertIn("report.json", output.getvalue())
        self.assertIn("auth-links.txt", output.getvalue())
        self.assertNotIn("Выберите", output.getvalue())
        self.assertNotIn("ошибка:", errors.getvalue())

    def test_discover_only_shows_all_types_without_authentication_selection(self) -> None:
        with TemporaryDirectory() as directory:
            output = io.StringIO()
            stdin = TtyInput("q\n")
            types = ("password_form", "http_basic", "js_login", "oauth2", "passwordless_form")

            def discover(argv: list[str]) -> int:
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": [
                    {"endpoint": f"https://example.test/{auth_type}", "auth_type": auth_type}
                    for auth_type in types
                ]}), encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-u", "https://example.test", "--discover-only", "--artifacts", directory],
                discover_runner=discover,
                runner=lambda argv: self.fail("module 4 must not run"),
                stdin=stdin,
                stdout=output,
                stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertEqual(stdin.tell(), 0)
        self.assertNotIn("Выберите", output.getvalue())
        self.assertIn("найдено точек 5", output.getvalue())
        for auth_type in types:
            self.assertIn(f"({auth_type})", output.getvalue())

    def test_discover_only_preserves_partial_exit_code_and_diagnostics(self) -> None:
        for partial, issues, discovery_code in (
            (False, [], 3),
            (True, [], 0),
            (False, [{"target": "https://example.test/down", "message": "connection timed out"}], 0),
        ):
            with self.subTest(partial=partial, issues=issues, discovery_code=discovery_code):
                with TemporaryDirectory() as directory:
                    output = io.StringIO()
                    errors = io.StringIO()

                    def discover(argv: list[str]) -> int:
                        report = Path(argv[argv.index("--output") + 1])
                        report.parent.mkdir(parents=True, exist_ok=True)
                        report.write_text(json.dumps({
                            "findings": [], "partial": partial, "issues": issues,
                        }), encoding="utf-8")
                        return discovery_code

                    result = direct_run_main(
                        ["-u", "https://example.test", "--discover-only", "--artifacts", directory],
                        discover_runner=discover,
                        runner=lambda argv: self.fail("module 4 must not run"),
                        stdout=output,
                        stderr=errors,
                    )

                self.assertEqual(result, 3)
                self.assertIn("завершён частично", output.getvalue())
                if issues:
                    self.assertIn("connection timed out", errors.getvalue())

    def test_discover_only_rejects_invalid_reports(self) -> None:
        for payload in ([], {}, {"findings": {}}, {"findings": [None]}, {"findings": [{"auth_type": "js_login"}]}):
            with self.subTest(payload=payload), TemporaryDirectory() as directory:
                errors = io.StringIO()

                def discover(argv: list[str]) -> int:
                    report = Path(argv[argv.index("--output") + 1])
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_text(json.dumps(payload), encoding="utf-8")
                    return 0

                result = direct_run_main(
                    ["-u", "https://example.test", "--discover-only", "--artifacts", directory],
                    discover_runner=discover,
                    runner=lambda argv: self.fail("module 4 must not run"),
                    stdout=io.StringIO(),
                    stderr=errors,
                )

                self.assertEqual(result, 2)
                self.assertIn("отчёте", errors.getvalue())

    def test_browser_resource_domains_forwarded_only_to_discovery(self) -> None:
        with TemporaryDirectory() as directory:
            discovery_calls: list[list[str]] = []
            check_calls: list[list[str]] = []

            def discover(argv: list[str]) -> int:
                discovery_calls.append(argv)
                report = Path(argv[argv.index("--output") + 1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps({"findings": [{
                    "endpoint": "https://example.test/login", "auth_type": "password_form",
                }]}), encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--login", "student", "--password", "secret", "-y",
                    "--browser-resource-domain", "static.example.net",
                    "--browser-resource-domain", "assets.example.net",
                    "--browser-resource-domain", "STATIC.EXAMPLE.NET.",
                    "--artifacts", directory,
                ],
                discover_runner=discover,
                runner=lambda argv: check_calls.append(argv) or 0,
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )

        self.assertEqual(result, 0)
        self.assertEqual(discovery_calls[0].count("--browser-resource-domain"), 2)
        self.assertIn("static.example.net", discovery_calls[0])
        self.assertIn("assets.example.net", discovery_calls[0])
        self.assertNotIn("--browser-resource-domain", check_calls[0])
        self.assertTrue(is_direct_run(["--browser-resource-domain=static.example.net"]))

    def test_browser_resource_domains_require_discovery(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            direct_run_main([
                "--target", "https://example.test/login", "--login", "student", "--password", "secret",
                "--browser-resource-domain", "static.example.net",
            ])
        self.assertEqual(raised.exception.code, 2)

    def test_invalid_browser_resource_domains_fail_before_any_component(self) -> None:
        for value in (
            "https://static.example.net", "*.example.net", "static.example.net:443",
            "static.example.net/path", "assets\n.example.net", "bad_domain.example",
            "-assets.example.net", "example..net", "",
        ):
            with self.subTest(value=value), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                direct_run_main(
                    [
                        "-q", "-u", "https://example.test", "--password", "secret",
                        "--browser-resource-domain", value,
                    ],
                    login_runner=lambda argv: self.fail("module 2 must not run"),
                    discover_runner=lambda argv: self.fail("module 3 must not run"),
                    runner=lambda argv: self.fail("module 4 must not run"),
                )
            self.assertEqual(raised.exception.code, 2)

    def test_quick_preset_enables_slow_subdomain_discovery_and_all_search_engines(self) -> None:
        with TemporaryDirectory() as directory:
            discovery_calls: list[list[str]] = []
            login_calls: list[list[str]] = []
            check_calls: list[list[str]] = []
            selected_login_files: list[str] = []
            stage_order: list[str] = []

            def discover(argv: list[str]) -> int:
                stage_order.append("discover")
                discovery_calls.append(argv)
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{"endpoint": "http://127.0.0.1:8080/login", "auth_type": "password_form"}]}),
                    encoding="utf-8",
                )
                return 0

            def find_logins(argv: list[str]) -> int:
                stage_order.append("logins")
                login_calls.append(argv)
                output = Path(argv[argv.index("--found-emails-output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("student@example.test\n", encoding="utf-8")
                return 0

            def check(argv: list[str]) -> int:
                stage_order.append("check")
                check_calls.append(argv)
                path = Path(argv[argv.index("--logins") + 1])
                selected_login_files.append(path.read_text(encoding="utf-8"))
                return 0

            result = direct_run_main(
                [
                    "-q", "-u", "http://127.0.0.1:8080", "-p", "password123",
                    "--with-nmap", "--slow", "-y", "--artifacts", directory,
                ],
                discover_runner=discover,
                login_runner=find_logins,
                runner=check,
            )

        self.assertEqual(result, 0)
        self.assertEqual(stage_order, ["discover", "logins", "check"])
        self.assertIn("--standard-paths", discovery_calls[0])
        self.assertNotIn("--no-auto-headless", discovery_calls[0])
        self.assertIn("--include-subdomains", discovery_calls[0])
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--tools") + 1],
            "katana,nmap,subfinder",
        )
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--top-ports") + 1],
            "100",
        )
        self.assertEqual(
            discovery_calls[0][discovery_calls[0].index("--subfinder-max-results") + 1],
            "50",
        )
        self.assertIn("--slow", discovery_calls[0])
        for flag in (
            "--katana-rate-limit", "--katana-parallelism",
            "--katana-concurrency", "--paths-concurrency",
            "--subfinder-rate-limit",
        ):
            self.assertNotIn(flag, discovery_calls[0])
        engines = [
            login_calls[0][index + 1]
            for index, value in enumerate(login_calls[0])
            if value == "--search-engine"
        ]
        self.assertEqual(engines, ["yandex", "google"])
        self.assertIn("--slow", login_calls[0])
        self.assertNotIn("--collect-only", login_calls[0])
        collection_log = Path(
            login_calls[0][login_calls[0].index("--auto-log") + 1]
        )
        self.assertEqual(collection_log.name, "collection.log")
        self.assertEqual(collection_log.parent.parent, Path(directory).resolve())
        self.assertEqual(
            login_calls[0][login_calls[0].index("--kind") + 1],
            "login",
        )
        self.assertEqual(login_calls[0].count("--person-pattern"), 3)
        self.assertIn("--people-output", login_calls[0])
        self.assertIn("--emails-output", login_calls[0])
        self.assertNotIn("--generate-logins", login_calls[0])
        self.assertEqual(selected_login_files, ["student@example.test\n"])
        self.assertIn("--auto-browser", check_calls[0])
        self.assertNotIn("--report", check_calls[0])
        self.assertEqual(
            check_calls[0][check_calls[0].index("--url") + 1],
            "http://127.0.0.1:8080/login",
        )
        self.assertIn("--slow", check_calls[0])
        self.assertIn("--auto-login-candidates", check_calls[0])
        self.assertEqual(
            float(check_calls[0][check_calls[0].index("--rate") + 1]),
            1.0 / 15.0,
        )
        self.assertEqual(check_calls[0][check_calls[0].index("--threads") + 1], "1")

    def test_quick_auto_browser_accepts_403_issue_as_fallback_target(self) -> None:
        with TemporaryDirectory() as directory:
            checks: list[list[str]] = []

            def find_logins(argv: list[str]) -> int:
                output = Path(argv[argv.index("--emails-output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("student@example.test\n", encoding="utf-8")
                return 0

            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.write_text(json.dumps({
                    "findings": [],
                    "issues": [{
                        "stage": "standard_paths",
                        "target": "https://example.test/login",
                        "message": "HTTP 403 while probing login page",
                    }],
                }), encoding="utf-8")
                return 3

            result = direct_run_main(
                [
                    "-q", "-u", "https://example.test",
                    "--password", "secret", "-y", "--artifacts", directory,
                ],
                login_runner=find_logins,
                discover_runner=discover,
                runner=lambda argv: checks.append(argv) or 0,
                run_id="quick-403",
            )

            self.assertEqual(result, 0)
            self.assertEqual(len(checks), 1)
            self.assertIn("--auto-browser", checks[0])
            self.assertEqual(
                checks[0][checks[0].index("--url") + 1],
                "https://example.test/login",
            )

    def test_generate_logins_merges_found_and_generated_candidates(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []
            check_calls: list[list[str]] = []
            certificate = Path(directory) / "proxy-ca.pem"
            certificate.write_text("test certificate", encoding="utf-8")

            def find_logins(argv: list[str]) -> int:
                calls.append(argv)
                found = Path(argv[argv.index("--emails-output") + 1])
                generated = Path(argv[argv.index("--output") + 1])
                people = Path(argv[argv.index("--people-output") + 1])
                found.parent.mkdir(parents=True, exist_ok=True)
                found.write_text("petr@example.test\n", encoding="utf-8")
                generated.write_text("p.ivanov\npetr.ivanov\n", encoding="utf-8")
                people.write_text("Пётр Иванов\n", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "--target", "https://example.test/login",
                    "--find-logins", "--generate-logins",
                    "--password", "secret", "-y", "--artifacts", directory,
                    "--proxy", "http://127.0.0.1:9090",
                    "--ca-cert", str(certificate),
                ],
                login_runner=find_logins,
                runner=lambda argv: check_calls.append(argv) or 0,
                run_id="generated-run",
            )

            self.assertEqual(result, 0)
            self.assertNotIn("--collect-only", calls[0])
            self.assertEqual(calls[0][calls[0].index("--proxy") + 1], "http://127.0.0.1:9090")
            self.assertEqual(calls[0][calls[0].index("--ca-cert") + 1], str(certificate.resolve()))
            self.assertEqual(calls[0][calls[0].index("--kind") + 1], "login")
            self.assertEqual(calls[0].count("--person-pattern"), 3)
            candidates = Path(check_calls[0][check_calls[0].index("--logins") + 1])
            self.assertEqual(
                candidates.read_text(encoding="utf-8").splitlines(),
                ["petr@example.test", "p.ivanov", "petr.ivanov"],
            )

    def test_find_logins_prompts_for_inferred_patterns_in_interactive_run(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def find_logins(argv: list[str]) -> int:
                calls.append(argv)
                found = Path(argv[argv.index("--found-emails-output") + 1])
                generated = Path(argv[argv.index("--output") + 1])
                found.parent.mkdir(parents=True, exist_ok=True)
                found.write_text("petr@example.test\n", encoding="utf-8")
                generated.write_text("p.ivanov\n", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "--target", "https://example.test/login",
                    "--find-logins", "--password", "secret",
                    "--artifacts", directory,
                ],
                stdin=TtyInput("\n"),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                login_runner=find_logins,
                runner=lambda argv: 0,
                run_id="interactive-patterns",
            )

        self.assertEqual(result, 0)
        self.assertIn("--prompt-inferred-patterns", calls[0])

    def test_yes_keeps_inferred_pattern_selection_noninteractive(self) -> None:
        with TemporaryDirectory() as directory:
            calls: list[list[str]] = []

            def find_logins(argv: list[str]) -> int:
                calls.append(argv)
                found = Path(argv[argv.index("--found-emails-output") + 1])
                generated = Path(argv[argv.index("--output") + 1])
                found.parent.mkdir(parents=True, exist_ok=True)
                found.write_text("petr@example.test\n", encoding="utf-8")
                generated.write_text("p.ivanov\n", encoding="utf-8")
                return 0

            result = direct_run_main(
                [
                    "--target", "https://example.test/login",
                    "--find-logins", "--password", "secret", "-y",
                    "--artifacts", directory,
                ],
                stdin=TtyInput(""),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
                login_runner=find_logins,
                runner=lambda argv: 0,
                run_id="automatic-patterns",
            )

        self.assertEqual(result, 0)
        self.assertNotIn("--prompt-inferred-patterns", calls[0])

    def test_find_logins_routes_candidates_by_detected_form_field(self) -> None:
        with TemporaryDirectory() as directory:
            for identifier_kind, expected in (
                ("email", ["petr@example.test"]),
                ("username", ["p.ivanov", "petr.ivanov"]),
                ("unknown", ["petr@example.test", "p.ivanov", "petr.ivanov"]),
            ):
                with self.subTest(identifier_kind=identifier_kind):
                    checked: list[list[str]] = []

                    def find_logins(argv: list[str]) -> int:
                        found = Path(argv[argv.index("--found-emails-output") + 1])
                        generated = Path(argv[argv.index("--output") + 1])
                        found.parent.mkdir(parents=True, exist_ok=True)
                        found.write_text("petr@example.test\n", encoding="utf-8")
                        generated.write_text(
                            "p.ivanov\npetr.ivanov\n",
                            encoding="utf-8",
                        )
                        return 0

                    def discover(argv: list[str]) -> int:
                        output = Path(argv[argv.index("--output") + 1])
                        output.write_text(json.dumps({
                            "findings": [{
                                "endpoint": "https://example.test/login",
                                "auth_type": "password_form",
                                "metadata": {"identifier_kind": identifier_kind},
                            }],
                        }), encoding="utf-8")
                        return 0

                    result = direct_run_main(
                        [
                            "-u", "https://example.test", "--find-logins",
                            "--password", "secret", "-y",
                            "--artifacts", directory,
                        ],
                        login_runner=find_logins,
                        discover_runner=discover,
                        runner=lambda argv: checked.append(argv) or 0,
                        run_id=f"route-{identifier_kind}",
                    )

                    self.assertEqual(result, 0)
                    self.assertEqual(len(checked), 1)
                    candidates = Path(
                        checked[0][checked[0].index("--logins") + 1]
                    )
                    self.assertEqual(
                        candidates.read_text(encoding="utf-8").splitlines(),
                        expected,
                    )
                    self.assertIn("--auto-login-candidates", checked[0])

    def test_quick_discover_only_runs_search_without_passwords(self) -> None:
        with TemporaryDirectory() as directory:
            login_calls: list[list[str]] = []
            stdin = TtyInput("q\n")

            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                        "metadata": {"identifier_kind": "username"},
                    }]}),
                    encoding="utf-8",
                )
                return 0

            def find_logins(argv: list[str]) -> int:
                login_calls.append(argv)
                output = Path(argv[argv.index("--found-emails-output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("admin@example.test\n", encoding="utf-8")
                return 0

            result = direct_run_main(
                ["-q", "-u", "https://example.test", "--discover-only", "--artifacts", directory],
                discover_runner=discover,
                login_runner=find_logins,
                runner=lambda argv: self.fail("module 4 must not run"),
                stdin=stdin,
            )

        self.assertEqual(result, 0)
        self.assertEqual(len(login_calls), 1)
        self.assertNotIn("--prompt-inferred-patterns", login_calls[0])
        self.assertEqual(stdin.tell(), 0)

    def test_run_plan_shows_effective_user_agent(self) -> None:
        with TemporaryDirectory() as directory:
            diagnostics = io.StringIO()

            def discover(argv: list[str]) -> int:
                output = Path(argv[argv.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [{
                        "endpoint": "https://example.test/login",
                        "auth_type": "password_form",
                    }]}),
                    encoding="utf-8",
                )
                return 0

            result = direct_run_main(
                [
                    "-u", "https://example.test", "--discover-only", "-y",
                    "--user-agent", "Mozilla/5.0 Diploma Test", "-v",
                    "--artifacts", directory,
                ],
                discover_runner=discover,
                stderr=diagnostics,
            )

        self.assertEqual(result, 0)
        self.assertIn("User-Agent:            Mozilla/5.0 Diploma Test", diagnostics.getvalue())


if __name__ == "__main__":
    import unittest

    unittest.main()
