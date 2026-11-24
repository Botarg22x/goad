from __future__ import annotations

import argparse
import csv
import io
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from zipfile import ZipFile

import logingen.cli as cli_module
from logingen.cli import (
    DomainInference,
    _config_cli_conflicts,
    _effective_configured_domains,
    _parse_collection_sources,
    apply_auto_artifact_paths,
    apply_overrides,
    build_parser,
    cli_default_config,
    choose_candidate_formats,
    choose_email_domains,
    choose_generation_masks,
    choose_inferred_patterns,
    choose_inferred_patterns_compact,
)
from logingen.config import config_from_dict
from logingen.collector import CollectionResult, EmailSourceRecord, PersonSourceRecord
from logingen.models import Person
from logingen.inference import PatternInference


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class CliOverrideTests(unittest.TestCase):
    def test_interactive_generation_selects_email_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            prompts = io.StringIO()

            def collected(config, *, pattern_selector=None, **_kwargs):
                selected = pattern_selector((
                    PatternInference("{f}.{lastname}", 1, ("i.ivanov@example.test",)),
                ))
                updated = cli_module.replace(
                    config,
                    people=(Person(firstname="Иван", lastname="Иванов"),),
                    patterns=cli_module.replace(config.patterns, person=selected),
                    domains=("example.test",),
                )
                return updated, CollectionResult(), selected

            with mock.patch.object(cli_module, "run_auto_collection", side_effect=collected), \
                 mock.patch("sys.stdin", TtyInput("1\n2\n")), \
                 mock.patch("sys.stderr", prompts), \
                 mock.patch("sys.stdout", io.StringIO()):
                code = cli_module.main([
                    "--url", "https://example.test/", "--domain", "example.test",
                    "--output", str(output), "--kind", "login",
                    "--no-domain-prompt", "--prompt-inferred-patterns",
                    "--no-technical-words", "--no-default-people",
                    "--auto-log", "none", "--evidence-output", "none",
                ])

            self.assertEqual(code, 0)
            self.assertIn("[ШАБЛОНЫ]", prompts.getvalue())
            self.assertIn("[ФОРМАТ] Что сохранить", prompts.getvalue())
            self.assertIn("Выберите номера или введите свой шаблон результата", prompts.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8").splitlines(), ["i.ivanov@example.test"])

    def test_cli_interrupt_returns_130_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with mock.patch.object(cli_module, "run_auto_collection", side_effect=KeyboardInterrupt), \
                 mock.patch("sys.stderr", errors):
                code = cli_module.main([
                    "--collect-only", "--setka", "--company", "demo",
                    "--domain", "demo.ru", "--people-output", str(Path(directory) / "fio.txt"),
                ])
            self.assertEqual(code, 130)
            self.assertIn("[ОСТАНОВЛЕНО]", errors.getvalue())
            self.assertNotIn("Traceback", errors.getvalue())

    def test_setka_checkpoint_survives_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = cli_module.cli_default_config()
            config = cli_module.replace(
                config,
                mode="auto", company="demo", domains=("demo.ru",),
                auto=cli_module.replace(
                    config.auto, enabled=True, url="", setka_enabled=True,
                    search_enabled=False, fio_path=root / "fio.txt",
                    found_emails_path=root / "found-emails.txt",
                    email_sources_path=root / "email_sources.csv",
                    evidence_path=root / "evidence.jsonl", log_path=root / "collection.log",
                ),
            )
            person = Person(firstname="Иван", lastname="Иванов")

            def interrupt_after_first_page(_company, _auto, *, log=None, on_progress=None):
                on_progress(CollectionResult(
                    people=(person,),
                    person_sources=(PersonSourceRecord(person, "setka", "https://setka.ru/networks/one/members"),),
                ))
                raise KeyboardInterrupt

            with mock.patch.object(cli_module, "collect_setka_people", side_effect=interrupt_after_first_page):
                with self.assertRaises(KeyboardInterrupt):
                    cli_module.run_auto_collection(config)

            self.assertEqual((root / "fio.txt").read_text(encoding="utf-8"), "Иванов Иван\n")
            self.assertTrue((root / "evidence.jsonl").is_file())
            self.assertTrue((root / "evidence.xlsx").is_file())

    def test_search_checkpoint_survives_keyboard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = cli_module.cli_default_config()
            config = cli_module.replace(
                config,
                mode="auto", company="demo", domains=("demo.ru",),
                auto=cli_module.replace(
                    config.auto, enabled=True, url="", setka_enabled=False,
                    search_enabled=True, fio_path=root / "fio.txt",
                    found_emails_path=root / "found-emails.txt",
                    email_sources_path=root / "email_sources.csv",
                    evidence_path=root / "evidence.jsonl", log_path=root / "collection.log",
                ),
            )

            def interrupt_after_first_result(_auto, _domains, *, company="", log=None, on_progress=None):
                on_progress(CollectionResult(
                    emails=("info@demo.ru",),
                    email_sources=(EmailSourceRecord("info@demo.ru", "search", query_url="https://yandex.ru/search/"),),
                ))
                raise KeyboardInterrupt

            with mock.patch.object(cli_module, "collect_search_source", side_effect=interrupt_after_first_result):
                with self.assertRaises(KeyboardInterrupt):
                    cli_module.run_auto_collection(config)

            self.assertEqual((root / "found-emails.txt").read_text(encoding="utf-8"), "info@demo.ru\n")
            self.assertIn("info@demo.ru", (root / "email_sources.csv").read_text(encoding="utf-8"))
            self.assertTrue((root / "evidence.xlsx").is_file())

    def test_collection_sources_accept_commas_and_repeated_flags(self) -> None:
        self.assertEqual(
            _parse_collection_sources(["site, search", "search"], ("site", "search"), "--email-source"),
            ["site", "search"],
        )
        self.assertEqual(
            _parse_collection_sources(["site,setka", "vedomosti"],
                                      ("site", "search", "setka", "vedomosti"), "--people-source"),
            ["site", "setka", "vedomosti"],
        )
        with self.assertRaisesRegex(ValueError, "неизвестное значение"):
            _parse_collection_sources(["site,serach"], ("site", "search"), "--email-source")

    def test_evidence_records_saved_sources_and_does_not_claim_missing_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / "people.html"
            page.write_text("Иван Иванов ivan@example.test", encoding="utf-8")
            person = Person(firstname="Иван", lastname="Иванов")
            result = CollectionResult(
                people=(person,), emails=("ivan@example.test", "other@example.test"),
                person_sources=(PersonSourceRecord(person, "site", "https://example.test/team", str(page)),),
                email_sources=(EmailSourceRecord("ivan@example.test", "site", found_url="https://example.test/team", source_path=str(page)),),
            )
            destination = root / "evidence.jsonl"
            cli_module._write_evidence(destination, result)
            rows = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["source_url"], "https://example.test/team")
            self.assertEqual(rows[0]["sha256"], hashlib.sha256(page.read_bytes()).hexdigest())
            self.assertEqual(rows[0]["proof_status"], "saved")
            self.assertEqual(rows[2]["proof_status"], "not_saved")
            with (root / "fio_sources.csv").open(encoding="utf-8-sig", newline="") as source:
                fio_rows = list(csv.DictReader(source))
            self.assertEqual(fio_rows[0]["ФИО"], "Иванов Иван")
            self.assertEqual(fio_rows[0]["Ссылка на источник"], "https://example.test/team")
            with ZipFile(root / "evidence.xlsx") as workbook:
                self.assertIsNone(workbook.testzip())
                self.assertIn("ФИО".encode(), workbook.read("xl/workbook.xml"))
                self.assertIn(b"E-mail", workbook.read("xl/workbook.xml"))
                self.assertIn("Иванов Иван".encode(), workbook.read("xl/worksheets/sheet1.xml"))
                self.assertIn(b"https://example.test/team", workbook.read("xl/worksheets/_rels/sheet1.xml.rels"))
                self.assertIn(b"file://", workbook.read("xl/worksheets/_rels/sheet1.xml.rels"))

    def test_auto_logger_keeps_details_in_file_and_prints_concise_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "collection.log"
            console = io.StringIO()
            logger = cli_module.AutoLogger(log_path)

            with mock.patch.object(cli_module.sys, "stderr", console):
                logger(
                    "yandex fetch 2/10: "
                    "https://yandex.ru/search/?text=%22ivanov%40example.test%22"
                )
                logger("search saved html: /tmp/query.html status=200")

            terminal = console.getvalue()
            details = log_path.read_text(encoding="utf-8")

        self.assertIn("[ПОИСК] Yandex: запрос 2/10", terminal)
        self.assertNotIn("https://yandex.ru", terminal)
        self.assertNotIn("search saved html", terminal)
        self.assertIn("https://yandex.ru", details)
        self.assertIn("search saved html", details)

    def test_setka_progress_and_disabled_site_are_distinct_from_yandex_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            console = io.StringIO()
            logger = cli_module.AutoLogger(Path(directory) / "collection.log")
            with mock.patch.object(cli_module.sys, "stderr", console):
                logger("site crawl skipped: site is not selected as a collection source")
                logger("setka search results parsed: company_pages=1")
                logger("setka company groups page: url=https://setka.ru/companies/test/networks")
                logger("setka networks parsed: url=https://setka.ru/companies/test/networks networks=51")
                logger("setka members parsed: index=1/51 url=https://setka.ru/networks/1/members people=25")
                logger("setka members parsed: index=2/51 url=https://setka.ru/networks/2/members people=25")
                logger("setka members parsed: index=5/51 url=https://setka.ru/networks/5/members people=25")
            terminal = console.getvalue()

        self.assertIn("[САЙТ] Обход отключён: сбор с сайта не выбран", terminal)
        self.assertNotIn("адрес сайта не задан", terminal)
        self.assertIn("[SETKA] Поиск завершён; найдено страниц компаний: 1", terminal)
        self.assertIn(
            "[SETKA] Страница со всеми группами: "
            "https://setka.ru/companies/test/networks",
            terminal,
        )
        self.assertIn("[SETKA] Найдено разделов: 51", terminal)
        self.assertIn("[SETKA] Раздел 1/51", terminal)
        self.assertIn("[SETKA] Раздел 5/51", terminal)
        self.assertNotIn("[SETKA] Раздел 2/51", terminal)

    def test_collection_sources_keep_search_emails_and_setka_people_separate(self) -> None:
        config = cli_module.cli_default_config()
        config = cli_module.replace(
            config,
            mode="auto",
            company="example",
            domains=("example.ru",),
            auto=cli_module.replace(
                config.auto,
                enabled=True,
                url="https://example.ru",
                search_enabled=True,
                search_fetch_enabled=True,
                setka_enabled=True,
                mail_from_url_path=None,
                fio_path=None,
                email_sources_path=None,
                log_path=None,
            ),
        )
        search_person = cli_module.Person(firstname="Поиск", lastname="Результатов")
        setka_person = cli_module.Person(firstname="Иван", lastname="Иванов")

        with mock.patch.object(
            cli_module,
            "collect_public_data",
            side_effect=AssertionError("site source must be skipped"),
        ), mock.patch.object(
            cli_module,
            "collect_search_source",
            return_value=SimpleNamespace(
                collection=CollectionResult(
                    emails=("mail@example.ru",),
                    people=(search_person,),
                    domains=("example.ru",),
                )
            ),
        ), mock.patch.object(
            cli_module,
            "collect_setka_people",
            return_value=CollectionResult(people=(setka_person,)),
        ):
            _config, collection, _patterns = cli_module.run_auto_collection(
                config,
                pattern_selector=lambda _candidates: (),
                domain_selector=lambda _candidates: (),
                email_sources=("search",),
                people_sources=("setka",),
            )

        self.assertEqual(collection.emails, ("mail@example.ru",))
        self.assertEqual(collection.people, (setka_person,))

    def test_collect_only_writes_information_and_skips_generation(self) -> None:
        original_collect_public_data = cli_module.collect_public_data
        original_generate = cli_module.generate
        cli_module.collect_public_data = lambda auto, log=None, on_progress=None: CollectionResult(
            emails=("info@example.ru", "support@example.ru"),
            people=(cli_module.Person(firstname="Иван", lastname="Иванов"),),
            domains=("example.ru",),
            visited_urls=("https://example.ru/",),
        )
        cli_module.generate = lambda _config: self.fail("generator must not run in --collect-only mode")
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                emails_path = root / "emails.txt"
                people_path = root / "fio.txt"
                output = io.StringIO()
                previous = Path.cwd()
                try:
                    os.chdir(root)
                    with mock.patch("sys.stdout", output):
                        exit_code = cli_module.main(
                            [
                                "--collect-only",
                                "--url",
                                "https://example.ru/",
                                "--domain",
                                "example.ru",
                                "--emails-output",
                                str(emails_path),
                                "--people-output",
                                str(people_path),
                                "--no-domain-prompt",
                            ]
                        )
                finally:
                    os.chdir(previous)

                self.assertEqual(exit_code, 0)
                self.assertEqual(emails_path.read_text(encoding="utf-8"), "info@example.ru\nsupport@example.ru\n")
                self.assertEqual(people_path.read_text(encoding="utf-8"), "Иванов Иван\n")
                self.assertFalse((root / "output/example.ru/logins.txt").exists())
                self.assertIn(
                    "[РЕЗУЛЬТАТ] Генерация логинов: пропущена (включить: -g)",
                    output.getvalue(),
                )
        finally:
            cli_module.collect_public_data = original_collect_public_data
            cli_module.generate = original_generate

    def test_generation_can_also_write_combined_collected_emails(self) -> None:
        collection = CollectionResult(
            emails=("i.ivanov@example.ru", "support@example.ru"),
            people=(cli_module.Person(firstname="Иван", lastname="Иванов"),),
            domains=("example.ru",),
            visited_urls=("https://example.ru/",),
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            cli_module, "collect_public_data", return_value=collection
        ):
            root = Path(directory)
            emails = root / "emails.txt"
            people = root / "fio.txt"
            generated = root / "generated.txt"
            exit_code = cli_module.main([
                "--url", "https://example.ru/", "--domain", "example.ru",
                "--emails-output", str(emails), "--people-output", str(people),
                "--output", str(generated), "--kind", "login",
                "--person-pattern", "{f}.{lastname}",
                "--no-pattern-prompt", "--no-domain-prompt",
                "--no-default-people", "--no-technical-words",
            ])

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                emails.read_text(encoding="utf-8"),
                "i.ivanov@example.ru\nsupport@example.ru\n",
            )
            self.assertEqual(people.read_text(encoding="utf-8"), "Иванов Иван\n")
            self.assertIn("i.ivanov", generated.read_text(encoding="utf-8").splitlines())

    def test_config_is_explicit_not_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])

        self.assertIsNone(args.config)

    def test_config_mode_rejects_cli_setting_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--config", "configs/example.yaml", "--company", "dns", "--setka"])

        self.assertEqual(_config_cli_conflicts(args), ("--company/--name", "--setka"))

    def test_config_mode_allows_runtime_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--config", "configs/example.yaml", "--dry-run", "--sample", "5", "--verbose"])

        self.assertEqual(_config_cli_conflicts(args), ())

    def test_config_mode_rejects_technical_words_cli_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--config", "configs/example.yaml", "--technical-words"])

        self.assertEqual(_config_cli_conflicts(args), ("--technical-words/--include-technical-words",))

    def test_cli_defaults_disable_technical_words(self) -> None:
        config = cli_default_config()

        self.assertFalse(config.generation.include_technical_words)

    def test_cli_defaults_do_not_depend_on_current_directory(self) -> None:
        previous = Path.cwd()
        try:
            with tempfile.TemporaryDirectory() as directory:
                os.chdir(directory)
                config = cli_default_config()
        finally:
            os.chdir(previous)

        self.assertFalse(config.generation.include_technical_words)
        self.assertEqual(config.generation.masks, ())
        self.assertEqual(config.generation.candidate_format_templates, ())

    def test_cli_can_enable_technical_words(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--technical-words"])
        config = apply_overrides(cli_default_config(), args)

        self.assertTrue(config.generation.include_technical_words)

    def test_domen_alias_overrides_domain(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--domen", "company.com"])
        config = apply_overrides(config_from_dict({}), args)

        self.assertEqual(config.domains, ("company.com",))

    def test_search_engine_flag_enables_search_fetching(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--domain", "company.com", "-s", "yandex,google"])
        config = apply_overrides(config_from_dict({}), args)

        self.assertTrue(config.auto.search_enabled)
        self.assertTrue(config.auto.search_fetch_enabled)
        self.assertEqual(config.auto.search_engines, ("yandex", "google"))
        self.assertEqual(config.auto.search_delay_seconds, 10.0)

    def test_search_delay_is_separate_from_general_collection_delay(self) -> None:
        args = build_parser().parse_args([
            "--domain", "company.com", "-s", "yandex,google",
            "--request-delay", "2", "--search-delay", "12",
        ])
        config = apply_overrides(cli_default_config(), args)

        self.assertEqual(config.auto.request_delay_seconds, 2.0)
        self.assertEqual(config.auto.search_delay_seconds, 12.0)

    def test_slow_profile_sets_at_least_fifteen_second_request_delay(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["--url", "https://company.com/", "--slow", "--request-delay", "2"]
        )

        config = apply_overrides(config_from_dict({}), args)

        self.assertEqual(config.auto.request_delay_seconds, 15.0)
        self.assertFalse(config.auto.browser_crawl)

    def test_slow_profile_can_explicitly_enable_browser_crawl(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["--url", "https://company.com/", "--slow", "--browser-crawl"]
        )

        config = apply_overrides(config_from_dict({}), args)

        self.assertEqual(config.auto.request_delay_seconds, 15.0)
        self.assertTrue(config.auto.browser_crawl)

    def test_custom_request_delay_can_be_slower_than_profile(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["--url", "https://company.com/", "--slow", "--request-delay", "30"]
        )

        config = apply_overrides(config_from_dict({}), args)

        self.assertEqual(config.auto.request_delay_seconds, 30.0)

    def test_setka_page_limit_is_applied_from_cli(self) -> None:
        args = build_parser().parse_args(["--setka", "--setka-max-pages", "2"])
        config = apply_overrides(cli_default_config(), args)

        self.assertTrue(config.auto.setka_enabled)
        self.assertEqual(config.auto.setka_max_pages, 2)

    def test_setka_page_limit_requires_source_and_positive_value(self) -> None:
        for args in (["--setka-max-pages", "0"], ["--setka-max-pages", "2"]):
            with self.subTest(args=args), mock.patch("sys.stderr", io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as raised:
                    cli_module.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("--setka-max-pages", errors.getvalue())

    def test_request_delay_is_a_config_exclusive_setting(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["--config", "configs/example.yaml", "--slow", "--request-delay", "20"]
        )

        self.assertEqual(
            _config_cli_conflicts(args),
            ("--slow", "--request-delay"),
        )

    def test_proxy_and_user_agent_override_auto_transport(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "proxy-ca.pem"
            certificate.write_text("test certificate", encoding="utf-8")
            parser = build_parser()
            args = parser.parse_args(
                [
                    "--proxy", "http://127.0.0.1:9090",
                    "--ca-cert", str(certificate),
                    "--user-agent", "Audit Browser",
                ]
            )
            config = apply_overrides(cli_default_config(), args)

            self.assertEqual(config.auto.proxy_url, "http://127.0.0.1:9090")
            self.assertEqual(config.auto.ca_cert, certificate.resolve())
            self.assertEqual(config.auto.user_agent, "Audit Browser")

    def test_ca_certificate_must_exist(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--ca-cert", "/missing/proxy-ca.pem"])

        with self.assertRaisesRegex(ValueError, "--ca-cert file not found"):
            apply_overrides(cli_default_config(), args)

    def test_setka_flag_enables_auto_source(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--company", "dns", "--setka"])
        config = apply_overrides(config_from_dict({}), args)

        self.assertEqual(config.mode, "auto")
        self.assertTrue(config.auto.enabled)
        self.assertTrue(config.auto.setka_enabled)
        self.assertFalse(config.auto.search_enabled)

    def test_example_domain_is_ignored_when_url_domain_is_real(self) -> None:
        self.assertEqual(_effective_configured_domains(("example.ru",), "auchan.ru"), ())
        self.assertEqual(_effective_configured_domains(("company.com",), "auchan.ru"), ("company.com",))

    def test_browser_crawl_flags_override_config(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "--url",
                "https://company.com/",
                "--browser-crawl",
                "--headed-browser",
                "--browser-timeout",
                "30",
                "--browser-wait",
                "250",
                "--browser-pages-dir",
                "tmp/pages",
                "--browser-channel",
                "chrome",
                "--browser-user-data-dir",
                "tmp/profile",
                "--no-browser-manual-access",
            ]
        )
        config = apply_overrides(config_from_dict({}), args)

        self.assertTrue(config.auto.browser_crawl)
        self.assertFalse(config.auto.browser_headless)
        self.assertEqual(config.auto.browser_timeout_seconds, 30)
        self.assertEqual(config.auto.browser_wait_ms, 250)
        self.assertEqual(config.auto.browser_pages_dir, Path("tmp/pages"))
        self.assertEqual(config.auto.browser_channel, "chrome")
        self.assertEqual(config.auto.browser_user_data_dir, Path("tmp/profile"))
        self.assertFalse(config.auto.browser_manual_access)

    def test_selects_inferred_pattern_from_prompt_input(self) -> None:
        selected = choose_inferred_patterns(
            (
                PatternInference("{lastname}_{f}{p}", 2, ("morozova_uv", "dzhafarov_sy")),
                PatternInference("{lastname}_{f}_{p}", 1, ("selivanova_m_v",)),
            ),
            input_stream=TtyInput("2\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(selected, ("{lastname}_{f}_{p}",))

    def test_compact_pattern_prompt_offers_inferred_and_base_patterns(self) -> None:
        output = io.StringIO()

        selected = choose_inferred_patterns_compact(
            (PatternInference("{lastname}-{f}", 2, ("ivanov-p",)),),
            fallback_patterns=("{f}.{lastname}", "{firstname}.{lastname}"),
            input_stream=TtyInput("2\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("{f}.{lastname}",))
        self.assertIn("[ШАБЛОНЫ]", output.getvalue())
        self.assertIn("1. {lastname}-{f}", output.getvalue())
        self.assertIn("2. {f}.{lastname} — базовый вариант", output.getvalue())
        self.assertNotIn("Шаблон логина:\n", output.getvalue())

    def test_compact_pattern_prompt_enter_uses_inferred_pattern(self) -> None:
        selected = choose_inferred_patterns_compact(
            (PatternInference("{lastname}-{f}", 2, ("ivanov-p",)),),
            fallback_patterns=("{f}.{lastname}",),
            input_stream=TtyInput("\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(selected, ("{lastname}-{f}",))

    def test_prints_single_inferred_pattern_for_generation(self) -> None:
        output = io.StringIO()

        selected = choose_inferred_patterns(
            (PatternInference("{lastname}_{f}{p}", 2, ("ivanov_pa", "petrov_an")),),
            input_stream=TtyInput(""),
            output_stream=output,
        )

        self.assertEqual(selected, ("{lastname}_{f}{p}",))
        self.assertIn("[ШАБЛОНЫ] Варианты по найденным почтам:", output.getvalue())
        self.assertIn("{lastname}_{f}{p}", output.getvalue())
        self.assertIn("ivanov_pa", output.getvalue())

    def test_accepts_custom_pattern_instead_of_single_inferred_pattern(self) -> None:
        output = io.StringIO()

        selected = choose_inferred_patterns(
            (PatternInference("{lastname}_{f}{p}", 2, ("ivanov_pa", "petrov_an")),),
            input_stream=TtyInput("{lastname}.{f}\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("{lastname}.{f}",))
        self.assertIn("Enter — {lastname}_{f}{p}", output.getvalue())

    def test_accepts_custom_pattern_when_no_pattern_is_inferred(self) -> None:
        output = io.StringIO()

        selected = choose_inferred_patterns(
            (),
            input_stream=TtyInput("{lastname}-{f}\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("{lastname}-{f}",))
        self.assertIn("Номера или шаблоны", output.getvalue())
        self.assertNotIn("Шаблон логина:\n", output.getvalue())
        self.assertIn("{f}.{lastname} → i.ivanov", output.getvalue())

    def test_accepts_custom_pattern_from_multiple_pattern_prompt(self) -> None:
        selected = choose_inferred_patterns(
            (
                PatternInference("{lastname}_{f}{p}", 2, ("morozova_uv", "dzhafarov_sy")),
                PatternInference("{lastname}_{f}_{p}", 1, ("selivanova_m_v",)),
            ),
            input_stream=TtyInput("1,{lastname}.{f}\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(selected, ("{lastname}_{f}{p}", "{lastname}.{f}"))

    def test_pattern_help_and_malformed_input_do_not_end_selection(self) -> None:
        output = io.StringIO()
        selected = choose_inferred_patterns(
            (),
            input_stream=TtyInput("?\n{f}{firstname\n{lastname}.{f}\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("{lastname}.{f}",))
        self.assertIn("Шаблон логина:", output.getvalue())
        self.assertIn("Маски дополнительных символов:", output.getvalue())
        self.assertIn("незакрытая или лишняя фигурная скобка", output.getvalue())
        self.assertNotIn("Pattern blocks", output.getvalue())

    def test_collection_summary_is_available_before_pattern_selection(self) -> None:
        config = cli_module.cli_default_config()
        config = cli_module.replace(
            config,
            auto=cli_module.replace(
                config.auto, enabled=True, url="https://example.test", search_enabled=True,
                mail_from_url_path=None, fio_path=None, email_sources_path=None, log_path=None,
            ),
            domains=("example.test",),
        )
        console = io.StringIO()

        def select(_candidates):
            text = console.getvalue()
            self.assertIn("[СБОР] Найдено ФИО: 1", text)
            self.assertIn("[ПОЧТЫ] Найдено: 2", text)
            self.assertIn("info@example.test", text)
            self.assertIn("i.ivanov@example.test", text)
            self.assertLess(text.index("Найдено ФИО"), text.index("[ПОЧТЫ]"))
            return ("{f}.{lastname}",)

        with mock.patch.object(cli_module.sys, "stderr", console), mock.patch.object(
            cli_module, "collect_public_data",
            return_value=CollectionResult(emails=("info@example.test",)),
        ), mock.patch.object(
            cli_module, "collect_search_source",
            return_value=SimpleNamespace(collection=CollectionResult(
                emails=("i.ivanov@example.test",),
                people=(cli_module.Person(firstname="Иван", lastname="Иванов"),),
            )),
        ):
            cli_module.run_auto_collection(config, pattern_selector=select)

    def test_selects_saved_mask_from_pattern_prompt(self) -> None:
        output = io.StringIO()

        selected = choose_inferred_patterns(
            (PatternInference("{lastname}_{f}_{p}", 5, ("kadyrova_a_a",)),),
            mask_templates=("{lastname}_{f}_{p}?d2026",),
            input_stream=TtyInput("m1\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("{lastname}_{f}_{p}?d2026",))
        self.assertNotIn("Маски дополнительных символов:", output.getvalue())
        self.assertIn("m1. {lastname}_{f}_{p}?d2026", output.getvalue())

    def test_selects_saved_generation_mask_before_generation(self) -> None:
        config = config_from_dict(
            {
                "generation": {
                    "masks_path": "none",
                    "masks": ["{f}.{lastname}?d2026"],
                },
                "patterns": {"person": ["{f}.{lastname}"]},
            }
        )

        updated = choose_generation_masks(
            config,
            input_stream=TtyInput("1\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(updated.patterns.person, ("{f}.{lastname}?d2026",))

    def test_prompts_for_custom_charset_used_by_generation_mask(self) -> None:
        config = config_from_dict(
            {
                "generation": {"masks_path": "none"},
                "patterns": {"person": ["{f}.{lastname}"]},
            }
        )

        updated = choose_generation_masks(
            config,
            input_stream=TtyInput("{f}{lastname}?1?1\nxy\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(updated.patterns.person, ("{f}{lastname}?1?1",))
        self.assertEqual(updated.generation.custom_charsets["1"], "xy")

    def test_prints_generation_patterns_when_mask_prompt_is_non_interactive(self) -> None:
        output = io.StringIO()
        config = config_from_dict(
            {
                "generation": {"masks_path": "none"},
                "patterns": {"person": ["{f}.{lastname}"]},
            }
        )

        updated = choose_generation_masks(
            config,
            input_stream=io.StringIO(""),
            output_stream=output,
        )

        self.assertIs(updated, config)
        self.assertIn("[МАСКИ] Текущие шаблоны:", output.getvalue())
        self.assertIn("{f}.{lastname}", output.getvalue())
        self.assertNotIn("? — справка", output.getvalue())

    def test_selects_candidate_formats_and_prompts_for_ad_values(self) -> None:
        config = config_from_dict(
            {
                "company": "magnit",
                "generation": {
                    "candidate_formats_path": "none",
                    "candidate_formats": [],
                },
            }
        )
        config = cli_module.replace(
            config,
            generation=cli_module.replace(
                config.generation,
                candidate_format_templates=("{login}", "{mail}", "{netbios}\\{login}", "{login}@{ad_domain}"),
            ),
        )

        updated = choose_candidate_formats(
            config,
            input_stream=TtyInput("1,3,4\ncorp.magnit.ru\n\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(updated.generation.candidate_formats, ("{login}", "{netbios}\\{login}", "{login}@{ad_domain}"))
        self.assertEqual(updated.generation.ad_domain, "corp.magnit.ru")
        self.assertEqual(updated.generation.netbios, "MAGNIT")

    def test_prints_candidate_formats_when_prompt_is_non_interactive(self) -> None:
        output = io.StringIO()
        config = config_from_dict(
            {
                "generation": {
                    "candidate_formats_path": "none",
                    "candidate_formats": ["{login}", "{mail}"],
                },
            }
        )

        updated = choose_candidate_formats(
            config,
            input_stream=io.StringIO(""),
            output_stream=output,
        )

        self.assertIs(updated, config)
        self.assertIn("[ФОРМАТ]", output.getvalue())
        self.assertIn("{mail}", output.getvalue())
        self.assertNotIn("? — справка", output.getvalue())

    def test_candidate_formats_offer_login_and_email_with_help_on_request(self) -> None:
        output = io.StringIO()
        config = cli_module.cli_default_config()
        updated = choose_candidate_formats(
            config, input_stream=TtyInput("?\n1,2\n"), output_stream=output,
        )

        self.assertEqual(updated.generation.candidate_formats, ("{login}", "{mail}"))
        self.assertIn("1. логин — {login}", output.getvalue())
        self.assertIn("2. почта — {mail}", output.getvalue())
        self.assertIn("Конечный формат кандидата:", output.getvalue())
        self.assertNotIn("Saved candidate formats", output.getvalue())

    def test_selects_email_domain_from_prompt_input(self) -> None:
        selected = choose_email_domains(
            (
                DomainInference("magnit.ru", 4, ("info@magnit.ru", "ivanov@magnit.ru")),
                DomainInference("b2b.magnit.ru", 1, ("support@b2b.magnit.ru",)),
            ),
            input_stream=TtyInput("1\n"),
            output_stream=io.StringIO(),
        )

        self.assertEqual(selected, ("magnit.ru",))

    def test_prints_all_email_domain_examples(self) -> None:
        output = io.StringIO()
        emails = (
            "pa.ivanov@auchan.ru",
            "se.ivanov@auchan.ru",
            "an.petrov@auchan.ru",
            "hr@auchan.ru",
            "press@auchan.ru",
            "office@auchan.ru",
        )

        selected = choose_email_domains(
            (
                DomainInference("auchan.ru", len(emails), emails),
                DomainInference("mail.ru", 1, ("auchan.ivan@mail.ru",)),
            ),
            input_stream=TtyInput("1\n"),
            output_stream=output,
        )

        self.assertEqual(selected, ("auchan.ru",))
        for email in emails:
            self.assertIn(email, output.getvalue())
        self.assertNotIn("...", output.getvalue())

    def test_auto_collection_uses_selected_site_email_domain_for_generation(self) -> None:
        original_collect_public_data = cli_module.collect_public_data
        cli_module.collect_public_data = lambda auto, log=None, on_progress=None: CollectionResult(
            emails=("info@magnit.ru", "support@b2b.magnit.ru"),
            domains=("magnit.ru", "b2b.magnit.ru"),
        )
        try:
            config = config_from_dict(
                {
                    "mode": "auto",
                    "domains": [],
                    "auto": {
                        "enabled": True,
                        "url": "https://b2b.magnit.ru/",
                        "mail_from_url_path": "none",
                        "fio_path": "none",
                        "email_sources_path": "none",
                        "log_path": "none",
                    },
                }
            )

            updated_config, _collection, _patterns = cli_module.run_auto_collection(
                config,
                pattern_selector=lambda _candidates: (),
                domain_selector=lambda _candidates: ("magnit.ru",),
            )
        finally:
            cli_module.collect_public_data = original_collect_public_data

        self.assertEqual(updated_config.domains, ("magnit.ru",))

    def test_auto_collection_uses_selected_person_patterns_only(self) -> None:
        original_collect_public_data = cli_module.collect_public_data
        cli_module.collect_public_data = lambda auto, log=None, on_progress=None: CollectionResult(
            emails=("i.ivanov@magnit.ru",),
            domains=("magnit.ru",),
        )
        try:
            config = config_from_dict(
                {
                    "mode": "auto",
                    "domains": [],
                    "auto": {
                        "enabled": True,
                        "url": "https://magnit.ru/",
                        "mail_from_url_path": "none",
                        "fio_path": "none",
                        "email_sources_path": "none",
                        "log_path": "none",
                    },
                }
            )

            updated_config, _collection, patterns = cli_module.run_auto_collection(
                config,
                pattern_selector=lambda _candidates: ("{lastname}.{f}",),
                domain_selector=lambda _candidates: ("magnit.ru",),
            )
        finally:
            cli_module.collect_public_data = original_collect_public_data

        self.assertEqual(patterns, ("{lastname}.{f}",))
        self.assertEqual(updated_config.patterns.person, ("{lastname}.{f}",))

    def test_auto_collection_merges_setka_people(self) -> None:
        original_collect_setka_people = cli_module.collect_setka_people
        cli_module.collect_setka_people = lambda company, auto, log=None, on_progress=None: CollectionResult(
            people=(cli_module.Person(firstname="РРІР°РЅ", lastname="РРІР°РЅРѕРІ"),),
        )
        try:
            config = config_from_dict(
                {
                    "company": "dns",
                    "mode": "auto",
                    "domains": [],
                    "auto": {
                        "enabled": True,
                        "setka_enabled": True,
                        "mail_from_url_path": "none",
                        "fio_path": "none",
                        "email_sources_path": "none",
                        "log_path": "none",
                    },
                }
            )

            _updated_config, collection, _patterns = cli_module.run_auto_collection(
                config,
                pattern_selector=lambda _candidates: (),
                domain_selector=lambda _candidates: (),
            )
        finally:
            cli_module.collect_setka_people = original_collect_setka_people

        self.assertEqual(len(collection.people), 1)
        self.assertEqual(collection.people[0].lastname, "РРІР°РЅРѕРІ")

    def test_auto_artifact_paths_are_derived_from_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--url", "https://b2b.magnit.ru/", "-s", "yandex"])
        config = apply_auto_artifact_paths(apply_overrides(config_from_dict({}), args), args)

        self.assertEqual(config.company, "b2b.magnit")
        root = Path("output/b2b.magnit.ru")
        self.assertEqual(config.auto.mail_from_url_path, root / "mail_from_url.txt")
        self.assertEqual(config.auto.fio_path, root / "fio.txt")
        self.assertEqual(config.auto.found_emails_path, root / "mail_from_search.txt")
        self.assertEqual(config.auto.email_sources_path, root / "email_sources.csv")
        self.assertEqual(config.auto.pdf_files_dir, root / "pdf")
        self.assertEqual(config.auto.log_path, root / "log.txt")
        self.assertEqual(config.output.path, root / "logins.txt")

    def test_evidence_output_keeps_email_csv_in_same_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "evidence.jsonl"
            args = build_parser().parse_args([
                "--company", "Микран", "--domain", "micran.ru", "--collect-only",
                "--evidence-output", str(destination),
            ])
            config = apply_auto_artifact_paths(apply_overrides(config_from_dict({}), args), args)

            self.assertEqual(config.auto.email_sources_path, destination.parent / "email_sources.csv")

    def test_auto_artifact_paths_ignore_example_domain_for_named_setka_run(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--company", "эльдорадо", "--setka"])
        config = apply_auto_artifact_paths(apply_overrides(config_from_dict({}), args), args)

        root = Path("output/эльдорадо")
        self.assertEqual(config.auto.log_path, root / "log.txt")
        self.assertEqual(config.output.path, root / "logins.txt")


if __name__ == "__main__":
    unittest.main()
