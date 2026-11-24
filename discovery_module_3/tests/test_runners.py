from __future__ import annotations

import json
import unittest
import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

from authpoints.config import DEFAULT_USER_AGENT, KatanaConfig, NmapConfig, SubfinderConfig
from authpoints.runners.katana import (
    build_katana_command,
    KatanaPartialError,
    katana_environment,
    katana_field_scope_pattern,
    katana_scope_patterns,
    resolve_bundled_chromium,
    resolve_headless_chromium,
    _katana_error_detail,
    _run_katana_once,
    run_katana,
)
from authpoints.runners.common import (
    ToolError,
    _local_executable_candidates,
    resolve_executable,
)
from authpoints.runners.nmap import (
    build_nmap_command,
    nmap_environment,
    partition_targets,
    resolve_nmap_version_db,
)
from authpoints.runners.subfinder import (
    build_subfinder_command,
    parse_subfinder_output,
)


class RunnerCommandTests(unittest.TestCase):
    @patch("authpoints.runners.subfinder.resolve_executable", return_value="subfinder")
    def test_subfinder_command_is_passive_bounded_and_proxied(
        self, _executable_mock: object
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / "domains.txt"
            command = build_subfinder_command(
                SubfinderConfig(
                    rate_limit_per_second=2,
                    proxy="http://127.0.0.1:9090",
                    all_sources=True,
                ),
                ["example.test"],
                input_file=input_file,
            )

            self.assertEqual(input_file.read_text(encoding="utf-8"), "example.test\n")
        self.assertIn("-silent", command)
        self.assertIn("-duc", command)
        self.assertIn("-all", command)
        self.assertEqual(command[command.index("-rl") + 1], "2")
        self.assertEqual(
            command[command.index("-proxy") + 1], "http://127.0.0.1:9090"
        )

    def test_subfinder_output_is_scoped_deduplicated_and_limited(self) -> None:
        output = "a.example.test\nOUTSIDE.test\na.example.test\nb.example.test\n"

        self.assertEqual(
            parse_subfinder_output(
                output,
                domains=["example.test"],
                max_results=1,
            ),
            ["a.example.test"],
        )

    @patch("authpoints.runners.common.shutil.which")
    @patch("authpoints.runners.common._local_executable_candidates")
    def test_local_tool_folder_is_used_before_path(
        self, candidates_mock: object, which_mock: object
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "nmap" / "nmap"
            executable.parent.mkdir()
            executable.write_bytes(b"test")
            executable.chmod(0o755)
            candidates_mock.return_value = [executable]  # type: ignore[attr-defined]
            self.assertEqual(resolve_executable("nmap"), str(executable.resolve()))
        which_mock.assert_not_called()  # type: ignore[attr-defined]

    @unittest.skipIf(os.name == "nt", "POSIX executable selection")
    def test_posix_ignores_bundled_windows_executable(self) -> None:
        candidates = _local_executable_candidates("nmap")
        self.assertTrue(candidates)
        self.assertTrue(all(candidate.name == "nmap" for candidate in candidates))

    @patch("authpoints.runners.nmap.resolve_executable", return_value="nmap")
    @patch(
        "authpoints.runners.nmap.resolve_nmap_version_db",
        return_value=Path("nmap-service-probes"),
    )
    def test_nmap_command_has_no_scripts_or_shell_fragments(
        self, _version_db_mock: object, _executable_mock: object
    ) -> None:
        command = build_nmap_command(NmapConfig(), ["192.0.2.10"])
        self.assertIn("-sV", command)
        self.assertIn("--versiondb", command)
        self.assertIn("-oX", command)
        self.assertNotIn("--script", command)
        self.assertEqual(command[-1], "192.0.2.10")

    @patch("authpoints.runners.nmap.resolve_executable", return_value="nmap")
    @patch(
        "authpoints.runners.nmap.resolve_nmap_version_db",
        return_value=Path("nmap-service-probes"),
    )
    def test_nmap_all_ports_uses_native_p_dash_flag(
        self, _version_db_mock: object, _executable_mock: object
    ) -> None:
        command = build_nmap_command(
            NmapConfig(all_ports=True),
            ["192.0.2.10"],
        )
        self.assertIn("-p-", command)
        self.assertNotIn("--top-ports", command)

    @patch("authpoints.runners.nmap.resolve_executable", return_value="nmap")
    @patch(
        "authpoints.runners.nmap.resolve_nmap_version_db",
        return_value=Path("nmap-service-probes"),
    )
    def test_nmap_ipv6_command_and_target_partition(
        self, _version_db_mock: object, _executable_mock: object
    ) -> None:
        ipv4, ipv6 = partition_targets(
            ["192.0.2.10", "example.test", "2001:db8::1", "2001:db8:1::/120"]
        )
        self.assertEqual(ipv4, ["192.0.2.10", "example.test"])
        self.assertEqual(ipv6, ["2001:db8::1", "2001:db8:1::/120"])
        command = build_nmap_command(NmapConfig(), ipv6, ipv6=True)
        self.assertEqual(command[1], "-6")
        self.assertEqual(command[-2:], ipv6)

    @patch("authpoints.runners.nmap.resolve_executable", return_value="nmap")
    @patch(
        "authpoints.runners.nmap.resolve_nmap_version_db",
        return_value=Path("nmap-service-probes"),
    )
    def test_nmap_udp_and_timing_are_explicit_fixed_arguments(
        self, _version_db_mock: object, _executable_mock: object
    ) -> None:
        command = build_nmap_command(
            NmapConfig(timing_template=4),
            ["192.0.2.10"],
            udp=True,
        )
        self.assertEqual(command[1], "-sU")
        self.assertIn("-T4", command)
        self.assertNotIn("--script", command)

    @patch("authpoints.runners.nmap.resolve_executable", return_value="nmap")
    @patch(
        "authpoints.runners.nmap.resolve_nmap_version_db",
        return_value=Path("nmap-service-probes"),
    )
    def test_nmap_command_rejects_target_file_injection_and_octet_ranges(
        self, _version_db_mock: object, _executable_mock: object
    ) -> None:
        for target in (
            "example.test\noutside.test",
            "192.168.0-255.1-254",
            "0-255.0-255.0-255.0-255",
        ):
            with self.assertRaises(ValueError, msg=target):
                build_nmap_command(NmapConfig(), [target])

    def test_nmap_environment_ignores_ambient_probe_configuration(self) -> None:
        injected = {
            "NMAPDIR": "unsafe-data",
            "NMAP_PRIVILEGED": "1",
            "HOME": "unsafe-home",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, injected, clear=False):
                environment = nmap_environment(root)
            self.assertNotIn("NMAPDIR", environment)
            self.assertNotIn("NMAP_PRIVILEGED", environment)
            self.assertEqual(environment["HOME"], str(root / "home"))

    def test_nmap_version_database_must_be_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            probes = Path(directory) / "nmap-service-probes"
            probes.write_text("Exclude T:9100\n", encoding="utf-8")
            resolved = resolve_nmap_version_db(
                NmapConfig(version_db=str(probes)),
                executable="nmap",
            )
            self.assertEqual(resolved, probes.resolve())

            with self.assertRaisesRegex(ToolError, "not found"):
                resolve_nmap_version_db(
                    NmapConfig(version_db=str(probes) + ".missing"),
                    executable="nmap",
                )

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_command_keeps_safe_crawl_defaults(self, _: object) -> None:
        command = build_katana_command(
            KatanaConfig(),
            input_file=Path("seeds.txt"),
            output_file=Path("results.jsonl"),
            include_subdomains=False,
            scope_hosts={"example.test"},
        )
        self.assertIn("-fx", command)
        self.assertIn("-mdp", command)
        self.assertIn("-cos", command)
        self.assertIn("-dr", command)
        self.assertIn("-cs", command)
        self.assertEqual(command[command.index("-d") + 1], "1")
        self.assertEqual(command[command.index("-mdp") + 1], "1")
        self.assertEqual(command[command.index("-p") + 1], "1")
        self.assertEqual(
            command[command.index("-H") + 1],
            f"User-Agent: {DEFAULT_USER_AGENT}",
        )
        field_scope = command[command.index("-fs") + 1]
        self.assertIsNotNone(re.fullmatch(field_scope, "example.test"))
        self.assertIsNone(re.fullmatch(field_scope, "other.test"))
        self.assertTrue(any(value.endswith("[^/?#]*@") for value in command))
        scope_values = [
            command[index + 1]
            for index, value in enumerate(command[:-1])
            if value == "-cs"
        ]
        self.assertTrue(scope_values)
        self.assertTrue(all("," not in value for value in scope_values))
        for prohibited in ("-aff", "-headless", "-ns", "-no-scope", "-kb"):
            self.assertNotIn(prohibited, command)

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_rejects_user_agent_header_injection(self, _: object) -> None:
        with self.assertRaisesRegex(ValueError, "control characters"):
            build_katana_command(
                KatanaConfig(user_agent="safe\r\nCookie: secret"),
                input_file=Path("seeds.txt"),
                output_file=Path("results.jsonl"),
                include_subdomains=False,
                scope_hosts={"example.test"},
            )

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_command_uses_explicit_proxy(self, _: object) -> None:
        command = build_katana_command(
            KatanaConfig(proxy="127.0.0.1:8080"),
            input_file=Path("seeds.txt"),
            output_file=Path("results.jsonl"),
            include_subdomains=False,
            scope_hosts={"example.test"},
        )
        self.assertEqual(command[command.index("-proxy") + 1], "http://127.0.0.1:8080")
        self.assertNotIn("-ho", command)

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_headless_passes_proxy_to_chromium(self, _: object) -> None:
        command = build_katana_command(
            KatanaConfig(headless=True, proxy="127.0.0.1:8080"),
            input_file=Path("seeds.txt"),
            output_file=Path("results.jsonl"),
            include_subdomains=False,
            scope_hosts={"example.test"},
        )
        self.assertEqual(command[command.index("-proxy") + 1], "http://127.0.0.1:8080")
        self.assertEqual(
            command[command.index("-ho") + 1],
            "proxy-server=http://127.0.0.1:8080",
        )
        self.assertIn("ignore-certificate-errors", command)

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_headless_command_uses_chrome_and_xhr(self, _: object) -> None:
        with patch(
            "authpoints.runners.katana.resolve_headless_chromium",
            return_value=None,
        ):
            command = build_katana_command(
                KatanaConfig(
                    headless=True,
                    depth=3,
                    parallelism=2,
                    max_domain_pages=25,
                ),
                input_file=Path("seeds.txt"),
                output_file=Path("results.jsonl"),
                include_subdomains=False,
                scope_hosts={"example.test"},
                seeds=[
                    "https://example.test/login",
                    "https://example.test/signin",
                ],
            )
        for expected in ("-hl", "-sc", "-xhr", "-fx"):
            self.assertIn(expected, command)
        for prohibited in ("-hh", "-aff", "-al", "-dr", "-H"):
            self.assertNotIn(prohibited, command)
        self.assertEqual(command[command.index("-d") + 1], "3")
        self.assertEqual(command[command.index("-p") + 1], "2")
        self.assertEqual(command[command.index("-mdp") + 1], "25")
        self.assertNotIn("-list", command)
        self.assertEqual(command.count("-u"), 2)
        self.assertEqual(
            command[command.index("-pls") + 1],
            "domcontentloaded",
        )
        self.assertEqual(command[command.index("-dwt") + 1], "5")
        self.assertEqual(
            command[command.index("-cdd") + 1],
            str(Path("chrome-data")),
        )
        self.assertEqual(command[command.index("-ho") + 1], "no-proxy-server")

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_headless_page_load_strategy_is_configurable(self, _: object) -> None:
        command = build_katana_command(
            KatanaConfig(
                headless=True,
                page_load_strategy="networkidle",
                dom_wait_seconds=12,
            ),
            input_file=Path("seeds.txt"),
            output_file=Path("results.jsonl"),
            include_subdomains=False,
            scope_hosts={"example.test"},
        )
        self.assertEqual(command[command.index("-pls") + 1], "networkidle")
        self.assertNotIn("-dwt", command)

    def test_katana_headless_uses_chromium_next_to_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            katana = Path(directory) / "katana.exe"
            chrome = Path(directory) / "chromium" / "chrome.exe"
            katana.write_bytes(b"katana")
            chrome.parent.mkdir()
            chrome.write_bytes(b"chromium")

            with patch(
                "authpoints.runners.katana.resolve_executable",
                return_value=str(katana),
            ), patch(
                "authpoints.runners.katana.resolve_system_chromium",
                return_value=None,
            ):
                command = build_katana_command(
                    KatanaConfig(headless=True),
                    input_file=Path("seeds.txt"),
                    output_file=Path("results.jsonl"),
                    include_subdomains=False,
                    scope_hosts={"example.test"},
                )

            self.assertEqual(resolve_bundled_chromium(str(katana)), chrome.resolve())
            self.assertEqual(command[command.index("-scp") + 1], str(chrome.resolve()))
            self.assertNotIn("-sc", command)

    def test_katana_headless_prefers_system_chrome(self) -> None:
        system_chrome = Path("system-chrome.exe")
        with patch(
            "authpoints.runners.katana.resolve_system_chromium",
            return_value=system_chrome,
        ):
            self.assertEqual(
                resolve_headless_chromium(KatanaConfig(headless=True), "katana"),
                system_chrome,
            )

    def test_katana_headless_uses_explicit_chrome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            chrome = Path(directory) / "chrome.exe"
            chrome.write_bytes(b"chrome")
            resolved = resolve_headless_chromium(
                KatanaConfig(headless=True, chrome_executable=str(chrome)),
                "katana",
            )
            self.assertEqual(resolved, chrome.resolve())

    def test_katana_headless_rejects_missing_explicit_chrome(self) -> None:
        with self.assertRaisesRegex(ToolError, "Chrome executable not found"):
            resolve_headless_chromium(
                KatanaConfig(
                    headless=True,
                    chrome_executable="missing-chrome.exe",
                ),
                "katana",
            )

    @patch("authpoints.runners.katana._run_katana_headless")
    def test_headless_mode_uses_one_browser_run_for_all_seeds(
        self, headless_mock: object
    ) -> None:
        headless_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"GET","endpoint":"https://one.example.test/"},'
            '"response":{"status_code":200}}\n'
        )
        progress: list[str] = []
        output = run_katana(
            KatanaConfig(headless=True),
            ["https://one.example.test/", "https://two.example.test/"],
            include_subdomains=False,
            scope_hosts={"one.example.test", "two.example.test"},
            on_progress=progress.append,
        )
        self.assertIn("one.example.test", output)
        headless_mock.assert_called_once()  # type: ignore[attr-defined]
        self.assertEqual(
            headless_mock.call_args.args[1],  # type: ignore[attr-defined]
            ["https://one.example.test/", "https://two.example.test/"],
        )
        self.assertTrue(any("Headless Chrome" in message for message in progress))

    def test_katana_environment_cannot_enable_auto_login(self) -> None:
        injected = {
            "AUTH_CREDENTIALS": "user:password",
            "CAPTCHA_SOLVER_KEY": "secret-key",
            "HTTPS_PROXY": "http://user:password@proxy.test:8080",
            "SAFE_AUTHPOINTS_TEST": "preserved",
        }
        with patch.dict(os.environ, injected, clear=False):
            environment = katana_environment()
        self.assertNotIn("AUTH_CREDENTIALS", environment)
        self.assertNotIn("CAPTCHA_SOLVER_KEY", environment)
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertEqual(environment["SAFE_AUTHPOINTS_TEST"], "preserved")

    def test_katana_environment_isolates_user_configuration(self) -> None:
        injected = {
            "HOME": "unsafe-home",
            "USERPROFILE": "unsafe-profile",
            "KATANA_CONFIG": "unsafe-config.yaml",
            "ftp_proxy": "http://proxy.test",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, injected, clear=False):
                environment = katana_environment(root)
            self.assertEqual(environment["HOME"], str(root / "home"))
            self.assertEqual(environment["USERPROFILE"], str(root / "home"))
            self.assertNotIn("KATANA_CONFIG", environment)
            self.assertNotIn("ftp_proxy", environment)
            self.assertTrue((root / "xdg-config").is_dir())

    def test_subdomain_scope_does_not_allow_sibling_domains(self) -> None:
        pattern = katana_scope_patterns(
            {"app.example.test"}, include_subdomains=True
        )[0]
        field_pattern = katana_field_scope_pattern(
            {"app.example.test"}, include_subdomains=True
        )

        self.assertIsNotNone(re.match(pattern, "https://child.app.example.test/login"))
        self.assertIsNone(re.match(pattern, "https://admin.example.test/login"))
        self.assertIsNotNone(re.fullmatch(field_pattern, "child.app.example.test"))
        self.assertIsNone(re.fullmatch(field_pattern, "admin.example.test"))

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    def test_katana_command_keeps_distinct_query_urls(self, _: object) -> None:
        command = build_katana_command(
            KatanaConfig(),
            input_file=Path("seeds.txt"),
            output_file=Path("results.jsonl"),
            scope_hosts={"e.test"},
            include_subdomains=False,
        )
        self.assertNotIn("-iqp", command)
        filters = [command[index + 1] for index, value in enumerate(command[:-1]) if value == "-cos"]
        self.assertFalse(any("token" in pattern.lower() for pattern in filters))

    def test_katana_error_keeps_query_token(self) -> None:
        detail = _katana_error_detail(
            "[ERR] failed https://example.test/login?access_token=local-secret"
        )
        self.assertIn("access_token=local-secret", detail)

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    @patch("authpoints.runners.katana.subprocess.run")
    def test_katana_exit_zero_without_output_is_an_error(
        self, run_mock: object, _: object
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(  # type: ignore[attr-defined]
            args=["katana"],
            returncode=0,
            stderr=b"[ERR] could not create runner: invalid option",
        )
        with self.assertRaises(ToolError):
            _run_katana_once(
                KatanaConfig(),
                "https://example.test/",
                include_subdomains=False,
                scope_hosts={"example.test"},
                timeout_seconds=10,
            )

    @patch("authpoints.runners.katana.resolve_executable", return_value="katana")
    @patch("authpoints.runners.katana.subprocess.run")
    def test_katana_orchestration_accepts_filtered_empty_page(
        self, run_mock: object, _: object
    ) -> None:
        def create_empty_output(command: list[str], **_kwargs: object) -> object:
            output_file = Path(command[command.index("-o") + 1])
            output_file.touch()
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stderr=b"",
            )

        run_mock.side_effect = create_empty_output  # type: ignore[attr-defined]
        output = _run_katana_once(
            KatanaConfig(),
            "https://example.test/robots.txt",
            include_subdomains=False,
            scope_hosts={"example.test"},
            timeout_seconds=10,
            allow_empty_output=True,
        )
        self.assertEqual(output, "")

    @patch("authpoints.runners.katana.build_katana_command")
    @patch("authpoints.runners.katana.subprocess.run")
    def test_katana_execution_failures_keep_complete_records_in_both_modes(
        self, run_mock: object, command_mock: object
    ) -> None:
        seeds = ["https://one.example.test/", "https://two.example.test/"]
        command_mock.side_effect = (  # type: ignore[attr-defined]
            lambda _config, *, output_file, **_kwargs: ["katana", "-o", str(output_file)]
        )
        for headless in (False, True):
            for failure in ("nonzero", "runtime", "timeout"):
                with self.subTest(headless=headless, failure=failure):
                    written: list[str] = []

                    def fail_after_output(command: list[str], **_kwargs: object) -> object:
                        seed = seeds[0] if headless else seeds[len(written)]
                        record = json.dumps(
                            {
                                "request": {"method": "GET", "endpoint": seed},
                                "response": {"status_code": 200},
                            }
                        ) + "\n"
                        written.append(record)
                        output_file = Path(command[command.index("-o") + 1])
                        output_file.write_text(record + '{"request":{"endpoint":', encoding="utf-8")
                        if failure == "timeout":
                            raise subprocess.TimeoutExpired(command, timeout=10)
                        return subprocess.CompletedProcess(
                            args=command,
                            returncode=1 if failure == "nonzero" else 0,
                            stderr=b"[ERR] crawl failed" if failure == "runtime" else b"",
                        )

                    run_mock.side_effect = fail_after_output  # type: ignore[attr-defined]
                    with self.assertRaises(KatanaPartialError) as raised:
                        run_katana(
                            KatanaConfig(
                                headless=headless,
                                depth=1,
                                parallelism=1,
                                rate_limit_per_second=1000,
                            ),
                            seeds,
                            include_subdomains=True,
                            scope_hosts={"example.test"},
                        )

                    self.assertEqual(raised.exception.output, "".join(written))
                    self.assertEqual({issue.target for issue in raised.exception.issues}, set(seeds))
                    self.assertTrue(all("omitted 1" in issue.message for issue in raised.exception.issues))
                    self.assertNotIn('{"request":{"endpoint":', raised.exception.output)

    @patch("authpoints.runners.katana.build_katana_command")
    @patch("authpoints.runners.katana.subprocess.run")
    def test_katana_execution_recovery_is_bounded_and_reports_truncation(
        self, run_mock: object, command_mock: object
    ) -> None:
        record = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {"status_code": 200},
            }
        ) + "\n"
        command_mock.side_effect = (  # type: ignore[attr-defined]
            lambda _config, *, output_file, **_kwargs: ["katana", "-o", str(output_file)]
        )

        def output_too_large(command: list[str], **_kwargs: object) -> object:
            output_file = Path(command[command.index("-o") + 1])
            output_file.write_text(record + record, encoding="utf-8")
            return subprocess.CompletedProcess(args=command, returncode=0, stderr=b"")

        run_mock.side_effect = output_too_large  # type: ignore[attr-defined]
        budget = len(record.encode("utf-8")) + 5
        with patch("authpoints.runners.katana.MAX_KATANA_OUTPUT_BYTES", budget):
            with self.assertRaises(KatanaPartialError) as raised:
                run_katana(
                    KatanaConfig(headless=True),
                    ["https://example.test/"],
                    include_subdomains=False,
                    scope_hosts={"example.test"},
                )

        self.assertEqual(raised.exception.output, record)
        self.assertLessEqual(len(raised.exception.output.encode("utf-8")), budget)
        self.assertIn("safety limit", raised.exception.issues[0].message)
        self.assertIn("recovery limited", raised.exception.issues[0].message)

    @patch("authpoints.runners.katana.build_katana_command")
    @patch("authpoints.runners.katana.subprocess.run")
    def test_katana_execution_with_only_truncated_record_does_not_invent_output(
        self, run_mock: object, command_mock: object
    ) -> None:
        command_mock.side_effect = (  # type: ignore[attr-defined]
            lambda _config, *, output_file, **_kwargs: ["katana", "-o", str(output_file)]
        )

        def incomplete_output(command: list[str], **_kwargs: object) -> object:
            output_file = Path(command[command.index("-o") + 1])
            output_file.write_text('{"request":{"endpoint":', encoding="utf-8")
            return subprocess.CompletedProcess(args=command, returncode=1, stderr=b"")

        run_mock.side_effect = incomplete_output  # type: ignore[attr-defined]
        with self.assertRaises(ToolError) as raised:
            _run_katana_once(
                KatanaConfig(),
                "https://example.test/",
                include_subdomains=False,
                scope_hosts={"example.test"},
                timeout_seconds=10,
            )

        self.assertNotIsInstance(raised.exception, KatanaPartialError)
        self.assertIn("exited with code 1", str(raised.exception))

    def test_katana_rejects_comma_seed_before_spawn(self) -> None:
        with self.assertRaises(ToolError):
            run_katana(
                KatanaConfig(),
                ["https://example.test/,https://outside.test/"],
                include_subdomains=False,
                scope_hosts={"example.test"},
            )
    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_depth_one_fetches_only_starting_page(
        self,
        run_once_mock: object,
    ) -> None:
        run_once_mock.return_value = json.dumps(  # type: ignore[attr-defined]
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": '<html><a href="/second">second</a></html>',
                },
            }
        )
        progress: list[str] = []

        run_katana(
            KatanaConfig(depth=1),
            ["https://example.test/"],
            include_subdomains=False,
            scope_hosts={"example.test"},
            on_progress=progress.append,
        )

        self.assertEqual(run_once_mock.call_count, 1)  # type: ignore[attr-defined]
        self.assertEqual(run_once_mock.call_args.args[1], "https://example.test/")  # type: ignore[attr-defined]
        self.assertIn("[KATANA] Уровень 1/1: 1 страниц", progress)
        self.assertTrue(any(message.startswith("[KATANA] GET ") for message in progress))
        self.assertIn("[KATANA] HTTP 200 https://example.test/", progress)
        self.assertTrue(progress[-1].startswith("[KATANA] Обход завершён"))

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_total_page_limit_applies_across_subdomains(
        self,
        run_once_mock: object,
    ) -> None:
        first_page = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        '<a href="https://one.example.test/login">one</a>'
                        '<a href="https://two.example.test/login">two</a>'
                    ),
                },
            }
        )

        def crawl_page(
            _config: KatanaConfig,
            seed: str,
            **_kwargs: object,
        ) -> str:
            if seed == "https://example.test/":
                return first_page
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {"status_code": 200},
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        progress: list[str] = []

        run_katana(
            KatanaConfig(depth=3, max_total_pages=2),
            ["https://example.test/"],
            include_subdomains=True,
            scope_hosts={"example.test"},
            on_progress=progress.append,
        )

        called_seeds = [
            call.args[1]
            for call in run_once_mock.call_args_list  # type: ignore[attr-defined]
        ]
        self.assertEqual(
            called_seeds,
            ["https://example.test/", "https://one.example.test/login"],
        )
        self.assertIn("[KATANA] Достигнут общий лимит: 2 страниц", progress)
        self.assertEqual(
            progress[-1],
            "[KATANA] Обход завершён: обработано 2 страниц",
        )

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_small_budget_prefers_login_and_navigation_over_resources(
        self, run_once_mock: object
    ) -> None:
        root = "https://example.test/"
        body = (
            '<link rel="search" href="/opensearch.xml">'
            '<link rel="manifest" href="/manifest.json">'
            '<a href="/logo.svg">Logo</a>'
            '<a href="/about">About</a>'
            '<a href="/login">Log in</a>'
            '<a href="/contact">Contact</a>'
        )

        def crawl_page(_config: KatanaConfig, seed: str, **_kwargs: object) -> str:
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": body if seed == root else "ok",
                    },
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        for budget, paths in (
            (3, ["/", "/login", "/about"]),
            (7, ["/", "/login", "/about", "/contact", "/opensearch.xml", "/manifest.json", "/logo.svg"]),
        ):
            with self.subTest(budget=budget):
                run_once_mock.reset_mock()  # type: ignore[attr-defined]
                run_katana(
                    KatanaConfig(
                        depth=2, max_total_pages=budget,
                        parallelism=1, rate_limit_per_second=1000,
                    ),
                    [root],
                    include_subdomains=False,
                    scope_hosts={"example.test"},
                )

                self.assertEqual(
                    [call.args[1] for call in run_once_mock.call_args_list],  # type: ignore[attr-defined]
                    ["https://example.test" + path for path in paths],
                )

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_redirects_take_priority_over_authentication_links(
        self, run_once_mock: object
    ) -> None:
        root = "https://example.test/"
        first_page = "\n".join(
            (
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": root},
                        "response": {
                            "status_code": 200,
                            "headers": {"content-type": "text/html"},
                            "body": '<a href="/login">Login</a><a href="/destination">Next</a>',
                        },
                    }
                ),
                json.dumps(
                    {
                        "request": {"method": "GET", "endpoint": root},
                        "response": {
                            "status_code": 302,
                            "headers": {"location": "/destination"},
                        },
                    }
                ),
            )
        )

        def crawl_page(_config: KatanaConfig, seed: str, **_kwargs: object) -> str:
            if seed == root:
                return first_page
            return json.dumps({"request": {"method": "GET", "endpoint": seed}})

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        run_katana(
            KatanaConfig(depth=2, max_total_pages=2, rate_limit_per_second=1000),
            [root],
            include_subdomains=False,
            scope_hosts={"example.test"},
        )

        self.assertEqual(
            [call.args[1] for call in run_once_mock.call_args_list],  # type: ignore[attr-defined]
            [root, "https://example.test/destination"],
        )

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_auth_json_and_xml_routes_remain_high_priority(
        self, run_once_mock: object
    ) -> None:
        root = "https://example.test/"
        body = (
            '<a href="/manifest.json">Manifest</a>'
            '<a href="/about">About</a>'
            '<a href="/api/auth/login.json">API login</a>'
            '<a href="/account/session.xml">Session</a>'
            '<a href="/sitemap.xml">Sitemap</a>'
        )

        def crawl_page(_config: KatanaConfig, seed: str, **_kwargs: object) -> str:
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": body if seed == root else "ok",
                    },
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        run_katana(
            KatanaConfig(depth=2, max_total_pages=3, rate_limit_per_second=1000),
            [root],
            include_subdomains=False,
            scope_hosts={"example.test"},
        )

        self.assertEqual(
            [call.args[1] for call in run_once_mock.call_args_list],  # type: ignore[attr-defined]
            [root, "https://example.test/api/auth/login.json", "https://example.test/account/session.xml"],
        )

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_keeps_explicit_resource_seeds_in_user_order(
        self, run_once_mock: object
    ) -> None:
        seeds = [
            "https://example.test/manifest.json",
            "https://example.test/about",
            "https://example.test/api/auth/login.json",
            "https://example.test/account/session.xml",
        ]
        run_once_mock.return_value = ""  # type: ignore[attr-defined]

        run_katana(
            KatanaConfig(depth=1, max_total_pages=4, rate_limit_per_second=1000),
            seeds,
            include_subdomains=False,
            scope_hosts={"example.test"},
        )

        self.assertEqual(
            [call.args[1] for call in run_once_mock.call_args_list],  # type: ignore[attr-defined]
            seeds,
        )

    @patch("authpoints.runners.katana._run_katana_once")
    def test_python_orchestration_schedules_only_safe_get_records(
        self,
        run_once_mock: object,
    ) -> None:
        body = """<html><body>
        <a href="/login?state=opaque">login</a>
        <a href="/logout">logout</a>
        <a href="/login?api_key=secret">credential query</a>
        <a href="https://outside.test/login">outside</a>
        <a href="/a,b">comma</a>
        </body></html>"""
        first_page = "\n".join(
            [
                json.dumps(
                    {
                        "request": {
                            "method": "GET",
                            "endpoint": "https://example.test/",
                        },
                        "response": {
                            "status_code": 200,
                            "headers": {"content-type": "text/html"},
                            "body": body,
                        },
                    }
                ),
                '{"request":{"method":"POST","endpoint":"https://example.test/mutate"}}',
            ]
        )
        def crawl_page(
            _config: KatanaConfig,
            seed: str,
            **_kwargs: object,
        ) -> str:
            if seed == "https://example.test/":
                return first_page
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {"status_code": 200},
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]

        output = run_katana(
            KatanaConfig(depth=2),
            ["https://example.test/"],
            include_subdomains=False,
            scope_hosts={"example.test"},
        )

        called_seeds = [
            call.args[1]
            for call in run_once_mock.call_args_list  # type: ignore[attr-defined]
        ]
        self.assertEqual(
            called_seeds,
            [
                "https://example.test/",
                "https://example.test/login?state=opaque",
                "https://example.test/login?api_key=secret",
            ],
        )
        self.assertIn("api_key=secret", output)

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_parallelism_controls_isolated_page_workers(
        self,
        run_once_mock: object,
    ) -> None:
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        active = 0
        maximum_active = 0

        def crawl_page(
            _config: KatanaConfig,
            seed: str,
            **_kwargs: object,
        ) -> str:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                barrier.wait(timeout=2)
                return (
                    '{"request":{"method":"GET","endpoint":"'
                    + seed
                    + '"},"response":{"status_code":200}}\n'
                )
            finally:
                with lock:
                    active -= 1

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        output = run_katana(
            KatanaConfig(
                depth=1,
                parallelism=2,
                rate_limit_per_second=1000,
            ),
            ["https://one.example.test/", "https://two.example.test/"],
            include_subdomains=False,
            scope_hosts={"one.example.test", "two.example.test"},
        )
        self.assertEqual(maximum_active, 2)
        self.assertIn("one.example.test", output)
        self.assertIn("two.example.test", output)

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_preserves_successes_and_continues_levels_after_seed_failure(
        self, run_once_mock: object
    ) -> None:
        root = "https://example.test/"
        failed = "https://offline.example.test/"
        nested = "https://example.test/login"

        def crawl_page(_config: KatanaConfig, seed: str, **_kwargs: object) -> str:
            if seed == failed:
                raise ToolError("connection refused")
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": '<a href="/login">Log in</a>' if seed == root else "ok",
                    },
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        with self.assertRaises(KatanaPartialError) as raised:
            run_katana(
                KatanaConfig(depth=2, rate_limit_per_second=1000),
                [failed, root],
                include_subdomains=True,
                scope_hosts={"example.test"},
            )

        error = raised.exception
        self.assertEqual([issue.target for issue in error.issues], [failed])
        self.assertIn(root, error.output)
        self.assertIn(nested, error.output)
        self.assertEqual(run_once_mock.call_count, 3)  # type: ignore[attr-defined]

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_later_level_failure_preserves_earlier_output(
        self, run_once_mock: object
    ) -> None:
        first_page = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": '<a href="/second">next</a>',
                },
            }
        )
        run_once_mock.side_effect = [first_page, ToolError("page timed out")]  # type: ignore[attr-defined]

        with self.assertRaises(KatanaPartialError) as raised:
            run_katana(
                KatanaConfig(depth=2),
                ["https://example.test/"],
                include_subdomains=False,
                scope_hosts={"example.test"},
            )

        self.assertEqual(raised.exception.output, first_page + "\n")
        self.assertEqual(raised.exception.issues[0].target, "https://example.test/second")

    @patch("authpoints.runners.katana._run_katana_once", side_effect=ToolError("unreachable"))
    def test_katana_all_failed_seeds_remain_an_error_with_each_target(
        self, _run_once_mock: object
    ) -> None:
        seeds = ["https://one.example.test/", "https://two.example.test/"]
        with self.assertRaises(KatanaPartialError) as raised:
            run_katana(
                KatanaConfig(depth=1, rate_limit_per_second=1000),
                seeds,
                include_subdomains=True,
                scope_hosts={"example.test"},
            )

        self.assertEqual(raised.exception.output, "")
        self.assertEqual({issue.target for issue in raised.exception.issues}, set(seeds))
        self.assertTrue(all(issue.message == "unreachable" for issue in raised.exception.issues))

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_deadline_on_later_level_keeps_earlier_output(
        self, run_once_mock: object
    ) -> None:
        clock = [0.0]
        first_page = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": '<a href="/second">next</a>',
                },
            }
        )

        def crawl_page(_config: KatanaConfig, _seed: str, **_kwargs: object) -> str:
            clock[0] = 11.0
            return first_page

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        with patch("authpoints.runners.katana.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(KatanaPartialError) as raised:
                run_katana(
                    KatanaConfig(depth=2, timeout_seconds=10),
                    ["https://example.test/"],
                    include_subdomains=False,
                    scope_hosts={"example.test"},
                )

        self.assertEqual(raised.exception.output, first_page + "\n")
        self.assertEqual(raised.exception.issues[0].target, "https://example.test/second")
        self.assertIn("page was not started", raised.exception.issues[0].message)
        self.assertEqual(run_once_mock.call_count, 1)  # type: ignore[attr-defined]

    @patch("authpoints.runners.katana._run_katana_once")
    def test_katana_output_budget_on_later_level_keeps_earlier_output(
        self, run_once_mock: object
    ) -> None:
        first_page = json.dumps(
            {
                "request": {"method": "GET", "endpoint": "https://example.test/"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": '<a href="/second">next</a>',
                },
            }
        )
        run_once_mock.side_effect = [first_page, first_page]  # type: ignore[attr-defined]
        with patch("authpoints.runners.katana.MAX_KATANA_OUTPUT_BYTES", len(first_page) + 1):
            with self.assertRaises(KatanaPartialError) as raised:
                run_katana(
                    KatanaConfig(depth=2),
                    ["https://example.test/"],
                    include_subdomains=False,
                    scope_hosts={"example.test"},
                )

        self.assertEqual(raised.exception.output, first_page + "\n")
        self.assertEqual(raised.exception.issues[0].target, "https://example.test/second")
        self.assertIn("safety limit", raised.exception.issues[0].message)

if __name__ == "__main__":
    unittest.main()
