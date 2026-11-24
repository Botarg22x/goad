from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from authpoints.cli import build_parser, main
from authpoints.config import (
    HttpConfig,
    KatanaConfig,
    NmapConfig,
    ScanConfig,
    SubfinderConfig,
)
from authpoints.models import FormField, FormObservation, Issue, Report, Source, WebObservation
from authpoints.pipeline import analyze_offline, run_active_scan
from authpoints.http_probe import ProbeResult
from authpoints.runners.common import ToolError
from authpoints.runners.katana import KatanaPartialError


FIXTURES = Path(__file__).parent / "fixtures"


class PipelineTests(unittest.TestCase):
    @patch("authpoints.pipeline.run_katana")
    def test_katana_discovers_basic_link_without_paths_or_extra_http_probe(
        self, run_katana_mock: object,
    ) -> None:
        root = "https://example.test/"
        private = "https://example.test/private"
        run_katana_mock.return_value = "\n".join((  # type: ignore[attr-defined]
            json.dumps({
                "request": {"method": "GET", "endpoint": root},
                "response": {"status_code": 200, "headers": {"content-type": "text/html"},
                             "body": '<a href="/private">Private</a>'},
            }),
            json.dumps({
                "request": {"method": "GET", "endpoint": private},
                "response": {"status_code": 401,
                             "headers": {"Www-Authenticate": 'Basic realm="Lab"'}},
            }),
        ))

        with patch("authpoints.pipeline.probe_urls") as probe_mock:
            report = run_active_scan(
                [], [root], ScanConfig(
                    standard_paths=[],
                    nmap=NmapConfig(enabled=False),
                    katana=KatanaConfig(enabled=True, auto_headless=False),
                    http=HttpConfig(enabled=False),
                ),
            )

        probe_mock.assert_not_called()
        self.assertEqual(
            [(item.auth_type, item.endpoint) for item in report.findings],
            [("http_basic", private)],
        )

    @patch("authpoints.pipeline.render_pages")
    @patch("authpoints.pipeline.probe_urls")
    def test_page_only_browser_fallback_attributes_redirected_form(
        self, probe_mock: object, render_mock: object,
    ) -> None:
        start = "https://example.test/"
        final = "https://auth.example.test/sign-in"
        probe_mock.return_value = [ProbeResult(  # type: ignore[attr-defined]
            requested_url=start,
            observation=WebObservation(url=final, source=Source.HTTP_PROBE, status_code=200),
        )]
        render_mock.return_value = json.dumps({  # type: ignore[attr-defined]
            "request": {"method": "GET", "endpoint": final},
            "response": {"status_code": 200, "headers": {"content-type": "text/html"},
                         "body": '<form method="post"><input name="username">'
                                 '<input name="password" type="password"></form>'},
        })

        report = run_active_scan(
            [], [start], ScanConfig(
                include_subdomains=True, page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True),
            ),
        )

        self.assertEqual(report.config["page_only_results"], [{
            "url": start,
            "final_url": final,
            "status": "found",
            "auth_types": ["password_form"],
        }])
        self.assertEqual(render_mock.call_args.args[0], [start])  # type: ignore[attr-defined]

    @patch("authpoints.pipeline.render_pages")
    @patch("authpoints.pipeline.probe_urls")
    def test_page_only_attributes_subdomain_redirect_to_start_page(
        self, probe_mock: object, render_mock: object,
    ) -> None:
        start = "https://example.test/"
        final = "https://auth.example.test/account/login"
        probe_mock.return_value = [ProbeResult(  # type: ignore[attr-defined]
            requested_url=start,
            observation=WebObservation(
                url=final, source=Source.HTTP_PROBE, status_code=200,
                forms=[FormObservation(method="post", fields=[
                    FormField(name="username"),
                    FormField(name="password", field_type="password"),
                ])],
            ),
        )]

        report = run_active_scan(
            [], [start], ScanConfig(
                include_subdomains=True, page_only=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True),
            ),
        )

        self.assertEqual(report.config["page_only_results"], [{
            "url": start,
            "final_url": final,
            "status": "found",
            "auth_types": ["password_form"],
        }])
        render_mock.assert_not_called()  # type: ignore[attr-defined]

    @patch("authpoints.pipeline.run_katana")
    @patch("authpoints.pipeline.render_pages")
    @patch("authpoints.pipeline.probe_urls")
    @patch("authpoints.pipeline.run_subfinder")
    def test_page_only_checks_seed_and_subdomain_root_without_link_crawl(
        self, subfinder_mock: object, probe_mock: object,
        render_mock: object, katana_mock: object,
    ) -> None:
        root = "https://example.test/login"
        sub = "https://app.example.test/"
        subfinder_mock.return_value = ["app.example.test"]  # type: ignore[attr-defined]
        probe_mock.return_value = [  # type: ignore[attr-defined]
            ProbeResult(observation=WebObservation(
                url=root, source=Source.URL_LIST, status_code=200,
                forms=[FormObservation(method="post", fields=[
                    FormField(name="username"),
                    FormField(name="password", field_type="password"),
                ])],
            )),
            ProbeResult(observation=WebObservation(
                url=sub, source=Source.URL_LIST, status_code=200,
                links=["https://app.example.test/next"],
            )),
        ]
        render_mock.return_value = "\n".join((  # type: ignore[attr-defined]
            json.dumps({"request": {"method": "GET", "endpoint": sub},
                        "response": {"status_code": 200, "headers": {"content-type": "text/html"},
                                     "body": '<form method="post"><input name="username"><input name="password" type="password"></form>'}}),
            json.dumps({"request": {"method": "GET", "endpoint": sub + "next"},
                        "response": {"status_code": 200, "headers": {"content-type": "text/html"},
                                     "body": '<form method="post"><input name="username"><input name="password" type="password"></form>'}}),
        ))

        report = run_active_scan(
            [], [root], ScanConfig(
                include_subdomains=True, page_only=True,
                nmap=NmapConfig(enabled=False),
                subfinder=SubfinderConfig(enabled=True),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True),
            ),
        )

        self.assertEqual(probe_mock.call_args.args[0], [root, sub])  # type: ignore[attr-defined]
        self.assertEqual(render_mock.call_args.args[0], [sub])  # type: ignore[attr-defined]
        katana_mock.assert_not_called()  # type: ignore[attr-defined]
        self.assertTrue(any(finding.endpoint == root for finding in report.findings))
        self.assertTrue(any(finding.endpoint == sub for finding in report.findings))
        self.assertFalse(any(finding.endpoint.endswith("/next") for finding in report.findings))
        self.assertEqual(
            [row["status"] for row in report.config["page_only_results"]],
            ["found", "found"],
        )

    @patch("authpoints.pipeline.run_katana")
    def test_ordinary_scan_passes_query_token_url_to_katana(
        self, run_katana_mock: object,
    ) -> None:
        target = "https://example.test/login?access_token=local-secret"
        run_katana_mock.return_value = json.dumps({  # type: ignore[attr-defined]
            "request": {"method": "GET", "endpoint": target},
            "response": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "body": (
                    '<form method="post" action="/session">'
                    '<input name="username"><input type="password" name="password">'
                    '<button>Log in</button></form>'
                ),
            },
        })
        report = run_active_scan(
            [], [target],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True, auto_headless=False),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertIn(target, run_katana_mock.call_args.args[1])  # type: ignore[attr-defined]
        self.assertTrue(report.findings)
        self.assertIn("local-secret", json.dumps(report.to_dict()))

    @patch("authpoints.runners.katana._run_katana_once")
    def test_failed_katana_seed_keeps_sibling_form_and_reports_partial(
        self, run_once_mock: object
    ) -> None:
        good = "https://example.test/login"
        bad = "https://offline.example.test/"

        def crawl_page(_config: KatanaConfig, seed: str, **_kwargs: object) -> str:
            if seed == bad:
                raise ToolError("connection refused")
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": seed},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": (
                            '<form action="/session" method="post">'
                            '<input name="username"><input name="password" type="password">'
                            '<button>Log in</button></form>'
                        ),
                    },
                }
            )

        run_once_mock.side_effect = crawl_page  # type: ignore[attr-defined]
        report = run_active_scan(
            [],
            [good, bad],
            ScanConfig(
                include_subdomains=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(depth=1, rate_limit_per_second=1000),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertTrue(report.partial)
        self.assertEqual(len(report.issues), 1)
        self.assertEqual(report.issues[0].stage, "katana")
        self.assertEqual(report.issues[0].target, bad)
        self.assertIn("connection refused", report.issues[0].message)
        self.assertTrue(any(f.auth_type == "password_form" and f.endpoint == good for f in report.findings))

    @patch("authpoints.runners.katana._run_katana_once", side_effect=ToolError("unreachable"))
    def test_all_failed_katana_seeds_are_reported_individually(
        self, _run_once_mock: object
    ) -> None:
        seeds = ["https://one.example.test/", "https://two.example.test/"]
        report = run_active_scan(
            [],
            seeds,
            ScanConfig(
                include_subdomains=True,
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(depth=1, rate_limit_per_second=1000),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertTrue(report.partial)
        self.assertEqual({issue.target for issue in report.issues}, set(seeds))
        self.assertEqual(report.findings, [])

    @patch("authpoints.pipeline.run_katana")
    def test_auto_headless_partial_output_and_page_issues_are_preserved(
        self, run_katana_mock: object
    ) -> None:
        good = "https://example.test/login"
        partial_page = json.dumps(
            {
                "request": {"method": "GET", "endpoint": good},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        '<form action="/session" method="post">'
                        '<input name="username"><input name="password" type="password">'
                        '<button>Log in</button></form>'
                    ),
                },
            }
        )
        run_katana_mock.side_effect = [  # type: ignore[attr-defined]
            "",
            KatanaPartialError(
                partial_page,
                [Issue(stage="katana", target=good + "/next", message="page timed out")],
            ),
        ]
        report = run_active_scan(
            [],
            [good],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(auto_headless=True),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertTrue(report.partial)
        self.assertTrue(any(f.auth_type == "password_form" for f in report.findings))
        self.assertEqual(report.issues[0].stage, "katana_headless")
        self.assertEqual(report.issues[0].target, good + "/next")

    @patch("authpoints.cli.run_active_scan", side_effect=KeyboardInterrupt)
    def test_cli_keyboard_interrupt_returns_130_without_traceback(
        self, _scan_mock: object
    ) -> None:
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            code = main(["https://example.test", "--tools", "katana"])

        self.assertEqual(code, 130)
        self.assertIn("[ОСТАНОВЛЕНО]", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    @patch("authpoints.pipeline.run_katana", return_value="")
    @patch(
        "authpoints.pipeline.run_subfinder",
        return_value=["admin.example.test", "sso.example.test"],
    )
    def test_subfinder_results_become_katana_seeds(
        self, subfinder_mock: object, katana_mock: object
    ) -> None:
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                include_subdomains=True,
                nmap=NmapConfig(enabled=False),
                subfinder=SubfinderConfig(enabled=True),
                katana=KatanaConfig(enabled=True, auto_headless=False),
                http=HttpConfig(enabled=False),
            ),
        )

        subfinder_mock.assert_called_once()  # type: ignore[attr-defined]
        seeds = katana_mock.call_args.args[1]  # type: ignore[attr-defined]
        self.assertIn("https://admin.example.test/", seeds)
        self.assertIn("https://sso.example.test/", seeds)
        self.assertEqual(
            report.config["subfinder"]["discovered_subdomains"],
            ["admin.example.test", "sso.example.test"],
        )

    def test_active_pipeline_reports_major_stages(self) -> None:
        progress: list[str] = []
        report = run_active_scan(
            ["example.test"],
            [],
            ScanConfig(
                standard_paths=[],
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=False),
            ),
            on_progress=progress.append,
        )

        self.assertFalse(report.partial)
        self.assertTrue(progress[0].startswith("[START]"))
        self.assertIn("[NMAP] Пропущен", progress)
        self.assertTrue(any(message.startswith("[PATHS]") for message in progress))
        self.assertIn("[KATANA] Пропущена", progress)
        self.assertTrue(any(message.startswith("[ANALYZE]") for message in progress))
        self.assertTrue(progress[-1].startswith("[DONE]"))

    def test_report_schema_is_packaged_and_matches_contract(self) -> None:
        schema = json.loads(
            files("authpoints").joinpath("report.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema["properties"]["schema_version"]["const"], "2.0")
        finding_schema = schema["$defs"]["finding"]
        self.assertIn("auth_type", finding_schema["required"])
        self.assertNotIn("score", finding_schema["properties"])
        self.assertNotIn("confidence", finding_schema["properties"])
        self.assertNotIn("weight", schema["$defs"]["evidence"]["properties"])
        self.assertTrue(
            {
                "scope",
                "findings",
                "services",
                "issues",
                "schema_version",
                "config",
            }.issubset(schema["required"])
        )
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(["--schema"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["$id"], schema["$id"])

    def test_offline_pipeline_merges_sources(self) -> None:
        report = analyze_offline(
            targets=["example.test"],
            urls=["https://example.test/login"],
            nmap_documents=[("nmap.xml", (FIXTURES / "nmap.xml").read_bytes())],
            katana_documents=[
                ("katana.jsonl", (FIXTURES / "katana.jsonl").read_text(encoding="utf-8"))
            ],
        )
        login = next(
            item
            for item in report.findings
            if item.endpoint == "https://example.test/login"
        )
        self.assertEqual(set(login.sources), {"katana"})
        self.assertGreaterEqual(len(report.findings), 4)
        self.assertFalse(report.partial)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_writes_json_and_links_reports_and_prints_findings(
        self, run_active_scan_mock: object
    ) -> None:
        report = analyze_offline(
            targets=["example.test"],
            urls=[],
            nmap_documents=[("nmap.xml", (FIXTURES / "nmap.xml").read_bytes())],
            katana_documents=[
                ("katana.jsonl", (FIXTURES / "katana.jsonl").read_text(encoding="utf-8"))
            ],
        )

        def return_report(*_args: object, **kwargs: object) -> Report:
            callback = kwargs.get("on_finding")
            if callable(callback):
                for finding in report.findings:
                    callback(finding)
            return report

        run_active_scan_mock.side_effect = return_report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            console = io.StringIO()
            with redirect_stdout(console):
                exit_code = main(
                    [
                        "https://example.test/",
                        "--tools",
                        "katana,nmap",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "2.0")
            self.assertGreaterEqual(len(payload["findings"]), 4)
            for finding in payload["findings"]:
                self.assertIn("auth_type", finding)
                self.assertNotIn("score", finding)
                self.assertNotIn("confidence", finding)
            links = output.with_suffix(".txt").read_text(encoding="utf-8").splitlines()
            self.assertIn("https://example.test/login", links)
            self.assertEqual(len(links), len(set(links)))
            self.assertIn("[FOUND]", console.getvalue())
            self.assertIn("https://example.test/login", console.getvalue())

    @patch("authpoints.cli.run_active_scan")
    def test_cli_accepts_custom_links_output(
        self, run_active_scan_mock: object
    ) -> None:
        run_active_scan_mock.return_value = analyze_offline(  # type: ignore[attr-defined]
            targets=["example.test"],
            urls=[],
            nmap_documents=[],
            katana_documents=[
                ("katana.jsonl", (FIXTURES / "katana.jsonl").read_text(encoding="utf-8"))
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            links_output = root / "endpoints.txt"
            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "https://example.test/",
                        "--tools",
                        "katana",
                        "--output",
                        str(root / "report.json"),
                        "--links-output",
                        str(links_output),
                    ]
                )
            self.assertEqual(exit_code, 0)
            self.assertIn(
                "https://example.test/login",
                links_output.read_text(encoding="utf-8").splitlines(),
            )

    @patch("authpoints.cli.run_active_scan")
    def test_cli_can_write_links_without_json(self, run_active_scan_mock: object) -> None:
        run_active_scan_mock.return_value = analyze_offline(  # type: ignore[attr-defined]
            targets=["example.test"],
            urls=[],
            nmap_documents=[],
            katana_documents=[
                ("katana.jsonl", (FIXTURES / "katana.jsonl").read_text(encoding="utf-8"))
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([
                    "-u", "https://example.test/", "--tools", "katana",
                    "--output", str(root / "report.json"),
                    "--links-output", str(root / "auth-links.txt"),
                    "--no-json",
                ])

            self.assertEqual(code, 0)
            self.assertFalse((root / "report.json").exists())
            self.assertIn("https://example.test/login", (root / "auth-links.txt").read_text(encoding="utf-8"))
            self.assertNotIn("JSON:", output.getvalue())

    def test_cli_accepts_mixed_target_file_and_speed_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets_file = root / "targets.txt"
            targets_file.write_text(
                "# module 2 output\nexample.test\n192.0.2.10\n",
                encoding="utf-8",
            )
            output = root / "report.json"
            ca_cert = root / "burp-ca.pem"
            ca_cert.write_text("test certificate fixture\n", encoding="utf-8")
            exit_code = main(
                [
                    "--targets-file",
                    str(targets_file),
                    "--tools",
                    "nmap",
                    "--fast",
                    "--nmap-timing",
                    "2",
                    "--katana-depth",
                    "4",
                    "--katana-max-total-pages",
                    "40",
                    "--katana-max-dom-mb",
                    "6",
                    "--katana-rate-limit",
                    "7",
                    "--katana-parallelism",
                    "3",
                    "--katana-page-load-strategy",
                    "domcontentloaded",
                    "--katana-dom-wait",
                    "9",
                    "--http-concurrency",
                    "6",
                    "--user-agent",
                    "PointFinder-Test/1.0",
                    "--proxy",
                    "127.0.0.1:8080",
                    "--ca-cert",
                    str(ca_cert),
                    "--no-nmap",
                    "--no-katana",
                    "--no-http-probe",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["scope"], ["192.0.2.10", "example.test"])
            config = payload["config"]
            self.assertEqual(config["speed_profile"], "fast")
            self.assertEqual(config["nmap"]["timing_template"], 2)
            self.assertEqual(config["katana"]["depth"], 4)
            self.assertEqual(config["katana"]["max_total_pages"], 40)
            self.assertEqual(config["katana"]["max_dom_bytes"], 6 * 1024 * 1024)
            self.assertEqual(config["katana"]["rate_limit_per_second"], 7)
            self.assertEqual(config["katana"]["parallelism"], 3)
            self.assertEqual(config["katana"]["page_load_strategy"], "domcontentloaded")
            self.assertEqual(config["katana"]["dom_wait_seconds"], 9)
            self.assertEqual(config["http"]["concurrency"], 6)
            self.assertEqual(config["http"]["user_agent"], "PointFinder-Test/1.0")
            self.assertEqual(config["katana"]["user_agent"], "PointFinder-Test/1.0")
            self.assertEqual(config["http"]["proxy"], "http://127.0.0.1:8080")
            self.assertEqual(config["http"]["ca_cert"], str(ca_cert.resolve()))
            self.assertEqual(config["katana"]["proxy"], "http://127.0.0.1:8080")

    def test_cli_help_uses_pointfinder_name(self) -> None:
        self.assertEqual(build_parser().prog, "pointfinder")

    @patch("authpoints.cli.run_active_scan")
    def test_cli_page_only_accepts_url_file_without_external_tools(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            urls = root / "login-urls.txt"
            urls.write_text(
                "https://example.test/login\nhttps://example.test/admin/login\n",
                encoding="utf-8",
            )
            exit_code = main(
                [
                    "--urls-file",
                    str(urls),
                    "--page-only",
                    "--output",
                    str(root / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        call = run_active_scan_mock.call_args  # type: ignore[attr-defined]
        self.assertEqual(
            call.args[1],
            ["https://example.test/login", "https://example.test/admin/login"],
        )
        config = call.args[2]
        self.assertTrue(config.page_only)
        self.assertTrue(config.http.enabled)
        self.assertFalse(config.katana.enabled)
        self.assertFalse(config.nmap.enabled)
        self.assertFalse(config.subfinder.enabled)

    def test_cli_keeps_legacy_access_token_flag_as_noop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with redirect_stdout(io.StringIO()):
                exit_code = main([
                    "https://example.test/",
                    "--tools", "nmap",
                    "--no-nmap",
                    "--allow-access-token-urls",
                    "--output", str(output),
                ])
        self.assertEqual(exit_code, 0)

    def test_cli_help_is_printed_verbatim_from_editable_file(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["-h"])
        self.assertEqual(raised.exception.code, 0)
        help_text = output.getvalue()
        expected = (
            files("authpoints")
            .joinpath("data/cli_help.txt")
            .read_text(encoding="utf-8-sig")
            .rstrip()
            + "\n"
        )
        self.assertEqual(help_text, expected)

    @patch("authpoints.cli.run_active_scan")
    def test_url_without_tools_selects_web_defaults(self, scan) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        scan.return_value = report
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            code = main(["-u", "https://example.test/login", "--output", str(Path(directory) / "report.json")])
        self.assertEqual(code, 0)
        config = scan.call_args.args[2]
        self.assertTrue(config.katana.enabled)
        self.assertTrue(config.katana.auto_headless)
        self.assertTrue(config.http.enabled)
        self.assertIn("/wp-login.php", config.standard_paths)
        self.assertFalse(config.nmap.enabled)
        self.assertFalse(config.subfinder.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_p_dash_enables_all_nmap_ports(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["192.0.2.10"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "192.0.2.10",
                    "--tools",
                    "nmap",
                    "-p-",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )
        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertTrue(config.nmap.all_ports)

    def test_cli_rejects_p_dash_with_top_ports(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(
                [
                    "192.0.2.10",
                    "--tools",
                    "nmap",
                    "-p-",
                    "--top-ports",
                    "100",
                ]
            )
        self.assertEqual(raised.exception.code, 2)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_accepts_mixed_positional_goals(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test", "192.0.2.10", "web.example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "example.test",
                    "192.0.2.10",
                    "https://web.example.test/admin",
                    "--tools",
                    "katana,nmap",
                    "--katana-headless",
                    "--no-http-probe",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        targets, urls, config = run_active_scan_mock.call_args.args  # type: ignore[attr-defined]
        self.assertEqual(targets, ["example.test", "192.0.2.10", "web.example.test"])
        self.assertEqual(urls, ["https://web.example.test/admin"])
        self.assertTrue(config.nmap.enabled)
        self.assertTrue(config.katana.enabled)
        self.assertTrue(config.katana.headless)
        self.assertFalse(config.katana.auto_headless)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_explicit_goals_route_hosts_and_urls(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        cases = [
            (["-u", "example.test", "--tools", "nmap"], ["example.test"], []),
            (
                ["-u", "https://example.test/login", "--tools", "katana"],
                [],
                ["https://example.test/login"],
            ),
            (
                ["-u", "https://example.test:8443/login", "--tools", "katana,nmap"],
                ["example.test"],
                ["https://example.test:8443/login"],
            ),
            (
                [
                    "192.0.2.10",
                    "-u", "example.test",
                    "-u", "https://web.example.test/login",
                    "--tools", "katana,nmap",
                ],
                ["192.0.2.10", "example.test", "web.example.test"],
                ["https://web.example.test/login"],
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            for argv, expected_targets, expected_urls in cases:
                with self.subTest(argv=argv), redirect_stdout(io.StringIO()):
                    exit_code = main([*argv, "--output", str(output)])
                    self.assertEqual(exit_code, 0)
                    targets, urls, _config = run_active_scan_mock.call_args.args  # type: ignore[attr-defined]
                    self.assertEqual(targets, expected_targets)
                    self.assertEqual(urls, expected_urls)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_implicit_scan_accepts_positional_target_and_selects_nmap(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "example.test",
                    "--tools",
                    "nmap",
                    "--no-http-probe",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        targets, urls, config = run_active_scan_mock.call_args.args  # type: ignore[attr-defined]
        self.assertEqual(targets, ["example.test"])
        self.assertEqual(urls, [])
        self.assertTrue(config.nmap.enabled)
        self.assertFalse(config.katana.enabled)
        self.assertFalse(config.http.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_implicit_scan_accepts_positional_url_and_selects_katana(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "https://example.test/",
                    "--tools",
                    "katana",
                    "--no-http-probe",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        targets, urls, config = run_active_scan_mock.call_args.args  # type: ignore[attr-defined]
        self.assertEqual(targets, [])
        self.assertEqual(urls, ["https://example.test/"])
        self.assertFalse(config.nmap.enabled)
        self.assertTrue(config.katana.enabled)
        self.assertTrue(config.katana.auto_headless)
        self.assertFalse(config.http.enabled)
        self.assertEqual(config.standard_paths, [])

    @patch("authpoints.cli.run_active_scan")
    def test_cli_depth_zero_maps_to_start_page_only(self, run_active_scan_mock: object) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory() as directory:
            result = main([
                "https://example.test/", "--tools", "katana",
                "--katana-depth", "0", "--no-http-probe",
                "--output", str(Path(directory) / "report.json"),
            ])

        self.assertEqual(result, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertEqual(config.katana.depth, 1)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_custom_paths_file_replaces_builtin(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths_file = root / "paths.txt"
            paths_file.write_text("/custom-login\n", encoding="utf-8")
            exit_code = main(
                [
                    "https://example.test/",
                    "--tools",
                    "katana",
                    "--paths-file",
                    str(paths_file),
                    "--output",
                    str(root / "report.json"),
                ]
            )
        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertEqual(config.standard_paths, ["/custom-login"])
        self.assertTrue(config.http.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_paths_file_can_run_without_external_tools(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths_file = root / "paths.txt"
            paths_file.write_text("/login\n", encoding="utf-8")
            exit_code = main(
                [
                    "https://example.test/",
                    "--paths-file",
                    str(paths_file),
                    "--output",
                    str(root / "report.json"),
                ]
            )
        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertFalse(config.nmap.enabled)
        self.assertFalse(config.katana.enabled)
        self.assertTrue(config.http.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_builtin_standard_paths_can_be_enabled_without_a_project_path(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "https://example.test/",
                    "--standard-paths",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertIn("/login", config.standard_paths)
        self.assertTrue(config.http.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_accepts_comma_separated_tool_selection(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]

        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "example.test",
                    "--tools",
                    "katana,nmap",
                    "--no-http-probe",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertTrue(config.nmap.enabled)
        self.assertTrue(config.katana.enabled)

    @patch("authpoints.cli.run_active_scan")
    def test_cli_enables_subfinder_and_subdomain_scope(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "https://example.test/",
                    "--tools",
                    "katana,subfinder",
                    "--subfinder-rate-limit",
                    "2",
                    "--subfinder-max-results",
                    "50",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        config = run_active_scan_mock.call_args.args[2]  # type: ignore[attr-defined]
        self.assertTrue(config.subfinder.enabled)
        self.assertTrue(config.include_subdomains)
        self.assertEqual(config.subfinder.rate_limit_per_second, 2)
        self.assertEqual(config.subfinder.max_results, 50)

    @patch("authpoints.cli.run_active_scan")
    def test_url_host_is_automatically_sent_to_nmap(
        self, run_active_scan_mock: object
    ) -> None:
        report = Report(scope=["example.test"])
        report.finish()
        run_active_scan_mock.return_value = report  # type: ignore[attr-defined]
        with tempfile.TemporaryDirectory() as directory:
            exit_code = main(
                [
                    "https://example.test:8443/login",
                    "--tools",
                    "katana,nmap",
                    "--no-http-probe",
                    "--output",
                    str(Path(directory) / "report.json"),
                ]
            )
        self.assertEqual(exit_code, 0)
        targets, urls, _config = run_active_scan_mock.call_args.args  # type: ignore[attr-defined]
        self.assertEqual(targets, ["example.test"])
        self.assertEqual(urls, ["https://example.test:8443/login"])

    def test_cli_rejects_unknown_tool(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["example.test", "--tools", "ffuf"])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_headless_requires_katana(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["https://example.test/", "--standard-paths", "--katana-headless"])
        self.assertEqual(raised.exception.code, 2)

    @patch("authpoints.pipeline.probe_urls", return_value=[])
    def test_standard_paths_are_expanded_for_http_probe_only(
        self, probe_urls_mock: object
    ) -> None:
        report = run_active_scan(
            [],
            ["https://example.test:8443/app"],
            ScanConfig(
                standard_paths=["/login", "/admin/login"],
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=True),
            ),
        )
        self.assertFalse(report.partial)
        probed = probe_urls_mock.call_args.args[0]  # type: ignore[attr-defined]
        self.assertEqual(
            probed,
            [
                "https://example.test:8443/login",
                "https://example.test:8443/admin/login",
            ],
        )

    @patch("authpoints.pipeline.run_katana", return_value="")
    def test_standard_paths_do_not_multiply_katana_roots(
        self, run_katana_mock: object
    ) -> None:
        run_active_scan(
            [],
            ["https://example.test/app"],
            ScanConfig(
                standard_paths=["/login"],
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertEqual(
            run_katana_mock.call_args.args[1],  # type: ignore[attr-defined]
            ["https://example.test/app"],
        )

    @patch("authpoints.pipeline.run_katana")
    def test_auto_mode_renders_root_and_finds_spa_login(
        self, run_katana_mock: object
    ) -> None:
        static_page = json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://example.test/",
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": "<html><body><div id='root'></div></body></html>",
                },
            }
        )
        rendered_page = json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://example.test/",
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><body><form action='/session' method='post'>"
                        "<input name='username'><input name='password' type='password'>"
                        "<button type='submit'>Log in</button></form></body></html>"
                    ),
                },
            }
        )
        run_katana_mock.side_effect = [static_page, rendered_page]  # type: ignore[attr-defined]

        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True, auto_headless=True),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertEqual(run_katana_mock.call_count, 2)  # type: ignore[attr-defined]
        first_config = run_katana_mock.call_args_list[0].args[0]  # type: ignore[attr-defined]
        second_config = run_katana_mock.call_args_list[1].args[0]  # type: ignore[attr-defined]
        self.assertTrue(first_config.js_crawl)
        self.assertFalse(first_config.headless)
        self.assertTrue(second_config.headless)
        self.assertEqual(second_config.depth, 1)
        self.assertEqual(
            run_katana_mock.call_args_list[1].args[1],  # type: ignore[attr-defined]
            ["https://example.test/"],
        )
        self.assertTrue(
            any(finding.auth_type == "password_form" for finding in report.findings)
        )

    @patch("authpoints.pipeline.render_pages")
    @patch("authpoints.pipeline.run_katana")
    def test_auto_mode_renders_confirmed_js_login(
        self, run_katana_mock: object, render_mock: object
    ) -> None:
        run_katana_mock.return_value = json.dumps(  # type: ignore[attr-defined]
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://example.test/login",
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><head><title>Sign In</title></head><body>"
                        "<div>login_component</div>"
                        "<script src='/assets/login.js'></script>"
                        "</body></html>"
                    ),
                },
            }
        )
        render_mock.return_value = json.dumps(  # type: ignore[attr-defined]
            {
                "request": {"method": "GET", "endpoint": "https://example.test/login"},
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><body><form action='/session' method='post'>"
                        "<input name='username'><input name='password' type='password'>"
                        "<button type='submit'>Log in</button></form></body></html>"
                    ),
                },
            }
        )
        report = run_active_scan(
            [],
            ["https://example.test/login"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True, auto_headless=True),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertEqual(run_katana_mock.call_count, 2)  # type: ignore[attr-defined]
        render_mock.assert_called_once()  # type: ignore[attr-defined]
        self.assertTrue(any(finding.auth_type == "password_form" for finding in report.findings))

    @patch("authpoints.pipeline.run_katana")
    def test_auto_headless_timeout_does_not_block_later_candidates(
        self, run_katana_mock: object
    ) -> None:
        static_page = json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://one.example.test/login",
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><body>JavaScript application</body></html>"
                    ),
                },
            }
        )

        def rendered(endpoint: str) -> str:
            return json.dumps(
                {
                    "request": {"method": "GET", "endpoint": endpoint},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": (
                            "<html><body><form action='/session' method='post'>"
                            "<input name='username'>"
                            "<input name='password' type='password'>"
                            "<button type='submit'>Log in</button>"
                            "</form></body></html>"
                        ),
                    },
                }
            )

        run_katana_mock.side_effect = [  # type: ignore[attr-defined]
            static_page,
            ToolError("Katana headless crawl timed out"),
            rendered("https://two.example.test/login"),
        ]

        report = run_active_scan(
            [],
            [
                "https://one.example.test/login",
                "https://two.example.test/login",
            ],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(
                    enabled=True,
                    auto_headless=True,
                    auto_headless_timeout_seconds=30,
                    parallelism=1,
                ),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertEqual(run_katana_mock.call_count, 3)  # type: ignore[attr-defined]
        for call in run_katana_mock.call_args_list[1:]:  # type: ignore[attr-defined]
            self.assertEqual(len(call.args[1]), 1)
            self.assertEqual(call.args[0].timeout_seconds, 30)
        self.assertTrue(any(issue.stage == "katana_headless" for issue in report.issues))
        self.assertTrue(any(finding.auth_type == "password_form" for finding in report.findings))

    @patch("authpoints.pipeline.render_pages", return_value="")
    @patch("authpoints.pipeline.run_katana")
    def test_auto_headless_uses_katana_parallelism(
        self, run_katana_mock: object, _render_mock: object
    ) -> None:
        static_page = json.dumps(
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://one.example.test/",
                },
                "response": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": (
                        "<html><body>JavaScript application</body></html>"
                    ),
                },
            }
        )
        lock = threading.Lock()
        workers_started = threading.Event()
        active = 0
        maximum_active = 0

        def fake_katana(config: KatanaConfig, seeds: list[str], **_kwargs: object) -> str:
            nonlocal active, maximum_active
            if not config.headless:
                return static_page
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active >= 2:
                    workers_started.set()
            if not workers_started.wait(timeout=2):
                raise AssertionError("headless candidates did not run concurrently")
            endpoint = seeds[0]
            result = json.dumps(
                {
                    "request": {"method": "GET", "endpoint": endpoint},
                    "response": {
                        "status_code": 200,
                        "headers": {"content-type": "text/html"},
                        "body": "<html><body></body></html>",
                    },
                }
            )
            with lock:
                active -= 1
            return result

        run_katana_mock.side_effect = fake_katana  # type: ignore[attr-defined]
        report = run_active_scan(
            [],
            [
                "https://one.example.test/",
                "https://two.example.test/",
                "https://three.example.test/",
            ],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(
                    enabled=True,
                    auto_headless=True,
                    parallelism=2,
                ),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertEqual(report.issues, [])
        self.assertEqual(run_katana_mock.call_count, 4)  # type: ignore[attr-defined]
        self.assertEqual(maximum_active, 2)

    @patch("authpoints.pipeline.render_pages", return_value="")
    @patch("authpoints.pipeline.run_katana")
    def test_auto_headless_groups_same_origin_in_one_browser_session(
        self, run_katana_mock: object, _render_mock: object
    ) -> None:
        run_katana_mock.side_effect = ["", ""]  # type: ignore[attr-defined]

        report = run_active_scan(
            [],
            [
                "https://example.test/login",
                "https://example.test/signin",
            ],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(
                    enabled=True,
                    auto_headless=True,
                    auto_headless_timeout_seconds=30,
                    parallelism=2,
                ),
                http=HttpConfig(enabled=False),
            ),
        )

        self.assertEqual(report.issues, [])
        self.assertEqual(run_katana_mock.call_count, 2)  # type: ignore[attr-defined]
        headless_call = run_katana_mock.call_args_list[1]  # type: ignore[attr-defined]
        self.assertEqual(
            headless_call.args[1],
            [
                "https://example.test/login",
                "https://example.test/signin",
            ],
        )
        self.assertEqual(headless_call.args[0].max_domain_pages, 2)
        self.assertEqual(headless_call.args[0].timeout_seconds, 60)
        self.assertEqual(headless_call.args[0].crawl_duration, "30s")

    @patch("authpoints.pipeline.run_nmap", return_value=b"<nmaprun />")
    def test_active_pipeline_runs_tcp_and_optional_udp(
        self, run_nmap_mock: object
    ) -> None:
        report = run_active_scan(
            ["192.0.2.10"],
            [],
            ScanConfig(
                nmap=NmapConfig(enabled=True, udp_enabled=True),
                katana=KatanaConfig(enabled=False),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertEqual(report.issues, [])
        udp_values = [
            call.kwargs["udp"]
            for call in run_nmap_mock.call_args_list  # type: ignore[attr-defined]
        ]
        self.assertEqual(udp_values, [False, True])

    @patch("authpoints.pipeline.run_katana")
    def test_active_pipeline_rejects_non_get_katana_record(self, run_katana_mock: object) -> None:
        run_katana_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"POST","endpoint":"https://example.test/session"},'
            '"response":{"status_code":200}}\n'
        )
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertTrue(any(issue.fatal and "POST" in issue.message for issue in report.issues))
        self.assertEqual(report.findings, [])

    @patch("authpoints.pipeline.run_katana")
    def test_active_pipeline_records_katana_server_error(
        self, run_katana_mock: object
    ) -> None:
        run_katana_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"GET","endpoint":"https://example.test/"},'
            '"response":{"status_code":503}}\n'
        )
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        issue = next(item for item in report.issues if item.stage == "katana_http")
        self.assertEqual(issue.target, "https://example.test/")
        self.assertIn("HTTP 503", issue.message)
        self.assertTrue(report.partial)
        self.assertEqual(report.findings, [])

    @patch("authpoints.pipeline.run_katana")
    def test_active_pipeline_accepts_response_with_query_credentials(
        self, run_katana_mock: object
    ) -> None:
        run_katana_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"GET",'
            '"endpoint":"https://example.test/login?sessionkey=secret"},'
            '"response":{"status_code":200}}\n'
        )
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertFalse(any(issue.fatal for issue in report.issues))

    @patch("authpoints.pipeline.run_katana")
    def test_active_pipeline_ignores_unrequested_non_get_discovery(
        self, run_katana_mock: object
    ) -> None:
        run_katana_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"POST",'
            '"endpoint":"https://example.test/session"}}\n'
        )
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertFalse(report.partial)
        self.assertEqual(report.findings, [])

    @patch("authpoints.pipeline.run_katana")
    def test_active_pipeline_flags_out_of_scope_katana_record(
        self, run_katana_mock: object
    ) -> None:
        run_katana_mock.return_value = (  # type: ignore[attr-defined]
            '{"request":{"method":"GET","endpoint":"https://outside.test/login"},'
            '"response":{"status_code":200}}\n'
        )
        report = run_active_scan(
            [],
            ["https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        self.assertTrue(any(issue.fatal and issue.stage == "scope" for issue in report.issues))

    @patch("authpoints.pipeline.run_katana", return_value="")
    def test_active_pipeline_skips_only_comma_url_for_katana(
        self, run_katana_mock: object
    ) -> None:
        report = run_active_scan(
            [],
            ["https://example.test/a,b", "https://example.test/"],
            ScanConfig(
                nmap=NmapConfig(enabled=False),
                katana=KatanaConfig(enabled=True),
                http=HttpConfig(enabled=False),
            ),
        )
        called_seeds = run_katana_mock.call_args.args[1]  # type: ignore[attr-defined]
        self.assertEqual(called_seeds, ["https://example.test/"])
        self.assertTrue(any("literal comma" in issue.message for issue in report.issues))


if __name__ == "__main__":
    unittest.main()
