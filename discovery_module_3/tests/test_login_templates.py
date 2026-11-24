from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
import yaml

from authpoints.classifier import classify_web
from authpoints.cli import main
from authpoints.config import ScanConfig, KatanaConfig, NmapConfig, HttpConfig
from authpoints.login_templates import load_login_templates, parse_template_selection, template_paths
from authpoints.models import Report, WebObservation
from authpoints.parsers.html import parse_html
from authpoints.pipeline import run_active_scan


def observation(body, url="https://example.test/login"):
    title, text, forms, links = parse_html(body, url)
    return WebObservation(url=url, source="http_probe", status_code=200,
                          title=title, text=text, forms=forms, links=links, body=body)


WORDPRESS = '<form method="post"><input name="log"><input name="pwd" type="password"></form>'


class TemplateTests(unittest.TestCase):
    def test_builtin_files_use_one_envelope(self):
        directory = Path(__file__).resolve().parents[1] / "src/authpoints/data/login_templates"
        for path in directory.glob("*.yaml"):
            with self.subTest(path=path.name):
                item = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(list(item)[:5], ["id", "label", "category", "paths", "detection"])
                self.assertLessEqual(set(item), {
                    "id", "label", "category", "paths", "detection", "verification",
                })

    @patch("authpoints.pipeline.run_katana")
    def test_filtered_callback_emits_template_added_by_browser_merge(self, katana):
        url = "https://example.test/custom"
        html = WORDPRESS.replace("<form", "<form aria-label='login'").replace("</form>", "<button>Log in</button></form>")
        # The first pass confirms a generic login; the browser provides the
        # product title at the same form, which is merged rather than duplicated.
        def records(body):
            return json.dumps({"request": {"endpoint": url, "method": "GET"},
                               "response": {"status_code": 200, "body": body}})
        katana.side_effect = [records(html), records("<title>WordPress</title>" + html)]
        seen = []
        config = ScanConfig(login_templates=("wordpress",), nmap=NmapConfig(enabled=False),
                            katana=KatanaConfig(enabled=True, auto_headless=True), http=HttpConfig(enabled=False))
        with patch("authpoints.pipeline._auto_headless_candidates", return_value=[url]):
            report = run_active_scan([], [url], config, on_finding=seen.append)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].metadata["login_template"], "wordpress")

    def test_products_have_real_fields_and_template_evidence(self):
        cases = [
            ("wordpress", "/wp-login.php", WORDPRESS, "log", "pwd"),
            ("bitrix-site", "/bitrix/admin/index.php", '<form><input name="USER_LOGIN"><input name="USER_PASSWORD" type="password"></form>', "USER_LOGIN", "USER_PASSWORD"),
            ("roundcube", "/roundcube/", '<form><input name="_user"><input name="_pass" type="password"></form>', "_user", "_pass"),
            ("zimbra", "/", '<title>Zimbra Web Client</title><form><input name="username"><input name="password" type="password"></form>', "username", "password"),
            ("owa", "/owa/auth/logon.aspx", '<form><input name="username"><input name="password" type="password"></form>', "username", "password"),
        ]
        for name, path, body, user, password in cases:
            with self.subTest(name=name):
                finding = classify_web(observation(body, "https://example.test" + path))[0]
                self.assertEqual(finding.auth_type, "password_form")
                self.assertEqual(finding.metadata["login_template"], name)
                self.assertIn(name, finding.metadata["tags"])
                self.assertEqual(finding.metadata["credential_fields"], {"username": user, "password": password})
                self.assertTrue(any(e.rule_id == "template." + name for e in finding.evidence))

    def test_custom_url_can_match_fields_and_product_title(self):
        result = classify_web(observation("<title>WordPress</title>" + WORDPRESS, "https://example.test/custom"))
        self.assertEqual(result[0].metadata["login_template"], "wordpress")

    def test_wordpress_template_carries_request_and_result_rules_to_module4(self):
        finding = classify_web(observation(WORDPRESS, "https://example.test/wp-login.php"))[0]
        profile = finding.metadata["login_verification"]
        self.assertEqual(profile["request"]["action"], "form")
        self.assertIn("log={{login}}&pwd={{password}}", profile["request"]["raw"])
        self.assertEqual(profile["result"]["success_any"], [{"link_query": {"action": "logout"}}])
        self.assertEqual(profile["result"]["failure_any"], [{"in_body": 'id="login_error"'}])

    def test_gitlab_template_describes_post_statuses_separately_from_page_markers(self):
        template = next(item for item in load_login_templates() if item.id == "gitlab")
        result = template.verification["result"]
        self.assertEqual(result["success_status"], 302)
        self.assertEqual(result["failure_status"], 200)
        self.assertEqual(result["success_any"], [])
        self.assertEqual(result["failure_any"], [{"in_body": "Invalid login or password"}])

    def test_hidden_markers_can_identify_product_without_product_path(self):
        result = classify_web(observation('<form><input name="USER_LOGIN"><input name="USER_PASSWORD" type="password"><input name="AUTH_FORM" type="hidden"><input name="TYPE" type="hidden"></form>'))
        self.assertEqual(result[0].metadata["login_template"], "bitrix-site")

    def test_url_title_or_other_form_fields_alone_do_not_match(self):
        bodies = [
            "<title>WordPress</title><p>No form</p>",
            '<form><input name="log"></form><form><input name="pwd" type="password"></form>',
            '<form><input name="log" disabled><input name="pwd" type="password"></form>',
            WORDPRESS.replace('name="pwd"', 'hidden name="pwd"'),
            '<input name="log"><input type="password" name="pwd">',
            WORDPRESS.replace('name="log"', 'name="log" type="hidden"'),
            '<form><input name="log"><input name="log"><input name="pwd" type="password"></form>',
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.assertFalse(any(f.metadata.get("login_template") for f in classify_web(observation(body, "https://example.test/wp-login.php"))))

    def test_registration_and_error_pages_are_not_promoted(self):
        for url, body, status in [
            ("https://example.test/register", "<title>WordPress</title>" + WORDPRESS, 200),
            ("https://example.test/wp-login.php", WORDPRESS.replace('type="password"', 'type="password" autocomplete="new-password"'), 200),
            ("https://example.test/wp-login.php", WORDPRESS, 404),
        ]:
            page = observation(body, url)
            page.status_code = status
            self.assertEqual(classify_web(page), [])

    def test_generic_form_stays_supported_and_untagged(self):
        findings = classify_web(observation('<form><input name="username"><input name="password" type="password"></form>'))
        self.assertEqual(findings[0].auth_type, "password_form")
        self.assertNotIn("login_template", findings[0].metadata)

    def test_selection_and_paths(self):
        self.assertEqual(parse_template_selection(["wordpress,bitrix", "wordpress"]), ("wordpress", "bitrix"))
        self.assertEqual(template_paths(("wordpress",)), ["/wp-login.php", "/wp-admin/"])
        with self.assertRaises(ValueError):
            parse_template_selection(["unknown"])
        self.assertEqual(len(load_login_templates()), 7)

    @patch("authpoints.pipeline.run_katana")
    def test_filter_applies_to_callback_json_and_links(self, katana):
        katana.return_value = "\n".join(json.dumps({
            "request": {"endpoint": url, "method": "GET"},
            "response": {"status_code": 200, "body": html},
        }) for url, html in [
            ("https://example.test/wp-login.php", WORDPRESS),
            ("https://example.test/login", '<form><input name="username"><input name="password" type="password"></form>'),
        ])
        seen = []
        config = ScanConfig(login_templates=("wordpress",), nmap=NmapConfig(enabled=False),
                            katana=KatanaConfig(enabled=True, auto_headless=False), http=HttpConfig(enabled=False))
        report = run_active_scan([], ["https://example.test/"], config, on_finding=seen.append)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(report.findings[0].metadata["login_template"], "wordpress")
        from authpoints.reporting import write_json_report, write_links_report
        with tempfile.TemporaryDirectory() as tmp:
            write_json_report(report, Path(tmp) / "report.json")
            write_links_report(report, Path(tmp) / "report.txt")
            payload = json.loads((Path(tmp) / "report.json").read_text())
            self.assertEqual(payload["findings"][0]["metadata"]["login_template"], "wordpress")
            self.assertEqual((Path(tmp) / "report.txt").read_text(), "https://example.test/wp-login.php\n")


class TemplateCliTests(unittest.TestCase):
    @patch("authpoints.cli.run_active_scan")
    def test_url_file_defaults_and_template_specific_paths(self, scan):
        report = Report(scope=["example.test"])
        report.finish()
        scan.return_value = report
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            path = Path(tmp) / "urls.txt"
            path.write_text("\ufeff# targets\nhttps://example.test/\nhttps://other.test/login\nhttps://example.test/\n", encoding="utf-8")
            code = main(["-u", str(path), "--login-template", "wordpress", "--output", str(Path(tmp) / "report.json")])
        self.assertEqual(code, 0)
        targets, urls, config = scan.call_args.args
        self.assertEqual(targets, [])
        self.assertEqual(urls, ["https://example.test/", "https://other.test/login"])
        self.assertTrue(config.katana.enabled)
        self.assertTrue(config.http.enabled)
        self.assertFalse(config.nmap.enabled)
        self.assertFalse(config.subfinder.enabled)
        self.assertEqual(config.standard_paths, ["/wp-login.php", "/wp-admin/"])
        self.assertEqual(config.login_templates, ("wordpress",))

    @patch("authpoints.cli.run_active_scan")
    def test_invalid_file_and_unknown_template_fail_before_network(self, scan):
        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            missing = Path(tmp) / "absent.txt"
            self.assertEqual(main(["-u", str(missing)]), 2)
            empty = Path(tmp) / "empty.txt"
            empty.write_text("# no urls\n")
            self.assertEqual(main(["-u", str(empty)]), 2)
            empty.write_text("not a URL\n")
            self.assertEqual(main(["-u", str(empty)]), 2)
            self.assertEqual(main(["-u", "https://example.test", "--login-template", "bogus"]), 2)
        scan.assert_not_called()

    @patch("authpoints.cli.run_active_scan")
    def test_opt_out_and_page_only_keep_explicit_behavior(self, scan):
        report = Report(scope=["example.test"])
        report.finish()
        scan.return_value = report
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            for flags, katana, http in [
                (["--no-standard-paths"], True, False),
                (["--no-katana"], False, True),
                (["--page-only"], False, True),
                (["--tools", "katana"], True, False),
            ]:
                with self.subTest(flags=flags):
                    self.assertEqual(main(["-u", "https://example.test/", *flags, "--output", str(Path(tmp) / "report.json")]), 0)
                    config = scan.call_args.args[2]
                    self.assertEqual(config.katana.enabled, katana)
                    self.assertEqual(config.http.enabled, http)

    @patch("authpoints.cli.run_active_scan")
    def test_list_templates_does_not_scan(self, scan):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--list-templates"]), 0)
        self.assertIn("wordpress", output.getvalue())
        scan.assert_not_called()
