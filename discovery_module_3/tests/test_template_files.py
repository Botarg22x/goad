from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
import yaml

from authpoints.cli import main
from authpoints.login_templates import _validate_template, load_login_templates


TEMPLATE = """# Один продукт на файл; кириллица и комментарии разрешены.
id: myportal
label: Мой портал
category: webapp
username_fields: [account_id]
password_fields: [secret]
signals_any:
  - text_contains: Мой портал
  - field_names_all: [AUTH_FORM, TYPE]
paths:
  - /portal/login
"""


class TemplateFileTests(unittest.TestCase):
    def test_example_uses_valid_unified_format(self):
        source = (Path(__file__).resolve().parents[1] / "src/authpoints/data/login_templates"
                  / "PRODUCT_TEMPLATE.yaml.example")
        item = yaml.safe_load(source.read_text(encoding="utf-8"))
        self.assertEqual(list(item)[:5], ["id", "label", "category", "paths", "detection"])
        self.assertEqual(_validate_template(item, str(source)).id, "myproduct")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.directory = root / "data" / "login_templates"
        self.directory.mkdir(parents=True)
        patcher = patch("authpoints.login_templates.files", return_value=root)
        patcher.start()
        self.addCleanup(patcher.stop)
        load_login_templates.cache_clear()
        self.addCleanup(load_login_templates.cache_clear)

    def write(self, text=TEMPLATE, name="myportal.yaml"):
        path = self.directory / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_yaml_comments_unicode_and_bom(self):
        self.write("\ufeff" + TEMPLATE)
        templates = load_login_templates()
        self.assertEqual(len(templates), 1)
        self.assertEqual(templates[0].id, "myportal")
        self.assertEqual(templates[0].label, "Мой портал")
        self.assertEqual(templates[0].username_fields, ("account_id",))
        self.assertEqual(templates[0].password_fields, ("secret",))
        self.assertEqual(templates[0].paths, ("/portal/login",))

    def test_unified_form_detection_keeps_legacy_runtime_contract(self):
        unified = TEMPLATE.replace(
            "username_fields: [account_id]\npassword_fields: [secret]\nsignals_any:\n"
            "  - text_contains: Мой портал\n  - field_names_all: [AUTH_FORM, TYPE]\n"
            "paths:\n  - /portal/login\n",
            "paths:\n  - /portal/login\ndetection:\n"
            "  username_fields: [account_id]\n  password_fields: [secret]\n"
            "  signals_any:\n    - text_contains: Мой портал\n"
            "    - field_names_all: [AUTH_FORM, TYPE]\n",
        )
        self.assertNotEqual(unified, TEMPLATE)
        self.write(unified)
        template = load_login_templates()[0]
        self.assertEqual(template.username_fields, ("account_id",))
        self.assertEqual(template.password_fields, ("secret",))
        self.assertEqual(template.signals_any, (
            {"text_contains": "Мой портал"},
            {"field_names_all": ["AUTH_FORM", "TYPE"]},
        ))
        self.assertIsNone(template.detection)

    def test_unified_form_detection_rejects_duplicate_field_sections(self):
        self.write(TEMPLATE + "detection:\n  username_fields: [other]\n"
                   "  password_fields: [secret]\n  signals_any: [{text_contains: Portal}]\n")
        with self.assertRaisesRegex(ValueError, "поля формы задаются либо в detection"):
            load_login_templates()

    def test_file_discovery_supports_yml_and_ignores_docs_backups_and_subdirs(self):
        self.write(TEMPLATE.replace("myportal", "bravo"), "b.yml")
        self.write(TEMPLATE.replace("myportal", "alpha"), "a.yaml")
        self.write("Not a template", "README.md")
        self.write("Not a template", "disabled.yaml.disabled")
        nested = self.directory / "nested.yaml"
        nested.mkdir()
        (nested / "ignored.yaml").write_text("Not a template", encoding="utf-8")
        self.assertEqual([t.id for t in load_login_templates()], ["alpha", "bravo"])

    def test_duplicate_id_identifies_both_files(self):
        self.write(name="first.yaml")
        self.write(name="second.yml")
        with self.assertRaises(ValueError) as raised:
            load_login_templates()
        message = str(raised.exception)
        self.assertIn("first.yaml", message)
        self.assertIn("second.yml", message)
        self.assertIn("myportal", message)

    def test_invalid_yaml_reports_filename_and_line(self):
        self.write(TEMPLATE + "broken: [\n")
        with self.assertRaises(ValueError) as raised:
            load_login_templates()
        self.assertIn("myportal.yaml", str(raised.exception))
        self.assertIn("строка", str(raised.exception))
        self.assertIn("столбец", str(raised.exception))

    def test_duplicate_yaml_keys_are_not_silently_overwritten(self):
        self.write(TEMPLATE + "id: changed\n")
        with self.assertRaisesRegex(ValueError, "повторяющийся ключ 'id'"):
            load_login_templates()

    def test_invalid_definitions_are_actionable(self):
        cases = [
            ("", "один объект"),
            ("[]", "один объект"),
            (TEMPLATE.replace("label: Мой портал\n", ""), "отсутствуют поля: label"),
            (TEMPLATE + "typo: value\n", "неизвестные поля: typo"),
            (TEMPLATE.replace("myportal", "My Portal"), "id должен"),
            (TEMPLATE.replace("[account_id]", "[]"), "username_fields"),
            (TEMPLATE.replace("[account_id]", "[on]"), "username_fields"),
            (TEMPLATE.replace("text_contains", "regex"), "неверный признак regex"),
            (TEMPLATE.replace("/portal/login", "https://other.test/login"), "paths:"),
            (TEMPLATE.replace("/portal/login", "/../login"), "paths:"),
            (TEMPLATE.replace("/portal/login", "/logout"), "paths:"),
            (TEMPLATE + "---\n" + TEMPLATE, "another document"),
            ("!!python/tuple [one, two]", "constructor"),
        ]
        for content, reason in cases:
            with self.subTest(reason=reason):
                self.write(content)
                load_login_templates.cache_clear()
                with self.assertRaises(ValueError) as raised:
                    load_login_templates()
                self.assertIn("myportal.yaml", str(raised.exception))
                self.assertIn(reason, str(raised.exception))

    def test_simple_template_rejects_invalid_response_status(self):
        base = ("id: myportal\npaths: [/login]\nin_body: Portal\n"
                "post: 'username={{login}}&password={{password}}'\n"
                "success: signed-in\nfailure: invalid-password\n")
        for value in ("true", "'200'", "99", "600"):
            with self.subTest(value=value):
                self.write(base + f"failure_status: {value}\n")
                load_login_templates.cache_clear()
                with self.assertRaisesRegex(ValueError, "failure_status должен быть HTTP-кодом"):
                    load_login_templates()

    def test_simple_template_accepts_response_codes_without_body_markers(self):
        base = ("id: myportal\npaths: [/login]\nin_body: Portal\n"
                "post: 'username={{login}}&password={{password}}'\n")
        self.write(base + "success_status: 302\nfailure_status: 200\n")
        profile = load_login_templates()[0].verification
        self.assertEqual(profile["result"]["success_any"], [])
        self.assertEqual(profile["result"]["failure_any"], [])
        self.assertEqual(profile["result"]["success_status"], 302)
        self.assertEqual(profile["result"]["failure_status"], 200)

        self.write(base + "failure_status: 200\n")
        load_login_templates.cache_clear()
        self.assertEqual(load_login_templates()[0].verification["result"]["success_any"], [])

        self.write(base)
        load_login_templates.cache_clear()
        with self.assertRaisesRegex(ValueError, "хотя бы один признак результата"):
            load_login_templates()

    def test_empty_directory_is_an_explicit_error(self):
        with self.assertRaisesRegex(ValueError, "не найдены шаблоны"):
            load_login_templates()

    @patch("authpoints.cli.run_active_scan")
    def test_cli_reload_sees_new_and_edited_files_without_network(self, scan):
        self.write()
        first, second = io.StringIO(), io.StringIO()
        with redirect_stdout(first):
            self.assertEqual(main(["--list-templates"]), 0)
        self.write(TEMPLATE.replace("Мой портал", "Изменённый портал"))
        self.write(TEMPLATE.replace("myportal", "another"), "another.yml")
        with redirect_stdout(second):
            self.assertEqual(main(["--list-templates"]), 0)
        self.assertIn("Мой портал", first.getvalue())
        self.assertIn("Изменённый портал", second.getvalue())
        self.assertIn("another", second.getvalue())
        scan.assert_not_called()

    @patch("authpoints.cli.run_active_scan")
    def test_cli_invalid_template_fails_before_network_without_traceback(self, scan):
        self.write("id: [\n")
        output = io.StringIO()
        with redirect_stderr(output):
            self.assertEqual(main(["-u", "https://example.test"]), 2)
        self.assertIn("myportal.yaml", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        scan.assert_not_called()
