import _support  # noqa: F401

from io import StringIO
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from goad import cli


class CliTests(TestCase):
    def test_component_tokens_are_not_parsed_or_changed(self):
        tokens = ["--unknown", "a b", "--", "-z"]
        with patch("goad.cli.delegate", return_value=23) as delegated:
            result = cli.main(["passwords", *tokens])

        self.assertEqual(result, 23)
        self.assertEqual(delegated.call_args.args[1], tokens)

    def test_short_check_is_routed_to_module_four(self):
        tokens = ["-r", "report.json", "-l", "student", "-p", "secret"]
        with patch("goad.cli.delegate", return_value=0) as delegated:
            result = cli.main(["check", *tokens])

        self.assertEqual(result, 0)
        self.assertEqual(delegated.call_args.args[0].command, "check")
        self.assertEqual(delegated.call_args.args[1], tokens)

    def test_top_level_help_aliases_render_editable_resource(self):
        expected = cli._read_help_resource().rstrip() + "\n"

        for arguments in ([], ["-h"], ["--help"]):
            with self.subTest(arguments=arguments):
                stdout = StringIO()
                with patch("goad.cli.delegate") as delegated:
                    self.assertEqual(cli.main(arguments, stdout=stdout), 0)
                delegated.assert_not_called()
                self.assertEqual(stdout.getvalue(), expected)

    def test_top_level_help_does_not_depend_on_current_directory(self):
        expected = cli._read_help_resource().rstrip() + "\n"
        previous_cwd = Path.cwd()

        with TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                stdout = StringIO()
                self.assertEqual(cli.main(["-h"], stdout=stdout), 0)
            finally:
                os.chdir(previous_cwd)

        self.assertEqual(stdout.getvalue(), expected)

    def test_top_level_help_falls_back_when_resource_cannot_be_read(self):
        for error in (FileNotFoundError("missing"), OSError("broken"), UnicodeError("bad")):
            with self.subTest(error=type(error).__name__):
                stdout = StringIO()
                with patch("goad.cli._read_help_resource", side_effect=error):
                    self.assertEqual(cli.main(["--help"], stdout=stdout), 0)
                self.assertIn("Полная справка временно недоступна", stdout.getvalue())
                self.assertTrue(stdout.getvalue().endswith("\n"))

    def test_top_level_help_falls_back_when_resource_is_empty(self):
        stdout = StringIO()
        with patch("goad.cli._read_help_resource", return_value=" \n\t"):
            self.assertEqual(cli.main(["-h"], stdout=stdout), 0)

        self.assertEqual(stdout.getvalue(), cli._FALLBACK_HELP.rstrip() + "\n")

    def test_editable_help_explains_module4_artifacts_and_commands(self):
        help_text = cli._read_help_resource()

        for obsolete in ("TOML", "конфиг", "pipeline.example.toml"):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, help_text)

        for fragment in (
            "passwords.txt",
            "goad passwords",
            "goad logins",
            "goad discover",
            "goad check",
            "goad run",
            "--slow",
            "passgen",
            "logingen",
            "pointfinder",
            "authchecker",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, help_text)
        self.assertLess(len(help_text.splitlines()), 60)

    def test_unknown_command_returns_usage_error(self):
        stderr = StringIO()
        result = cli.main(["wat"], stderr=stderr)
        self.assertEqual(result, 2)
        self.assertIn("unknown command", stderr.getvalue())

    def test_run_with_target_uses_direct_mode(self):
        arguments = [
            "--target",
            "http://127.0.0.1:8080/login",
            "--login",
            "student",
            "--password",
            "password123",
        ]
        with patch("goad.cli.direct_run_main", return_value=19) as direct:
            result = cli.main(["run", *arguments])
        self.assertEqual(result, 19)
        direct.assert_called_once()
        self.assertEqual(direct.call_args.args[0], arguments)

    def test_run_with_config_keeps_legacy_orchestrator(self):
        with patch("goad.cli.run_main", return_value=23) as configured:
            result = cli.main(["run", "pipeline.toml", "--validate-only"])
        self.assertEqual(result, 23)
        configured.assert_called_once()
        self.assertEqual(
            configured.call_args.args[0],
            ["pipeline.toml", "--validate-only"],
        )
