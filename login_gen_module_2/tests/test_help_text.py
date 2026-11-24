from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from importlib.resources import files

from logingen.cli import main
from logingen.help_text import HELP_RESOURCE, load_cli_help


class HelpTextTests(unittest.TestCase):
    def test_loads_editable_help_from_package_resource(self) -> None:
        help_text = load_cli_help()
        expected = files("logingen").joinpath(HELP_RESOURCE).read_text(encoding="utf-8")

        self.assertEqual(help_text, expected)
        self.assertTrue(help_text.strip())

    def test_both_help_flags_print_the_russian_resource_verbatim(self) -> None:
        expected = load_cli_help()

        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                output = io.StringIO()
                with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                    main([flag])

                self.assertEqual(raised.exception.code, 0)
                self.assertEqual(output.getvalue(), expected)
                self.assertIn("LOGINGEN — СБОР ФИО И E-MAIL", output.getvalue())
                self.assertIn("--domain", output.getvalue())
                self.assertIn("-g, --generate", output.getvalue())
                self.assertIn("--slow", output.getvalue())
                self.assertIn("--request-delay", output.getvalue())
                self.assertNotIn("КОНФИГ", output.getvalue())
                self.assertNotIn("--config", output.getvalue())


if __name__ == "__main__":
    unittest.main()
