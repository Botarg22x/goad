import _support  # noqa: F401

from types import ModuleType
from unittest import TestCase
from io import StringIO

from goad.components import COMPONENTS
from goad.delegation import DelegationError, delegate


class DelegationTests(TestCase):
    def test_passes_same_argv_object_and_returns_exit_code(self):
        module = ModuleType("fake")
        observed = []

        def main(argv):
            observed.append(argv)
            return 17

        module.main = main
        argv = ["--name", "значение с пробелом", "--", "-x"]

        result = delegate(COMPONENTS["passwords"], argv, importer=lambda _: module)

        self.assertEqual(result, 17)
        self.assertIs(observed[0], argv)
        self.assertEqual(observed[0], ["--name", "значение с пробелом", "--", "-x"])

    def test_none_result_means_success(self):
        module = ModuleType("fake")
        module.main = lambda argv: None
        self.assertEqual(
            delegate(COMPONENTS["logins"], [], importer=lambda _: module),
            0,
        )

    def test_system_exit_string_is_reported_as_failure(self):
        module = ModuleType("fake")

        def main(argv):
            raise SystemExit("bad arguments")

        module.main = main
        stderr = StringIO()
        result = delegate(
            COMPONENTS["discover"], [], importer=lambda _: module, stderr=stderr
        )
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "bad arguments\n")

    def test_missing_main_raises_clear_error(self):
        with self.assertRaisesRegex(DelegationError, "main\\(argv\\)"):
            delegate(
                COMPONENTS["check"],
                [],
                importer=lambda _: ModuleType("fake"),
            )

