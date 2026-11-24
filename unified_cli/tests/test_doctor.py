import _support  # noqa: F401

from io import StringIO
from types import ModuleType
from unittest import TestCase

from goad.components import COMPONENTS
from goad.doctor import ComponentHealth, doctor_main, inspect_component


class DoctorTests(TestCase):
    def test_inspection_requires_main_and_reports_version(self):
        module = ModuleType("fake")
        module.main = lambda argv: 0
        item = inspect_component(
            COMPONENTS["logins"],
            importer=lambda _: module,
            version_resolver=lambda _module, _component: "9.1",
        )
        self.assertTrue(item.available)
        self.assertEqual(item.version, "9.1")

    def test_json_and_nonzero_when_component_is_missing(self):
        health = [
            ComponentHealth("passwords", "p.cli", True, "1.0", None),
            ComponentHealth("check", "c.cli", False, None, "not installed"),
        ]
        stdout = StringIO()
        result = doctor_main(
            ["--json"], stdout=stdout, health_provider=lambda: health
        )
        self.assertEqual(result, 1)
        self.assertIn('"available": false', stdout.getvalue())

