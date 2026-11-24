from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from authchecker.importer import ReportValidationError, load_report, parse_report

from support import valid_report


class ImporterTests(unittest.TestCase):
    def test_accepts_exact_schema_2_and_partial_report(self) -> None:
        source = valid_report()
        source["partial"] = True
        report = parse_report(json.dumps(source))
        self.assertEqual(report.schema_version, "2.0")
        self.assertTrue(report.partial)
        self.assertEqual(report.findings[0].auth_type, "password_form")

    def test_loads_utf8_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "report.json")
            path.write_text(json.dumps(valid_report()), encoding="utf-8")
            self.assertEqual(load_report(path).scope, ("example.test",))

    def test_rejects_wrong_version(self) -> None:
        source = valid_report()
        source["schema_version"] = "1.0"
        with self.assertRaisesRegex(ReportValidationError, "schema_version"):
            parse_report(source)

    def test_rejects_missing_and_extra_members(self) -> None:
        source = valid_report()
        del source["config"]
        with self.assertRaisesRegex(ReportValidationError, "missing required"):
            parse_report(source)

        source = valid_report()
        source["unknown"] = True
        with self.assertRaisesRegex(ReportValidationError, "unexpected member"):
            parse_report(source)

    def test_rejects_extra_finding_or_evidence_member(self) -> None:
        source = valid_report()
        source["findings"][0]["extra"] = "no"
        with self.assertRaisesRegex(ReportValidationError, "extra"):
            parse_report(source)

        source = valid_report()
        source["findings"][0]["evidence"][0]["extra"] = "no"
        with self.assertRaisesRegex(ReportValidationError, "extra"):
            parse_report(source)

    def test_rejects_invalid_id_port_datetime_and_uuid(self) -> None:
        mutations = (
            ("id", "auth-not-hex", "id"),
            ("port", 0, "port"),
            ("discovered_at", "yesterday", "date-time"),
        )
        for key, value, message in mutations:
            with self.subTest(key=key):
                source = valid_report()
                source["findings"][0][key] = value
                with self.assertRaisesRegex(ReportValidationError, message):
                    parse_report(source)
        source = valid_report()
        source["run_id"] = "nope"
        with self.assertRaisesRegex(ReportValidationError, "UUID"):
            parse_report(source)

    def test_rejects_duplicate_object_members(self) -> None:
        text = '{"schema_version":"2.0","schema_version":"2.0"}'
        with self.assertRaisesRegex(ReportValidationError, "duplicate"):
            parse_report(text)

    def test_rejects_non_json_numbers_and_non_rfc3339_datetime(self) -> None:
        with self.assertRaisesRegex(ReportValidationError, "non-JSON"):
            parse_report('{"value": NaN}')
        source = valid_report()
        source["started_at"] = "2026-10-01 10:00:00+00:00"
        with self.assertRaisesRegex(ReportValidationError, "RFC 3339"):
            parse_report(source)

    def test_rejects_boolean_as_integer_and_nonunique_sources(self) -> None:
        source = valid_report()
        source["findings"][0]["port"] = True
        with self.assertRaisesRegex(ReportValidationError, "integer"):
            parse_report(source)
        source = valid_report()
        source["findings"][0]["sources"] = ["katana", "katana"]
        with self.assertRaisesRegex(ReportValidationError, "unique"):
            parse_report(source)


if __name__ == "__main__":
    unittest.main()

