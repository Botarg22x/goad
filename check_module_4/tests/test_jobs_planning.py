from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from authchecker.importer import parse_report
from authchecker.jobs import build_jobs
from authchecker.planning import plan_for_report

from support import valid_finding, valid_report


class JobTests(unittest.TestCase):
    def test_builds_only_allowlisted_findings_not_services(self) -> None:
        source = valid_report(
            findings=[
                valid_finding(auth_type="password_form"),
                valid_finding(
                    finding_id="auth-fedcba9876543210",
                    auth_type="js_login",
                    endpoint="https://example.test/app",
                ),
            ]
        )
        report = parse_report(source)
        jobs = build_jobs(report)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].auth_type, "password_form")
        self.assertNotEqual(jobs[0].endpoint, "ssh://example.test:22")

    def test_colliding_finding_ids_get_distinct_composite_keys(self) -> None:
        first = valid_finding(
            metadata={
                "auth_fingerprint": "form-aaaaaaaaaaaaaaaa",
                "form_action": "https://example.test/session-a",
            }
        )
        second = valid_finding(
            metadata={
                "auth_fingerprint": "form-bbbbbbbbbbbbbbbb",
                "form_action": "https://example.test/session-b",
            }
        )
        jobs = build_jobs(parse_report(valid_report(findings=[first, second])))
        self.assertEqual(len(jobs), 2)
        self.assertNotEqual(jobs[0].job_key, jobs[1].job_key)

    def test_exact_duplicates_are_deduplicated(self) -> None:
        finding = valid_finding()
        jobs = build_jobs(parse_report(valid_report(findings=[finding, finding])))
        self.assertEqual(len(jobs), 1)

    def test_plan_contains_counts_but_no_candidate_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logins = Path(directory, "logins.txt")
            passwords = Path(directory, "passwords.txt")
            logins.write_text("alice\nbob\n", encoding="utf-8")
            passwords.write_text("secret-one\nsecret-two\n", encoding="utf-8")
            report = parse_report(valid_report())
            plan = plan_for_report(
                report,
                report_path="report.json",
                logins_path=logins,
                passwords_path=passwords,
            )
            self.assertEqual(plan.potential_attempt_count, 4)
            rendered = str(plan.as_dict())
            self.assertNotIn("alice", rendered)
            self.assertNotIn("secret-one", rendered)
            self.assertEqual(plan.jobs[0]["adapter"], "password_form")


if __name__ == "__main__":
    unittest.main()

