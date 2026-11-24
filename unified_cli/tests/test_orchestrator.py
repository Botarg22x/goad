import _support  # noqa: F401

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
import json

from goad.orchestrator import OrchestrationService, manifest_document


class OrchestratorTests(TestCase):
    def test_plans_and_atomically_writes_manifest_without_importing_components(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "pipeline.toml"
            config_path.write_text(
                """\
schema_version = 1
output_dir = "results"

[metadata]
purpose = "test"

[stages.passwords]
args = ["--count", "2", "--output", "{run_dir}/passwords-{run_id}.txt"]
cwd = "."

[stages.check]
enabled = false
""",
                encoding="utf-8",
            )
            instant = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
            service = OrchestrationService(
                clock=lambda: instant,
                id_factory=lambda _: "fixed-run",
            )
            plan = service.plan(config_path)

            self.assertEqual(plan.run_id, "fixed-run")
            self.assertEqual(plan.output_dir, (root / "results").resolve())
            self.assertEqual(
                plan.stages[0].argv,
                (
                    "--count",
                    "2",
                    "--output",
                    str(root / "results" / "fixed-run" / "passwords-fixed-run.txt"),
                ),
            )
            self.assertEqual(plan.stages[0].cwd, root.resolve())
            self.assertEqual(manifest_document(plan)["status"], "planned")

            path = service.write_manifest(plan)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["run_id"], "fixed-run")
            self.assertEqual(data["stages"][0]["module"], "password_generator.cli")
            self.assertEqual(data["stages"][3]["status"], "disabled")

    def test_execute_stops_on_failure_and_checkpoints_manifest(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "pipeline.toml"
            config_path.write_text(
                """\
schema_version = 1
output_dir = "results"

[stages.passwords]
args = ["--output", "{run_dir}/passwords.txt"]

[stages.logins]
args = ["--run", "{run_id}"]

[stages.discover]
args = []
""",
                encoding="utf-8",
            )
            service = OrchestrationService(id_factory=lambda _: "execution")
            plan = service.plan(config_path)
            calls = []

            def executor(stage):
                calls.append(stage.name)
                return 5 if stage.name == "logins" else 0

            outcome = service.execute(plan, executor=executor)

            self.assertEqual(outcome.exit_code, 5)
            self.assertEqual(outcome.failed_stage, "logins")
            self.assertEqual(calls, ["passwords", "logins"])
            data = json.loads(outcome.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "failed")
            self.assertEqual(data["stages"][0]["status"], "succeeded")
            self.assertEqual(data["stages"][0]["exit_code"], 0)
            self.assertEqual(data["stages"][1]["status"], "failed")
            self.assertEqual(data["stages"][1]["exit_code"], 5)
            self.assertEqual(data["stages"][2]["status"], "skipped")

    def test_execute_runs_all_enabled_stages_in_registry_order(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "pipeline.toml"
            config_path.write_text(
                """\
schema_version = 1
[stages.passwords]
[stages.logins]
[stages.discover]
[stages.check]
""",
                encoding="utf-8",
            )
            service = OrchestrationService(id_factory=lambda _: "all-stages")
            plan = service.plan(config_path)
            calls = []
            outcome = service.execute(
                plan, executor=lambda stage: calls.append(stage.name) or 0
            )
            self.assertEqual(
                calls, ["passwords", "logins", "discover", "check"]
            )
            self.assertEqual(outcome.status, "succeeded")
            self.assertEqual(outcome.exit_code, 0)

    def test_validate_only_is_supported_by_service_plan(self):
        with TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "pipeline.toml"
            config_path.write_text(
                "schema_version = 1\n[stages.discover]\nenabled = true\n",
                encoding="utf-8",
            )
            service = OrchestrationService(id_factory=lambda _: "validation")
            plan = service.plan(config_path)
            self.assertEqual(plan.run_id, "validation")
            self.assertFalse(plan.manifest_path.exists())

