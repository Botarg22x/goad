from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


INSTALLER_PATH = Path(__file__).resolve().parents[1] / "install_workspace.py"
SPEC = importlib.util.spec_from_file_location("workspace_installer", INSTALLER_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import bootstrap guard
    raise RuntimeError(f"Cannot load installer module from {INSTALLER_PATH}")
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class WorkspaceFixture:
    def __init__(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary_directory.name) / "diplom workspace Кириллица"
        self.root.mkdir()
        for project in installer.PROJECTS:
            project_dir = self.root / project.directory
            project_dir.mkdir()
            (project_dir / "pyproject.toml").write_text(
                f"[project]\nname = {project.distribution!r}\nversion = '0.0.0'\n",
                encoding="utf-8",
            )

    def close(self) -> None:
        self._temporary_directory.cleanup()


class ProjectSelectionTests(unittest.TestCase):
    def test_default_selection_has_dependency_friendly_order(self) -> None:
        selected = installer.resolve_projects()

        self.assertEqual(
            tuple(project.key for project in selected),
            ("module1", "module2", "module3", "module4", "unified_cli"),
        )

    def test_alias_selection_keeps_canonical_order_and_deduplicates(self) -> None:
        selected = installer.resolve_projects(
            ("goad", "discovery_module_3", "pointfinder", "module1")
        )

        self.assertEqual(
            tuple(project.key for project in selected),
            ("module1", "module3", "unified_cli"),
        )

    def test_unknown_project_is_rejected(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "Unknown project"):
            installer.resolve_projects(("not-a-project",))


class InstallPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = WorkspaceFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_default_plan_uses_one_editable_command_per_project(self) -> None:
        bootstrap_python = Path("C:/Python311/python.exe")
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.PROJECTS,
            bootstrap_python=bootstrap_python,
            os_name="nt",
        )

        self.assertEqual(
            plan.create_environment.argv,
            (
                str(bootstrap_python),
                "-m",
                "venv",
                str((self.fixture.root / ".venv").resolve()),
            ),
        )
        self.assertEqual(len(plan.install_commands), 5)
        self.assertEqual(
            plan.install_commands[1].argv[-1],
            f"{(self.fixture.root / 'login_gen_module_2').resolve()}[browser,pdf]",
        )
        self.assertEqual(
            plan.install_commands[2].argv[-1],
            str((self.fixture.root / "discovery_module_3").resolve()),
        )
        self.assertEqual(
            plan.browser_command.argv,
            (
                str((self.fixture.root / ".venv" / "Scripts" / "python.exe").resolve()),
                "-m",
                "playwright",
                "install",
                "chromium",
            ),
        )
        self.assertEqual(
            plan.doctor_command.argv,
            (
                str((self.fixture.root / ".venv" / "Scripts" / "goad.exe").resolve()),
                "doctor",
            ),
        )
        self.assertEqual(plan.commands[-1], plan.doctor_command)

    def test_space_plus_and_cyrillic_path_is_one_subprocess_argument(self) -> None:
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv с пробелом"),
            installer.resolve_projects(("module3",)),
            bootstrap_python=Path("python.exe"),
            os_name="nt",
            install_playwright_browser=False,
        )

        command = plan.install_commands[0].argv
        self.assertEqual(len(command), 6)
        self.assertEqual(command[-2], "--editable")
        self.assertEqual(
            command[-1],
            str((self.fixture.root / "discovery_module_3").resolve()),
        )
        self.assertNotIn('"', command[-1])

    def test_minimal_plan_omits_extras_and_browser_download(self) -> None:
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.resolve_projects(("module2",)),
            bootstrap_python=Path("python"),
            minimal=True,
            os_name="nt",
        )

        self.assertEqual(
            plan.install_commands[0].argv[-1],
            str((self.fixture.root / "login_gen_module_2").resolve()),
        )
        self.assertIsNone(plan.browser_command)

    def test_existing_environment_is_reused(self) -> None:
        interpreter = self.fixture.root / ".venv" / "Scripts" / "python.exe"
        interpreter.parent.mkdir(parents=True)
        interpreter.touch()

        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.resolve_projects(("module4",)),
            bootstrap_python=Path("python"),
            os_name="nt",
            install_playwright_browser=False,
        )

        self.assertIsNone(plan.create_environment)
        self.assertEqual(plan.venv_python, interpreter.resolve())

    def test_preflight_fails_before_environment_creation_when_project_is_missing(self) -> None:
        missing = self.fixture.root / "check_module_4" / "pyproject.toml"
        missing.unlink()

        with self.assertRaisesRegex(installer.InstallError, "missing pyproject.toml"):
            installer.create_install_plan(
                self.fixture.root,
                Path(".venv"),
                installer.PROJECTS,
                bootstrap_python=Path("python"),
                os_name="nt",
            )

        self.assertFalse((self.fixture.root / ".venv").exists())

    def test_preflight_validates_new_distribution_names(self) -> None:
        module4_pyproject = self.fixture.root / "check_module_4" / "pyproject.toml"
        module4_pyproject.write_text(
            "[project]\nname = 'credential-auditor'\nversion = '0.0.0'\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            installer.InstallError,
            "expected 'authchecker', found 'credential-auditor'",
        ):
            installer.create_install_plan(
                self.fixture.root,
                Path(".venv"),
                installer.resolve_projects(("module4",)),
                bootstrap_python=Path("python"),
                os_name="nt",
                install_playwright_browser=False,
            )

    def test_environment_inside_project_is_rejected(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "cannot be created inside project"):
            installer.create_install_plan(
                self.fixture.root,
                Path("check_module_4/.venv"),
                installer.resolve_projects(("module4",)),
                bootstrap_python=Path("python"),
                os_name="nt",
                install_playwright_browser=False,
            )

    def test_posix_environment_interpreter_path(self) -> None:
        path = installer.venv_python_path(Path("/tmp/work space/.venv"), os_name="posix")
        self.assertEqual(path, Path("/tmp/work space/.venv/bin/python"))

    def test_posix_doctor_command_uses_environment_bin_directory(self) -> None:
        path = installer.venv_console_script_path(
            Path("/tmp/work space/.venv"), "goad", os_name="posix"
        )
        self.assertEqual(path, Path("/tmp/work space/.venv/bin/goad"))

    def test_doctor_can_be_disabled_for_independent_unified_cli_install(self) -> None:
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.resolve_projects(("unified_cli",)),
            bootstrap_python=Path("python"),
            os_name="nt",
            install_playwright_browser=False,
            run_doctor=False,
        )
        self.assertIsNone(plan.doctor_command)


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = WorkspaceFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_dry_run_never_invokes_runner_or_creates_environment(self) -> None:
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.resolve_projects(("module1",)),
            bootstrap_python=Path("python"),
            os_name="nt",
            install_playwright_browser=False,
        )
        calls: list[tuple[str, ...]] = []
        output = io.StringIO()

        installer.execute_plan(
            plan,
            dry_run=True,
            runner=lambda argv: calls.append(tuple(argv)),
            version_probe=lambda _path: self.fail("version probe must not run during dry-run"),
            stream=output,
        )

        self.assertEqual(calls, [])
        self.assertFalse((self.fixture.root / ".venv").exists())
        self.assertIn("no commands were executed", output.getvalue())

    def test_existing_environment_executes_argument_lists_without_shell(self) -> None:
        interpreter = self.fixture.root / ".venv" / "Scripts" / "python.exe"
        interpreter.parent.mkdir(parents=True)
        interpreter.touch()
        plan = installer.create_install_plan(
            self.fixture.root,
            Path(".venv"),
            installer.resolve_projects(("module3", "module4")),
            bootstrap_python=Path("python"),
            os_name="nt",
            install_playwright_browser=False,
        )
        calls: list[tuple[str, ...]] = []

        installer.execute_plan(
            plan,
            runner=lambda argv: calls.append(tuple(argv)),
            version_probe=lambda _path: (3, 11, 9),
            stream=io.StringIO(),
        )

        self.assertEqual(calls, [command.argv for command in plan.install_commands])
        self.assertTrue(all(isinstance(call, tuple) for call in calls))

    def test_python_310_is_rejected(self) -> None:
        with self.assertRaisesRegex(installer.InstallError, "Python >= 3.11"):
            installer.ensure_supported_version((3, 10, 14))


class PowerShellWrapperTests(unittest.TestCase):
    def test_wrapper_is_thin_and_does_not_build_shell_command_strings(self) -> None:
        wrapper = (INSTALLER_PATH.parent / "install-workspace.ps1").read_text(encoding="utf-8")

        self.assertIn("$PSScriptRoot", wrapper)
        self.assertIn("@InstallerArguments", wrapper)
        self.assertIn("sys.version_info >= (3, 11)", wrapper)
        self.assertNotIn("Invoke-Expression", wrapper)
        self.assertNotIn("Start-Process", wrapper)


class CliDryRunTests(unittest.TestCase):
    def test_real_cli_dry_run_validates_full_workspace_without_installing(self) -> None:
        fixture = WorkspaceFixture()
        self.addCleanup(fixture.close)

        result = subprocess.run(
            [
                sys.executable,
                str(INSTALLER_PATH),
                "--workspace-root",
                str(fixture.root),
                "--dry-run",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install module1 editable", result.stdout)
        self.assertIn("install unified_cli editable", result.stdout)
        self.assertIn("playwright", result.stdout)
        self.assertIn("goad", result.stdout)
        self.assertIn("doctor", result.stdout)
        self.assertIn("Dry run: no commands were executed", result.stdout)
        self.assertFalse((fixture.root / ".venv").exists())


if __name__ == "__main__":
    unittest.main()
