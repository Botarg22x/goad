#!/usr/bin/env python3
"""Create a workspace virtual environment and install local projects editable.

The script intentionally uses only the Python standard library and executes
commands as argument lists (never through a shell).  It is meant to live next
to the project directories in the GOAD workspace.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


MIN_PYTHON = (3, 11)


class InstallError(RuntimeError):
    """A preflight or installation error that can be shown to the user."""


@dataclass(frozen=True)
class ProjectSpec:
    key: str
    directory: str
    distribution: str
    extras: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()

    def matches(self, value: str) -> bool:
        normalized = value.strip().casefold()
        return normalized in {
            self.key.casefold(),
            self.directory.casefold(),
            self.distribution.casefold(),
            *(alias.casefold() for alias in self.aliases),
        }


PROJECTS: tuple[ProjectSpec, ...] = (
    ProjectSpec(
        key="module1",
        directory="pass_gen_module_1",
        distribution="password-generator",
        aliases=("passgen",),
    ),
    ProjectSpec(
        key="module2",
        directory="login_gen_module_2",
        distribution="logingen",
        extras=("browser", "pdf"),
        aliases=("logingen",),
    ),
    ProjectSpec(
        key="module3",
        directory="discovery_module_3",
        distribution="pointfinder",
        aliases=("pointfinder",),
    ),
    ProjectSpec(
        key="module4",
        directory="check_module_4",
        distribution="authchecker",
        aliases=("credential-auditor", "credential_auditor"),
    ),
    ProjectSpec(
        key="unified_cli",
        directory="unified_cli",
        distribution="goad",
        aliases=("cli",),
    ),
)


@dataclass(frozen=True)
class Command:
    purpose: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class InstallPlan:
    workspace_root: Path
    venv_dir: Path
    venv_python: Path
    projects: tuple[ProjectSpec, ...]
    create_environment: Command | None
    install_commands: tuple[Command, ...]
    browser_command: Command | None = None
    doctor_command: Command | None = None

    @property
    def commands(self) -> tuple[Command, ...]:
        commands: list[Command] = []
        if self.create_environment is not None:
            commands.append(self.create_environment)
        commands.extend(self.install_commands)
        if self.browser_command is not None:
            commands.append(self.browser_command)
        if self.doctor_command is not None:
            commands.append(self.doctor_command)
        return tuple(commands)


CommandRunner = Callable[[Sequence[str]], None]
VersionProbe = Callable[[Path], tuple[int, int, int]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create/reuse a workspace .venv and install the GOAD projects "
            "as independent editable packages."
        )
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory containing all project folders (default: directory of this script).",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        default=Path(".venv"),
        help="Virtual environment path, relative to workspace root unless absolute (default: .venv).",
    )
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        metavar="NAME",
        help="Install only this project; repeatable. Accepts module1..module4, unified_cli, folder, or package name.",
    )
    parser.add_argument(
        "--skip-project",
        action="append",
        default=[],
        metavar="NAME",
        help="Exclude a project from the selected set; repeatable.",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Do not install optional login module browser/PDF extras or a Playwright browser.",
    )
    parser.add_argument(
        "--skip-playwright-browser",
        action="store_true",
        help="Install login module extras, but do not download Playwright Chromium.",
    )
    parser.add_argument(
        "--skip-doctor",
        action="store_true",
        help="Do not run the final 'goad doctor' workspace check.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate paths and print commands without creating or installing anything.",
    )
    parser.add_argument(
        "--list-projects",
        action="store_true",
        help="Show known project names and exit.",
    )
    return parser


def resolve_projects(
    requested: Iterable[str] = (),
    skipped: Iterable[str] = (),
    projects: tuple[ProjectSpec, ...] = PROJECTS,
) -> tuple[ProjectSpec, ...]:
    requested_values = tuple(value for value in requested if value.strip())
    skipped_values = tuple(value for value in skipped if value.strip())

    if requested_values:
        requested_keys = {_resolve_project(value, projects).key for value in requested_values}
        # Keep dependency-friendly canonical order regardless of CLI argument order.
        selected = [project for project in projects if project.key in requested_keys]
    else:
        selected = list(projects)
    skipped_specs = {_resolve_project(value, projects).key for value in skipped_values}

    result: list[ProjectSpec] = []
    for project in selected:
        if project.key in skipped_specs or project in result:
            continue
        result.append(project)
    if not result:
        raise InstallError("No projects remain after applying the selection filters.")
    return tuple(result)


def _resolve_project(value: str, projects: tuple[ProjectSpec, ...]) -> ProjectSpec:
    for project in projects:
        if project.matches(value):
            return project
    known = ", ".join(project.key for project in projects)
    raise InstallError(f"Unknown project {value!r}. Known project keys: {known}.")


def create_install_plan(
    workspace_root: Path,
    venv: Path,
    selected_projects: tuple[ProjectSpec, ...],
    *,
    bootstrap_python: Path,
    minimal: bool = False,
    install_playwright_browser: bool = True,
    run_doctor: bool = True,
    os_name: str = os.name,
) -> InstallPlan:
    root = workspace_root.expanduser().resolve()
    if not root.is_dir():
        raise InstallError(f"Workspace root does not exist or is not a directory: {root}")

    project_paths = _preflight_project_paths(root, selected_projects)
    environment = _resolve_venv_path(root, venv)
    _validate_venv_target(root, environment)

    environment_exists = environment.exists()
    environment_python = venv_python_path(environment, os_name=os_name)
    if environment_exists:
        if not environment.is_dir():
            raise InstallError(f"Virtual environment path is not a directory: {environment}")
        if not environment_python.is_file():
            raise InstallError(
                f"Existing virtual environment is incomplete; interpreter not found: {environment_python}"
            )

    create_environment = None
    if not environment_exists:
        create_environment = Command(
            purpose="create virtual environment",
            argv=(str(bootstrap_python), "-m", "venv", str(environment)),
        )

    install_commands: list[Command] = []
    for project, project_path in zip(selected_projects, project_paths, strict=True):
        extras = () if minimal else project.extras
        editable_target = editable_requirement(project_path, extras)
        install_commands.append(
            Command(
                purpose=f"install {project.key} editable",
                argv=(
                    str(environment_python),
                    "-m",
                    "pip",
                    "install",
                    "--editable",
                    editable_target,
                ),
            )
        )

    selected_keys = {project.key for project in selected_projects}
    browser_command = None
    if (
        "module2" in selected_keys
        and not minimal
        and install_playwright_browser
    ):
        browser_command = Command(
            purpose="install Playwright Chromium",
            argv=(str(environment_python), "-m", "playwright", "install", "chromium"),
        )

    doctor_command = None
    if "unified_cli" in selected_keys and run_doctor:
        doctor_command = Command(
            purpose="verify workspace with goad doctor",
            argv=(str(venv_console_script_path(environment, "goad", os_name=os_name)), "doctor"),
        )

    return InstallPlan(
        workspace_root=root,
        venv_dir=environment,
        venv_python=environment_python,
        projects=selected_projects,
        create_environment=create_environment,
        install_commands=tuple(install_commands),
        browser_command=browser_command,
        doctor_command=doctor_command,
    )


def _preflight_project_paths(
    workspace_root: Path,
    projects: tuple[ProjectSpec, ...],
) -> tuple[Path, ...]:
    paths: list[Path] = []
    problems: list[str] = []
    for project in projects:
        path = (workspace_root / project.directory).resolve()
        pyproject_path = path / "pyproject.toml"
        if not path.is_dir():
            problems.append(f"missing directory for {project.key}: {path}")
        elif not pyproject_path.is_file():
            problems.append(f"missing pyproject.toml for {project.key}: {path}")
        else:
            try:
                with pyproject_path.open("rb") as file:
                    metadata = tomllib.load(file)
            except (OSError, tomllib.TOMLDecodeError) as error:
                problems.append(f"invalid pyproject.toml for {project.key}: {error}")
            else:
                project_metadata = metadata.get("project")
                actual_name = (
                    str(project_metadata.get("name", "")).strip()
                    if isinstance(project_metadata, dict)
                    else ""
                )
                if _canonical_distribution_name(actual_name) != _canonical_distribution_name(
                    project.distribution
                ):
                    problems.append(
                        f"unexpected distribution for {project.key}: expected "
                        f"{project.distribution!r}, found {actual_name or '<missing>'!r}"
                    )
        paths.append(path)
    if problems:
        details = "\n  - ".join(problems)
        raise InstallError(f"Workspace preflight failed:\n  - {details}")
    return tuple(paths)


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _resolve_venv_path(workspace_root: Path, value: Path) -> Path:
    value = value.expanduser()
    if not value.is_absolute():
        value = workspace_root / value
    return value.resolve()


def _validate_venv_target(workspace_root: Path, venv_dir: Path) -> None:
    if venv_dir == workspace_root:
        raise InstallError("The virtual environment cannot be the workspace root itself.")
    for project in PROJECTS:
        project_dir = (workspace_root / project.directory).resolve()
        if _is_relative_to(venv_dir, project_dir):
            raise InstallError(
                f"The virtual environment cannot be created inside project {project.key}: {venv_dir}"
            )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def venv_python_path(venv_dir: Path, *, os_name: str = os.name) -> Path:
    if os_name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def venv_console_script_path(venv_dir: Path, command: str, *, os_name: str = os.name) -> Path:
    if os_name == "nt":
        return venv_dir / "Scripts" / f"{command}.exe"
    return venv_dir / "bin" / command


def editable_requirement(project_path: Path, extras: tuple[str, ...]) -> str:
    path = str(project_path)
    if not extras:
        return path
    return f"{path}[{','.join(extras)}]"


def execute_plan(
    plan: InstallPlan,
    *,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
    version_probe: VersionProbe | None = None,
    stream: TextIO = sys.stdout,
) -> None:
    runner = runner or run_command
    version_probe = version_probe or probe_python_version

    print(f"Workspace: {plan.workspace_root}", file=stream)
    print(f"Virtual environment: {plan.venv_dir}", file=stream)
    print(
        "Projects: " + ", ".join(project.key for project in plan.projects),
        file=stream,
    )
    for command in plan.commands:
        print(f"[{command.purpose}] {format_command(command.argv)}", file=stream)

    if dry_run:
        print("Dry run: no commands were executed.", file=stream)
        return

    if plan.create_environment is not None:
        runner(plan.create_environment.argv)
        if not plan.venv_python.is_file():
            raise InstallError(
                "Virtual environment command completed, but its Python interpreter "
                f"was not found: {plan.venv_python}"
            )

    target_version = version_probe(plan.venv_python)
    ensure_supported_version(target_version, label=str(plan.venv_python))

    for command in plan.install_commands:
        runner(command.argv)
    if plan.browser_command is not None:
        runner(plan.browser_command.argv)
    if plan.doctor_command is not None:
        runner(plan.doctor_command.argv)
    print("Workspace installation completed.", file=stream)


def run_command(argv: Sequence[str]) -> None:
    subprocess.run(list(argv), check=True, shell=False)


def probe_python_version(executable: Path) -> tuple[int, int, int]:
    try:
        result = subprocess.run(
            [
                str(executable),
                "-c",
                "import sys; print('.'.join(map(str, sys.version_info[:3])))",
            ],
            check=True,
            shell=False,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise InstallError(f"Could not run virtual-environment Python {executable}: {error}") from error
    try:
        major, minor, patch = (int(part) for part in result.stdout.strip().split(".", 2))
    except (TypeError, ValueError) as error:
        raise InstallError(
            f"Could not determine Python version from {executable}: {result.stdout!r}"
        ) from error
    return major, minor, patch


def ensure_supported_version(
    version: tuple[int, ...],
    *,
    label: str = "Python",
) -> None:
    if tuple(version[:2]) < MIN_PYTHON:
        found = ".".join(str(part) for part in version[:3])
        required = ".".join(str(part) for part in MIN_PYTHON)
        raise InstallError(f"{label} {found} is unsupported; Python >= {required} is required.")


def format_command(argv: Sequence[str], *, os_name: str = os.name) -> str:
    values = [str(value) for value in argv]
    if os_name == "nt":
        return subprocess.list2cmdline(values)
    return shlex.join(values)


def print_projects(stream: TextIO = sys.stdout) -> None:
    for project in PROJECTS:
        extras = f" extras={','.join(project.extras)}" if project.extras else ""
        print(
            f"{project.key:11} {project.directory} ({project.distribution}){extras}",
            file=stream,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_projects:
        print_projects()
        return 0

    try:
        ensure_supported_version(sys.version_info[:3], label=sys.executable)
        selected = resolve_projects(args.project, args.skip_project)
        plan = create_install_plan(
            args.workspace_root,
            args.venv,
            selected,
            bootstrap_python=Path(sys.executable),
            minimal=args.minimal,
            install_playwright_browser=not args.skip_playwright_browser,
            run_doctor=not args.skip_doctor,
        )
        execute_plan(plan, dry_run=args.dry_run)
    except InstallError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"error: command failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
