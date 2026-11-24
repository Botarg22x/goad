"""Artifact-agnostic service/API for sequential pipeline orchestration.

Planning is side-effect free. Execution delegates to an injectable stage
executor; this module itself implements no authentication or network protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TextIO
from uuid import uuid4
import argparse
import json
import os
import sys
import tempfile

from . import __version__
from .components import COMPONENTS, STAGE_ORDER
from .config import ConfigError, RunConfig, load_config
from .delegation import DelegationError, delegate


class OrchestrationError(RuntimeError):
    """A plan or its manifest cannot be created."""


@dataclass(frozen=True, slots=True)
class PlannedStage:
    name: str
    module: str
    enabled: bool
    argv: tuple[str, ...]
    cwd: Path | None


@dataclass(frozen=True, slots=True)
class RunPlan:
    run_id: str
    created_at: datetime
    config_path: Path
    output_dir: Path
    stages: tuple[PlannedStage, ...]
    metadata: Mapping[str, Any]

    @property
    def manifest_path(self) -> Path:
        return self.output_dir / self.run_id / "manifest.json"

    @property
    def run_dir(self) -> Path:
        return self.output_dir / self.run_id


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    plan: RunPlan
    manifest_path: Path
    status: str
    exit_code: int
    failed_stage: str | None
    document: Mapping[str, Any]


class StageExecutor(Protocol):
    def __call__(self, stage: PlannedStage) -> int:
        """Execute one planned stage and return its process-style exit code."""


class InProcessStageExecutor:
    """Default executor that invokes the registered module's ``main(argv)``."""

    def __init__(self, *, stderr: TextIO = sys.stderr) -> None:
        self._stderr = stderr

    def __call__(self, stage: PlannedStage) -> int:
        previous_cwd = Path.cwd()
        changed_cwd = stage.cwd is not None
        try:
            if stage.cwd is not None:
                if not stage.cwd.is_dir():
                    raise OrchestrationError(
                        f"working directory for stage {stage.name!r} does not exist: "
                        f"{stage.cwd}"
                    )
                os.chdir(stage.cwd)
            # A fresh list preserves tokens while allowing component parsers to
            # mutate their own argv without mutating the immutable run plan.
            return delegate(
                COMPONENTS[stage.name], list(stage.argv), stderr=self._stderr
            )
        finally:
            if changed_cwd:
                os.chdir(previous_cwd)


def _new_run_id(now: datetime) -> str:
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"


def _validate_run_id(run_id: str) -> None:
    if not run_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in run_id):
        raise OrchestrationError(
            "run_id must contain only ASCII letters, digits, '-' and '_'"
        )


def _expand_template(value: str, *, run_id: str, run_dir: Path) -> str:
    """Expand only goad placeholders, leaving module-specific braces alone."""

    native_run_dir = str(run_dir)
    return (
        value.replace("{run_dir}/", native_run_dir + os.sep)
        .replace("{run_dir}\\", native_run_dir + os.sep)
        .replace("{run_dir}", native_run_dir)
        .replace("{run_id}", run_id)
    )


class OrchestrationService:
    """Public service seam for planning a pipeline without executing it."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[datetime], str] = _new_run_id,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory

    def plan(self, config_path: str | Path, *, run_id: str | None = None) -> RunPlan:
        path = Path(config_path).resolve()
        config: RunConfig = load_config(path)
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        else:
            now = now.astimezone(timezone.utc)
        selected_id = run_id or self._id_factory(now)
        _validate_run_id(selected_id)
        run_dir = config.output_dir / selected_id

        stages = tuple(
            PlannedStage(
                name=name,
                module=COMPONENTS[name].module,
                enabled=config.stages[name].enabled,
                argv=tuple(
                    _expand_template(argument, run_id=selected_id, run_dir=run_dir)
                    for argument in config.stages[name].args
                ),
                cwd=self._resolve_stage_cwd(
                    config.stages[name].cwd,
                    config_dir=path.parent,
                    run_id=selected_id,
                    run_dir=run_dir,
                ),
            )
            for name in STAGE_ORDER
        )
        return RunPlan(
            run_id=selected_id,
            created_at=now,
            config_path=path,
            output_dir=config.output_dir,
            stages=stages,
            metadata=config.metadata,
        )

    @staticmethod
    def _resolve_stage_cwd(
        cwd: str | None,
        *,
        config_dir: Path,
        run_id: str,
        run_dir: Path,
    ) -> Path | None:
        if cwd is None:
            return None
        expanded = Path(_expand_template(cwd, run_id=run_id, run_dir=run_dir))
        if not expanded.is_absolute():
            expanded = config_dir / expanded
        return expanded.resolve()

    def write_manifest(
        self,
        plan: RunPlan,
        destination: str | Path | None = None,
    ) -> Path:
        path = Path(destination).resolve() if destination else plan.manifest_path
        document = manifest_document(plan)
        self._write_document(path, document)
        return path

    def _write_document(self, path: Path, document: Mapping[str, Any]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump(document, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_name, path)
            except BaseException:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                raise
        except OSError as exc:
            raise OrchestrationError(f"cannot write manifest {path}: {exc}") from exc

    def execute(
        self,
        plan: RunPlan,
        *,
        destination: str | Path | None = None,
        executor: StageExecutor | None = None,
    ) -> ExecutionOutcome:
        """Execute enabled stages in order and checkpoint an atomic manifest.

        The injected executor owns module execution. The orchestration service
        only controls ordering, stop-on-failure semantics, and durable state.
        """

        path = Path(destination).resolve() if destination else plan.manifest_path
        selected_executor = executor or InProcessStageExecutor()
        document = manifest_document(plan)
        document["status"] = "running"
        document["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            plan.run_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OrchestrationError(
                f"cannot create run directory {plan.run_dir}: {exc}"
            ) from exc
        self._write_document(path, document)

        for index, stage in enumerate(plan.stages):
            stage_document = document["stages"][index]
            if not stage.enabled:
                continue

            stage_document["status"] = "running"
            stage_document["started_at"] = datetime.now(timezone.utc).isoformat()
            self._write_document(path, document)
            error: str | None = None
            try:
                exit_code = selected_executor(stage)
                if not isinstance(exit_code, int):
                    raise OrchestrationError(
                        f"executor for stage {stage.name!r} returned "
                        f"{type(exit_code).__name__}, expected int"
                    )
            except (Exception, SystemExit) as exc:
                exit_code = 127 if isinstance(exc, DelegationError) else 1
                error = str(exc) or type(exc).__name__

            stage_document["exit_code"] = exit_code
            stage_document["finished_at"] = datetime.now(timezone.utc).isoformat()
            if error is not None:
                stage_document["error"] = error

            if exit_code != 0:
                stage_document["status"] = "failed"
                document["status"] = "failed"
                document["exit_code"] = exit_code
                document["failed_stage"] = stage.name
                document["finished_at"] = datetime.now(timezone.utc).isoformat()
                for later in document["stages"][index + 1 :]:
                    if later["status"] == "planned":
                        later["status"] = "skipped"
                self._write_document(path, document)
                return ExecutionOutcome(
                    plan=plan,
                    manifest_path=path,
                    status="failed",
                    exit_code=exit_code,
                    failed_stage=stage.name,
                    document=document,
                )

            stage_document["status"] = "succeeded"
            self._write_document(path, document)

        document["status"] = "succeeded"
        document["exit_code"] = 0
        document["finished_at"] = datetime.now(timezone.utc).isoformat()
        self._write_document(path, document)
        return ExecutionOutcome(
            plan=plan,
            manifest_path=path,
            status="succeeded",
            exit_code=0,
            failed_stage=None,
            document=document,
        )


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict | Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def manifest_document(plan: RunPlan) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tool": {"name": "goad", "version": __version__},
        "run_id": plan.run_id,
        "created_at": plan.created_at.isoformat(),
        "status": "planned",
        "config_path": str(plan.config_path),
        "output_dir": str(plan.output_dir),
        "metadata": _json_safe(plan.metadata),
        "stages": [
            {
                "name": stage.name,
                "module": stage.module,
                "enabled": stage.enabled,
                "status": "planned" if stage.enabled else "disabled",
                "argv": list(stage.argv),
                "cwd": str(stage.cwd) if stage.cwd is not None else None,
                "exit_code": None,
            }
            for stage in plan.stages
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goad run",
        description="Validate and execute a configured module pipeline.",
    )
    parser.add_argument("config", help="path to a TOML pipeline configuration")
    parser.add_argument("--run-id", help="stable run identifier for reproducible tooling")
    parser.add_argument("--manifest", help="override the manifest destination")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate and display the plan without executing or writing a manifest",
    )
    parser.add_argument("--json", action="store_true", help="print the plan as JSON")
    return parser


def run_main(
    argv: list[str],
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    service: OrchestrationService | None = None,
) -> int:
    args = _parser().parse_args(argv)
    orchestrator = service or OrchestrationService()
    try:
        plan = orchestrator.plan(args.config, run_id=args.run_id)
        document = manifest_document(plan)
        if args.validate_only:
            if args.json:
                json.dump(document, stdout, ensure_ascii=False, indent=2)
                stdout.write("\n")
            else:
                enabled_count = sum(stage.enabled for stage in plan.stages)
                print(
                    f"Configuration valid: {enabled_count} enabled stage(s), "
                    f"run_id={plan.run_id}",
                    file=stdout,
                )
            return 0

        outcome = orchestrator.execute(
            plan,
            destination=args.manifest,
            executor=InProcessStageExecutor(stderr=stderr),
        )
    except (ConfigError, OrchestrationError) as exc:
        print(f"goad run: error: {exc}", file=stderr)
        return 2

    if args.json:
        json.dump(outcome.document, stdout, ensure_ascii=False, indent=2)
        stdout.write("\n")
    else:
        if outcome.status == "succeeded":
            print(f"Pipeline succeeded: {outcome.manifest_path}", file=stdout)
        else:
            print(
                f"Pipeline failed at {outcome.failed_stage!r} "
                f"with exit code {outcome.exit_code}: {outcome.manifest_path}",
                file=stderr,
            )
    return outcome.exit_code

