"""Strict TOML configuration parsing for a planned multi-stage run."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
import tomllib

from .components import STAGE_ORDER


SCHEMA_VERSION = 1


class ConfigError(ValueError):
    """The run configuration is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class StageConfig:
    enabled: bool = True
    args: tuple[str, ...] = ()
    cwd: str | None = None


@dataclass(frozen=True, slots=True)
class RunConfig:
    schema_version: int
    output_dir: Path
    stages: Mapping[str, StageConfig]
    metadata: Mapping[str, Any] = field(default_factory=dict)


def _reject_unknown(mapping: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigError(f"unknown {context} key(s): {', '.join(unknown)}")


def _parse_stage(name: str, raw: Any) -> StageConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"stages.{name} must be a table")
    _reject_unknown(raw, {"enabled", "args", "cwd"}, f"stages.{name}")

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"stages.{name}.enabled must be a boolean")

    args = raw.get("args", [])
    if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
        raise ConfigError(f"stages.{name}.args must be an array of strings")

    cwd = raw.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
        raise ConfigError(f"stages.{name}.cwd must be a non-empty string")
    return StageConfig(enabled=enabled, args=tuple(args), cwd=cwd)


def parse_config(raw: Mapping[str, Any], *, base_dir: Path) -> RunConfig:
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be a table")
    _reject_unknown(raw, {"schema_version", "output_dir", "stages", "metadata"}, "top-level")

    schema_version = raw.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise ConfigError(
            f"schema_version must be {SCHEMA_VERSION}, got {schema_version!r}"
        )

    output_value = raw.get("output_dir", "runs")
    if not isinstance(output_value, str) or not output_value.strip():
        raise ConfigError("output_dir must be a non-empty string")
    output_dir = Path(output_value)
    if not output_dir.is_absolute():
        output_dir = base_dir / output_dir
    output_dir = output_dir.resolve()

    stages_raw = raw.get("stages", {})
    if not isinstance(stages_raw, dict):
        raise ConfigError("stages must be a table")
    unknown_stages = sorted(set(stages_raw) - set(STAGE_ORDER))
    if unknown_stages:
        raise ConfigError(f"unknown stage(s): {', '.join(unknown_stages)}")

    stages = {
        name: _parse_stage(name, stages_raw.get(name, {"enabled": False}))
        for name in STAGE_ORDER
    }
    if not any(stage.enabled for stage in stages.values()):
        raise ConfigError("at least one stage must be enabled")

    metadata_raw = raw.get("metadata", {})
    if not isinstance(metadata_raw, dict):
        raise ConfigError("metadata must be a table")

    return RunConfig(
        schema_version=schema_version,
        output_dir=output_dir,
        stages=MappingProxyType(stages),
        metadata=MappingProxyType(dict(metadata_raw)),
    )


def load_config(path: str | Path) -> RunConfig:
    config_path = Path(path).resolve()
    try:
        with config_path.open("rb") as stream:
            raw = tomllib.load(stream)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {config_path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration {config_path}: {exc}") from exc
    return parse_config(raw, base_dir=config_path.parent)

