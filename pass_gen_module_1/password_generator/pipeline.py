"""Planning, streaming, deduplication and atomic output for passgen."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import errno
from itertools import zip_longest
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from typing import Iterator, Mapping, TextIO

from .atomic import publish_file
from .config import ConfigError, GeneratorConfig, WordlistSpec
from .limits import MAX_CANDIDATE_LENGTH
from .mutations import (
    COMPOSITIONAL_EFFECTS,
    EFFECT_ALWAYS,
    EFFECT_CAPITALIZE_FIRST,
    EFFECT_NEVER,
    MutationEngine,
    mutation_effect_kind,
    value_is_unchanged_for_effect,
)
from .patterns import (
    CharsetToken,
    CompiledPattern,
    LiteralToken,
    WordlistToken,
    compile_pattern,
)
from .streams import EncodedStreamWriter


@dataclass(frozen=True)
class PlannedPattern:
    index: int
    value: str
    compiled: CompiledPattern
    apply_mutations: bool
    base_candidates: int
    estimated_candidates: int
    estimate_is_upper_bound: bool


@dataclass(frozen=True)
class GenerationPlan:
    wordlist_counts: dict[str, int]
    paired_wordlist_counts: dict[tuple[str, str], int]
    patterns: tuple[PlannedPattern, ...]
    estimated_candidates: int
    estimate_is_upper_bound: bool


@dataclass
class GenerationStats:
    base_candidates: int = 0
    mutation_candidates: int = 0
    filtered_candidates: int = 0
    duplicate_candidates: int = 0
    written_candidates: int = 0
    existing_candidates: int = 0
    existing_duplicate_candidates: int = 0


class GenerationInterrupted(KeyboardInterrupt):
    """A stopped run with a recoverable, explicitly incomplete output file."""

    def __init__(
        self,
        partial_path: Path | None,
        written_candidates: int,
        save_error: str | None = None,
    ) -> None:
        super().__init__()
        self.partial_path = partial_path
        self.written_candidates = written_candidates
        self.save_error = save_error


@dataclass(frozen=True)
class _WordlistPlanStats:
    count: int
    max_length: int
    unchanged_by_effect: dict[str, int]


def _analyze_wordlist(
    wordlist: WordlistSpec,
    effects: frozenset[str],
) -> _WordlistPlanStats:
    unchanged = {effect: 0 for effect in effects}
    count = 0
    max_length = 0
    for word in wordlist.iter_words():
        count += 1
        max_length = max(max_length, len(word))
        for effect in effects:
            if value_is_unchanged_for_effect(word, effect):
                unchanged[effect] += 1
    return _WordlistPlanStats(
        count=count,
        max_length=max_length,
        unchanged_by_effect=unchanged,
    )


def _count_paired_rows(left: WordlistSpec, right: WordlistSpec) -> int:
    missing = object()
    count = 0
    for left_row, right_row in zip_longest(
        left.iter_rows(), right.iter_rows(), fillvalue=missing
    ):
        if left_row is missing or right_row is missing:
            raise ConfigError(
                f"Попарные словари {left.name!r} и {right.name!r} имеют разное "
                "число физических строк; исправьте файлы или --wl-max-lines"
            )
        if left_row is not None and right_row is not None:
            count += 1
    return count


def _count_compositional_unchanged(
    compiled: CompiledPattern,
    effect: str,
    wordlist_stats: dict[str, _WordlistPlanStats],
) -> int:
    unchanged_candidates = 1
    seen_wordlists: set[str] = set()
    for token in compiled.tokens:
        if isinstance(token, LiteralToken):
            if not value_is_unchanged_for_effect(token.value, effect):
                return 0
        elif isinstance(token, CharsetToken):
            unchanged_candidates *= sum(
                value_is_unchanged_for_effect(character, effect)
                for character in token.characters
            )
        elif token.name not in seen_wordlists:
            unchanged_candidates *= wordlist_stats[token.name].unchanged_by_effect[effect]
            seen_wordlists.add(token.name)
    return unchanged_candidates


def _count_first_character_unchanged(
    compiled: CompiledPattern,
    base_count: int,
    wordlist_stats: dict[str, _WordlistPlanStats],
) -> int:
    if base_count == 0:
        return 0
    first_token = compiled.tokens[0]
    if isinstance(first_token, LiteralToken):
        return (
            base_count
            if value_is_unchanged_for_effect(
                first_token.value,
                EFFECT_CAPITALIZE_FIRST,
            )
            else 0
        )
    if isinstance(first_token, CharsetToken):
        unchanged_choices = sum(
            value_is_unchanged_for_effect(
                character,
                EFFECT_CAPITALIZE_FIRST,
            )
            for character in first_token.characters
        )
        return base_count // len(first_token.characters) * unchanged_choices
    stats = wordlist_stats[first_token.name]
    if stats.count == 0:
        return 0
    return (
        base_count
        // stats.count
        * stats.unchanged_by_effect[EFFECT_CAPITALIZE_FIRST]
    )


def _estimate_independent_mutations(
    config: GeneratorConfig,
    compiled: CompiledPattern,
    base_count: int,
    wordlist_stats: dict[str, _WordlistPlanStats],
    effect_multiplicities: Mapping[str, int],
) -> tuple[int, bool]:
    mutations = config.mutations
    if mutations is None:
        return base_count, False

    estimate = base_count if mutations.include_original else 0
    is_upper_bound = False
    for effect, multiplicity in effect_multiplicities.items():
        if effect == EFFECT_NEVER:
            changed = 0
        elif effect == EFFECT_ALWAYS:
            changed = base_count
        elif effect in COMPOSITIONAL_EFFECTS:
            unchanged = _count_compositional_unchanged(
                compiled,
                effect,
                wordlist_stats,
            )
            changed = base_count - unchanged
        elif effect == EFFECT_CAPITALIZE_FIRST:
            unchanged = _count_first_character_unchanged(
                compiled,
                base_count,
                wordlist_stats,
            )
            changed = base_count - unchanged
        else:
            changed = base_count
            is_upper_bound = True
        estimate += changed * multiplicity
    return estimate, is_upper_bound


def build_plan(config: GeneratorConfig) -> GenerationPlan:
    _validate_output(config)
    compiled_patterns = [
        compile_pattern(
            pattern.value,
            wordlists=config.wordlists,
            charsets=config.charsets,
            zip_wordlists=config.generation.zip_wordlists,
        )
        for pattern in config.patterns
    ]
    for left, right in config.generation.zip_wordlists:
        if not any(
            left in compiled.wordlist_names and right in compiled.wordlist_names
            for compiled in compiled_patterns
        ):
            raise ConfigError(
                f"Попарные словари {left!r} и {right!r} "
                "не используются вместе ни в одной маске"
            )
    referenced_names: list[str] = []
    for compiled in compiled_patterns:
        for name in compiled.wordlist_names:
            if name not in referenced_names:
                referenced_names.append(name)
    mutation_engine = MutationEngine(config.mutations) if config.mutations else None
    effect_multiplicities: Counter[str] = Counter()
    analyzable_effects: frozenset[str] = frozenset()
    if config.mutations is not None and config.mutations.mode == "independent":
        effect_multiplicities.update(
            mutation_effect_kind(operation)
            for operation in config.mutations.operations
        )
        analyzable_effects = frozenset(
            effect
            for effect in effect_multiplicities
            if (
                effect in COMPOSITIONAL_EFFECTS
                or effect == EFFECT_CAPITALIZE_FIRST
            )
        )
    wordlist_stats = {
        name: _analyze_wordlist(config.wordlists[name], analyzable_effects)
        for name in referenced_names
    }
    wordlist_counts = {
        name: stats.count
        for name, stats in wordlist_stats.items()
    }
    paired_wordlist_counts = {
        (left, right): _count_paired_rows(
            config.wordlists[left], config.wordlists[right]
        )
        for left, right in config.generation.zip_wordlists
    }
    wordlist_max_lengths = {
        name: stats.max_length
        for name, stats in wordlist_stats.items()
    }

    patterns: list[PlannedPattern] = []
    for index, (spec, compiled) in enumerate(zip(config.patterns, compiled_patterns), start=1):
        base_count = compiled.cardinality(wordlist_counts, paired_wordlist_counts)
        maximum_base_length = compiled.maximum_candidate_length(wordlist_max_lengths)
        if base_count and maximum_base_length > MAX_CANDIDATE_LENGTH:
            raise ConfigError(
                f"Pattern {index} can render a base candidate of "
                f"{maximum_base_length:,} characters; the hard safety limit is "
                f"{MAX_CANDIDATE_LENGTH:,}"
            )
        if not spec.apply_mutations:
            estimated_count = base_count
            is_upper_bound = False
        elif (
            config.mutations is not None
            and any(len(group) > 1 for group in compiled.binding_groups)
        ):
            # Per-wordlist no-op counts cannot be multiplied for paired rows.
            estimated_count = base_count * mutation_engine.estimate_factor()
            is_upper_bound = bool(config.mutations.operations)
        elif config.mutations is not None and config.mutations.mode == "independent":
            estimated_count, is_upper_bound = _estimate_independent_mutations(
                config,
                compiled,
                base_count,
                wordlist_stats,
                effect_multiplicities,
            )
        else:
            factor = mutation_engine.estimate_factor() if mutation_engine else 1
            estimated_count = base_count * factor
            is_upper_bound = bool(config.mutations and config.mutations.operations)
        patterns.append(
            PlannedPattern(
                index=index,
                value=spec.value,
                compiled=compiled,
                apply_mutations=spec.apply_mutations,
                base_candidates=base_count,
                estimated_candidates=estimated_count,
                estimate_is_upper_bound=is_upper_bound,
            )
        )
    return GenerationPlan(
        wordlist_counts=wordlist_counts,
        paired_wordlist_counts=paired_wordlist_counts,
        patterns=tuple(patterns),
        estimated_candidates=sum(pattern.estimated_candidates for pattern in patterns),
        estimate_is_upper_bound=any(
            pattern.estimate_is_upper_bound for pattern in patterns
        ),
    )


def iter_candidates(
    config: GeneratorConfig,
    plan: GenerationPlan,
    stats: GenerationStats,
) -> Iterator[str]:
    mutation_engine = MutationEngine(config.mutations) if config.mutations else None
    for planned in plan.patterns:
        for base_candidate in planned.compiled.generate(config.wordlists):
            stats.base_candidates += 1
            if planned.apply_mutations:
                if mutation_engine is None:
                    raise ConfigError(
                        f"Pattern {planned.index} requests mutations, but none are configured"
                    )
                variants = mutation_engine.mutate(base_candidate)
            else:
                variants = iter((base_candidate,))
            for candidate in variants:
                stats.mutation_candidates += 1
                if len(candidate) > MAX_CANDIDATE_LENGTH:
                    raise ConfigError(
                        "Candidate exceeds the hard safety limit "
                        f"({MAX_CANDIDATE_LENGTH:,} characters)"
                    )
                if any(character in candidate for character in ("\x00", "\r", "\n")):
                    raise ConfigError(
                        f"Pattern {planned.index} produced a candidate with NUL/CR/LF"
                    )
                if not config.result_filters.matches(candidate):
                    stats.filtered_candidates += 1
                    continue
                yield candidate


class DiskDeduplicator:
    def __init__(self, directory: Path | None = None) -> None:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=".passgen-dedup-",
            suffix=".sqlite3",
            dir=str(directory) if directory else None,
        )
        os.close(descriptor)
        self._path = Path(raw_path)
        try:
            self._connection = sqlite3.connect(self._path)
            self._connection.execute("PRAGMA journal_mode=OFF")
            self._connection.execute("PRAGMA synchronous=OFF")
            self._connection.execute("CREATE TABLE seen (value TEXT PRIMARY KEY)")
        except sqlite3.Error as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._path.unlink(missing_ok=True)
            raise ConfigError(f"Cannot initialize disk deduplication: {exc}") from exc
        except BaseException:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._path.unlink(missing_ok=True)
            raise
        self._pending = 0

    def add(self, value: str) -> bool:
        try:
            cursor = self._connection.execute(
                "INSERT OR IGNORE INTO seen(value) VALUES (?)",
                (value,),
            )
            self._pending += 1
            if self._pending >= 1000:
                self._connection.commit()
                self._pending = 0
            return cursor.rowcount == 1
        except sqlite3.Error as exc:
            raise ConfigError(f"Disk deduplication failed: {exc}") from exc

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is None:
            return
        self._connection = None
        close_error: sqlite3.Error | None = None
        try:
            try:
                connection.close()
            except sqlite3.Error as exc:
                close_error = exc
        finally:
            try:
                self._path.unlink(missing_ok=True)
            except OSError as exc:
                if close_error is None:
                    raise ConfigError(
                        f"Cannot remove temporary deduplication database: {exc}"
                    ) from exc
        if close_error is not None:
            raise ConfigError(f"Cannot close disk deduplication: {close_error}") from close_error


@dataclass(frozen=True)
class _OutputSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int
    mode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "_OutputSnapshot":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            modified_ns=value.st_mtime_ns,
            mode=value.st_mode,
        )


class _OutputLock:
    """A stable sibling advisory lock shared by passgen writers."""

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.path = output_path.with_name(f".{output_path.name}.passgen.lock")
        self._handle: object | None = None

    def __enter__(self) -> "_OutputLock":
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise ConfigError(f"Cannot open output lock {self.path}: {exc}") from exc
        try:
            handle = os.fdopen(descriptor, "r+b", buffering=0)
        except OSError as exc:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise ConfigError(f"Cannot open output lock {self.path}: {exc}") from exc
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._handle = handle
            return self
        except OSError as exc:
            try:
                handle.close()
            except OSError:
                pass
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise ConfigError(
                    f"Another passgen process is writing output: {self.output_path}"
                ) from exc
            raise ConfigError(f"Cannot acquire output lock {self.path}: {exc}") from exc

    def __exit__(self, *_: object) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            # Closing the descriptor releases the OS lock even if an explicit
            # unlock fails. Never report a false generation failure after an
            # output file may already have been published.
            pass
        finally:
            try:
                handle.close()
            except OSError:
                pass


def _output_snapshot(path: Path) -> _OutputSnapshot | None:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(value.st_mode):
        raise ConfigError(f"Output must be a regular file: {path}")
    return _OutputSnapshot.from_stat(value)


def _validate_output_relationships(config: GeneratorConfig) -> None:
    if config.output.path == Path("-"):
        return
    output_path = config.output.path.resolve()
    lock_path = output_path.with_name(f".{output_path.name}.passgen.lock")
    for wordlist in config.wordlists.values():
        if output_path == wordlist.path.resolve():
            raise ConfigError(
                f"Output path cannot be the same as wordlist {wordlist.name}: {output_path}"
            )
        if lock_path == wordlist.path.resolve():
            raise ConfigError(
                "Output lock path cannot be the same as wordlist "
                f"{wordlist.name}: {lock_path}"
            )
    if config.mutations is not None:
        for rule_path in config.mutations.rule_paths:
            if output_path == rule_path.resolve():
                raise ConfigError(
                    f"Output path cannot be the same as hashcat rule file: {output_path}"
                )
            if lock_path == rule_path.resolve():
                raise ConfigError(
                    "Output lock path cannot be the same as hashcat rule file: "
                    f"{lock_path}"
                )


def _validate_output(config: GeneratorConfig) -> None:
    _validate_output_relationships(config)
    if config.output.path != Path("-"):
        _output_snapshot(config.output.path)


def _write_stream(
    handle: TextIO,
    config: GeneratorConfig,
    plan: GenerationPlan,
    deduplicator: DiskDeduplicator,
    stats: GenerationStats,
) -> None:
    max_passwords = config.generation.max_passwords
    existing_unique = stats.existing_candidates - stats.existing_duplicate_candidates
    if max_passwords is not None and existing_unique >= max_passwords:
        return
    for candidate in iter_candidates(config, plan, stats):
        if not deduplicator.add(candidate):
            stats.duplicate_candidates += 1
            continue
        handle.write(candidate + "\n")
        stats.written_candidates += 1
        if (
            max_passwords is not None
            and existing_unique + stats.written_candidates >= max_passwords
        ):
            break


def _copy_existing_candidates(
    output_path: Path,
    handle: TextIO,
    encoding: str,
    deduplicator: DiskDeduplicator,
    stats: GenerationStats,
    expected_snapshot: _OutputSnapshot,
    max_passwords: int | None,
) -> None:
    try:
        source = output_path.open(
            "r",
            encoding=encoding,
            errors="strict",
            newline=None,
        )
    except FileNotFoundError as exc:
        raise ConfigError(f"Output changed before merge: {output_path}") from exc
    with source:
        opened_snapshot = _OutputSnapshot.from_stat(os.fstat(source.fileno()))
        if opened_snapshot != expected_snapshot:
            raise ConfigError(f"Output changed before merge: {output_path}")
        line_number = 0
        while True:
            raw_line = source.readline(MAX_CANDIDATE_LENGTH + 2)
            if raw_line == "":
                break
            line_number += 1
            candidate = raw_line[:-1] if raw_line.endswith("\n") else raw_line
            if len(candidate) > MAX_CANDIDATE_LENGTH:
                raise ConfigError(
                    f"Existing output line is too long at {output_path}:{line_number}; "
                    f"maximum is {MAX_CANDIDATE_LENGTH:,} characters"
                )
            if "\x00" in candidate:
                raise ConfigError(
                    f"Existing output contains NUL at {output_path}:{line_number}"
                )
            stats.existing_candidates += 1
            if not deduplicator.add(candidate):
                stats.existing_duplicate_candidates += 1
                continue
            existing_unique = stats.existing_candidates - stats.existing_duplicate_candidates
            if max_passwords is not None and existing_unique > max_passwords:
                raise ConfigError(
                    f"Existing output already exceeds --max-passwords {max_passwords}: "
                    f"{output_path}; use --force to replace it"
                )
            handle.write(candidate + "\n")


def _close_deduplicator_after_success(deduplicator: DiskDeduplicator) -> None:
    """Close SQLite before commit so close failures cannot follow publication."""

    deduplicator.close()


def _safe_close_deduplicator(deduplicator: DiskDeduplicator) -> None:
    try:
        deduplicator.close()
    except (ConfigError, OSError):
        pass


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _publish_partial_output(
    temporary_path: Path, output_path: Path, encoding: str
) -> Path:
    """Publish only complete lines, without replacing the requested output."""

    descriptor, raw_clean_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.partial-",
        suffix=".part",
        dir=str(output_path.parent),
    )
    clean_path = Path(raw_clean_path)
    try:
        complete_lines = 0
        with temporary_path.open(
            "r", encoding=encoding, errors="ignore", newline=None
        ) as source:
            with os.fdopen(
                descriptor, "w", encoding=encoding, errors="strict", newline="\n"
            ) as destination:
                descriptor = -1
                while True:
                    line = source.readline(MAX_CANDIDATE_LENGTH + 2)
                    if not line or not line.endswith("\n"):
                        break
                    if len(line) > MAX_CANDIDATE_LENGTH + 1:
                        raise ConfigError("Interrupted output contains an oversized line")
                    destination.write(line)
                    complete_lines += 1
                destination.flush()
                os.fsync(destination.fileno())
        if not complete_lines:
            raise ConfigError("Interrupted output contains no complete lines")
        for number in range(1, 10_001):
            suffix = "" if number == 1 else f"-{number}"
            partial_path = output_path.with_name(
                f"{output_path.stem}.partial{suffix}{output_path.suffix}"
            )
            try:
                publish_file(clean_path, partial_path, overwrite=False)
                return partial_path
            except FileExistsError:
                continue
        raise ConfigError(f"Too many partial output files beside {output_path}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        _safe_unlink(clean_path)


def write_candidates(config: GeneratorConfig, plan: GenerationPlan) -> GenerationStats:
    _validate_output(config)
    stats = GenerationStats()
    if config.output.path == Path("-"):
        sys.stdout.flush()
        output_stream = EncodedStreamWriter(sys.stdout, config.output.encoding)
        deduplicator = DiskDeduplicator()
        try:
            _write_stream(output_stream, config, plan, deduplicator, stats)
            output_stream.finish()
        except BaseException:
            _safe_close_deduplicator(deduplicator)
            raise
        _close_deduplicator_after_success(deduplicator)
        return stats

    output_path = config.output.path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with _OutputLock(output_path):
        existing_snapshot = _output_snapshot(output_path)
        descriptor, raw_temporary_path = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".part",
            dir=str(output_path.parent),
        )
        temporary_path = Path(raw_temporary_path)
        try:
            deduplicator = DiskDeduplicator(output_path.parent)
        except BaseException:
            os.close(descriptor)
            _safe_unlink(temporary_path)
            raise
        completed = False
        deduplicator_open = True
        try:
            handle = os.fdopen(
                descriptor,
                "w",
                encoding=config.output.encoding,
                errors="strict",
                newline="\n",
            )
            descriptor = -1
            with handle:
                if existing_snapshot is not None and not config.output.overwrite:
                    _copy_existing_candidates(
                        output_path,
                        handle,
                        config.output.encoding,
                        deduplicator,
                        stats,
                        existing_snapshot,
                        config.generation.max_passwords,
                    )
                _write_stream(handle, config, plan, deduplicator, stats)
                handle.flush()
                os.fsync(handle.fileno())

            _close_deduplicator_after_success(deduplicator)
            deduplicator_open = False

            if existing_snapshot is not None:
                current_snapshot = _output_snapshot(output_path)
                if current_snapshot != existing_snapshot:
                    raise ConfigError(f"Output changed during generation: {output_path}")
                os.chmod(
                    temporary_path,
                    stat.S_IMODE(existing_snapshot.mode),
                )
                publish_file(temporary_path, output_path, overwrite=True)
            else:
                try:
                    publish_file(temporary_path, output_path, overwrite=False)
                except FileExistsError as exc:
                    raise ConfigError(
                        f"Output appeared during generation: {output_path}"
                    ) from exc
            completed = True
            return stats
        except KeyboardInterrupt as exc:
            if stats.written_candidates > 0 and temporary_path.exists():
                try:
                    partial_path = _publish_partial_output(
                        temporary_path, output_path, config.output.encoding
                    )
                except (ConfigError, OSError) as save_exc:
                    raise GenerationInterrupted(
                        None, stats.written_candidates, str(save_exc)
                    ) from exc
                raise GenerationInterrupted(
                    partial_path, stats.written_candidates
                ) from exc
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if deduplicator_open:
                _safe_close_deduplicator(deduplicator)
            if not completed:
                _safe_unlink(temporary_path)
