"""Command-line interface for YAML and quick pattern generation."""

from __future__ import annotations

import argparse
import copy
from dataclasses import replace
import os
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .config import (
    ConfigError,
    CUSTOM_RULE_FIELDS,
    FILTER_CATEGORIES,
    Filters,
    GeneratorConfig,
    config_from_mapping,
    dump_yaml_mapping,
    load_config,
)
from .help_loader import help_value
from .pipeline import (
    GenerationInterrupted,
    GenerationPlan,
    GenerationStats,
    build_plan,
    write_candidates,
)
from .streams import configure_text_stream


def _option_help(command: str, name: str, fallback: str) -> str:
    return help_value(f"{command}.options.{name}", fallback)


class EditableHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep argparse's layout while sourcing its usage label from help YAML."""

    def _format_usage(
        self,
        usage: str | None,
        actions: Sequence[argparse.Action],
        groups: Sequence[argparse._MutuallyExclusiveGroup],
        prefix: str | None,
    ) -> str:
        if prefix is None:
            prefix = f"{help_value('common.usage', 'usage')}: "
        return super()._format_usage(usage, actions, groups, prefix)


class PrimaryHelpParser(argparse.ArgumentParser):
    """Show only the user-maintained primary help from ``ru.yaml``."""

    def __init__(
        self,
        *args: Any,
        help_section: str = "quick",
        **kwargs: Any,
    ) -> None:
        self._help_section = help_section
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        usage_label = help_value("common.usage", "Использование")
        usage = help_value(f"{self._help_section}.usage")
        description = help_value(f"{self._help_section}.description")
        sections: list[str] = []
        if description:
            heading, _, body = description.rstrip().partition("\n")
            sections.append(heading)
        else:
            body = ""
        if usage:
            sections.append(f"{usage_label}: {usage}")
        if body.strip():
            sections.append(body.lstrip("\n"))
        if not sections:
            return super().format_help()
        return "\n\n".join(sections) + "\n"


def _localize_parser(parser: argparse.ArgumentParser) -> None:
    parser._positionals.title = help_value(
        "common.positional_arguments", "positional arguments"
    )
    parser._optionals.title = help_value("common.options", "options")
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=help_value("common.help", "show this help message and exit"),
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the root quick-generation parser."""

    parser = PrimaryHelpParser(
        prog="passgen",
        usage=help_value("quick.usage") or None,
        description=help_value("quick.description"),
        formatter_class=EditableHelpFormatter,
        add_help=False,
        allow_abbrev=False,
    )
    parser._positionals.title = help_value(
        "common.positional_arguments", "positional arguments"
    )
    parser._optionals.title = help_value("common.options", "options")

    patterns = parser.add_argument_group(
        help_value("quick.groups.patterns", "Паттерны")
    )
    patterns.add_argument(
        "-p",
        "--pattern",
        action="append",
        required=True,
        metavar="PATTERN",
        help=_option_help("quick", "pattern", "Generation pattern"),
    )
    patterns.add_argument(
        "--charset1",
        metavar="CHARACTERS",
        help=_option_help("quick", "charset1", "Charset ?1"),
    )

    wordlists = parser.add_argument_group(
        help_value("quick.groups.wordlists", "Словари")
    )
    wordlists.add_argument(
        "--wordlist",
        action="append",
        nargs="+",
        metavar="NAME_OR_PATH",
        default=[],
        help=_option_help("quick", "wordlist", "Named wordlist"),
    )
    for option, destination, value_name in (
        ("--wl-min-length", "wl_min_length", "N"),
        ("--wl-max-length", "wl_max_length", "N"),
        ("--wl-require", "wl_require", "CATEGORY"),
        ("--wl-forbid", "wl_forbid", "CATEGORY"),
    ):
        wordlists.add_argument(
            option,
            dest=destination,
            action="append",
            nargs=2,
            metavar=("NAME", value_name),
            default=[],
            help=_option_help("quick", destination, option),
        )
    wordlists.add_argument(
        "--zip-wordlists",
        action="append",
        default=[],
        metavar="NAME1,NAME2",
        help=_option_help("quick", "zip_wordlists", "Pair wordlist rows"),
    )

    output = parser.add_argument_group(
        help_value("quick.groups.output", "Вывод")
    )
    output.add_argument(
        "--result-min-length",
        type=int,
        metavar="N",
        help=_option_help("quick", "result_min_length", "Minimum result length"),
    )
    output.add_argument(
        "--result-max-length",
        type=int,
        metavar="N",
        help=_option_help("quick", "result_max_length", "Maximum result length"),
    )
    output.add_argument(
        "-o",
        "--output",
        default="candidates.txt",
        metavar="PATH",
        help=_option_help("quick", "output", "Output path"),
    )
    output.add_argument(
        "--encoding",
        default="utf-8",
        help=_option_help("quick", "encoding", "Output encoding"),
    )
    output.add_argument(
        "--force",
        action="store_true",
        help=_option_help("quick", "force", "Replace output instead of merging"),
    )
    output.add_argument(
        "--confirm-above",
        type=int,
        default=1_000_000,
        metavar="N",
        help=_option_help("quick", "confirm_above", "Confirmation threshold"),
    )
    output.add_argument(
        "--max-passwords",
        type=int,
        metavar="N",
        help=_option_help("quick", "max_passwords", "Maximum passwords in output"),
    )
    output.add_argument(
        "--plan",
        action="store_true",
        help=_option_help("quick", "plan", "Show plan"),
    )

    mutations = parser.add_argument_group(
        help_value("quick.groups.mutations", "Мутации")
    )
    mutations.add_argument(
        "--mutation",
        action="append",
        nargs="+",
        default=[],
        metavar="RULE",
        help=_option_help("quick", "mutation", "Mutation rule"),
    )
    mutations.add_argument(
        "--mutation-mode",
        choices=("independent", "chained"),
        default="independent",
        help=_option_help("quick", "mutation_mode", "Mutation mode"),
    )
    mutations.add_argument(
        "--include-original",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=_option_help("quick", "include_original", "Include original candidate"),
    )

    additional = parser.add_argument_group(
        help_value("quick.groups.additional", "Дополнительные команды"),
        description=help_value("quick.additional_description"),
    )
    for option, destination, value_name in (
        ("--wl-max-lines", "wl_max_lines", "N|all"),
        ("--wl-encoding", "wl_encoding", "ENCODING"),
    ):
        additional.add_argument(
            option,
            dest=destination,
            action="append",
            nargs=2,
            metavar=("NAME", value_name),
            default=[],
            help=_option_help("quick", destination, option),
        )
    additional.add_argument(
        "--charset",
        action="append",
        nargs=2,
        metavar=("NAME", "CHARACTERS"),
        default=[],
        help=_option_help("quick", "charset", "Named charset"),
    )
    for number in range(2, 5):
        additional.add_argument(
            f"--charset{number}",
            metavar="CHARACTERS",
            help=_option_help("quick", f"charset{number}", f"Charset ?{number}"),
        )
    additional.add_argument(
        "--rule-file",
        action="append",
        default=[],
        metavar="PATH",
        help=_option_help("quick", "rule_file", "Hashcat rule file"),
    )
    additional.add_argument(
        "--yes",
        action="store_true",
        help=_option_help("quick", "yes", "Confirm generation"),
    )
    additional.add_argument(
        "--save-config",
        type=Path,
        metavar="PATH",
        help=_option_help("quick", "save_config", "Save YAML config"),
    )
    additional.add_argument(
        "--overwrite-config",
        action="store_true",
        help=_option_help(
            "quick",
            "overwrite_config",
            "Overwrite the file specified by --save-config",
        ),
    )
    additional.add_argument(
        "--stats",
        action="store_true",
        help=_option_help("quick", "stats", "Show statistics"),
    )
    additional.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help=help_value("common.version", "show program's version number and exit"),
    )
    additional.add_argument(
        "-h",
        "--help",
        action="help",
        help=help_value("common.help", "show this help message and exit"),
    )
    parser.set_defaults(handler=_handle_quick)
    return parser


def build_from_config_parser() -> argparse.ArgumentParser:
    # The project deliberately has one complete help page. Calling
    # ``passgen from-config -h`` is retained as a friendly alias for it, while
    # the actual config parser and its validation behaviour remain unchanged.
    parser = PrimaryHelpParser(
        prog="passgen from-config",
        formatter_class=EditableHelpFormatter,
        add_help=False,
        allow_abbrev=False,
        help_section="quick",
    )
    _localize_parser(parser)
    parser.add_argument(
        "config_path",
        type=Path,
        metavar="CONFIG",
        help=_option_help("from_config", "config", "YAML config path"),
    )
    inspection_mode = parser.add_mutually_exclusive_group()
    inspection_mode.add_argument(
        "--check",
        action="store_true",
        help=_option_help("from_config", "check", "Validate only"),
    )
    inspection_mode.add_argument(
        "--plan",
        action="store_true",
        help=_option_help("from_config", "plan", "Show plan"),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=_option_help("from_config", "yes", "Confirm generation"),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=_option_help("from_config", "force", "Replace output instead of merging"),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help=_option_help("from_config", "output", "Override output"),
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help=_option_help("from_config", "stats", "Show statistics"),
    )
    parser.set_defaults(handler=_handle_from_config)
    return parser


def _parse_wordlist_definition(values: list[str]) -> tuple[str, str]:
    if len(values) == 1 and "=" in values[0]:
        name, path = values[0].split("=", 1)
    elif len(values) == 2:
        name, path = values
    else:
        raise ConfigError("--wordlist expects NAME PATH or NAME=PATH")
    if not name or not path:
        raise ConfigError("--wordlist name and path cannot be empty")
    return name, path


def _parse_positive_cli_int(value: str, option: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{option} expects an integer, got {value!r}") from exc
    if parsed <= 0:
        raise ConfigError(f"{option} expects a positive integer")
    return parsed


def _apply_wordlist_pairs(
    wordlists: dict[str, dict[str, Any]],
    pairs: list[list[str]],
    field: str,
    option: str,
    converter: Any = str,
    *,
    append: bool = False,
) -> None:
    for name, raw_value in pairs:
        if name not in wordlists:
            raise ConfigError(f"{option} references undefined wordlist: {name}")
        value = converter(raw_value)
        if append:
            wordlists[name].setdefault(field, []).append(value)
        elif field in wordlists[name]:
            raise ConfigError(f"{option} is specified more than once for {name}")
        else:
            wordlists[name][field] = value


def _parse_mutation(value: str) -> dict[str, Any]:
    if "=" not in value:
        return {"type": value}
    action, payload = value.split("=", 1)
    if action in {"append", "prepend"}:
        return {"type": action, "value": payload.replace("\x00", ",")}
    if action == "replace":
        if "," not in payload:
            raise ConfigError("replace mutation uses replace=FROM,TO")
        old, new = payload.split(",", 1)
        return {
            "type": "replace",
            "from": old.replace("\x00", ","),
            "to": new.replace("\x00", ","),
        }
    raise ConfigError(f"Mutation {action!r} does not accept a value")


def _split_mutation_commas(value: str) -> list[str]:
    """Split rule separators, leaving escaped commas inside rule arguments."""

    items: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(value):
        if value[index:index + 2] == r"\,":
            current.append("\x00")
            index += 2
        elif value[index] == ",":
            items.append("".join(current))
            current = []
            index += 1
        else:
            current.append(value[index])
            index += 1
    items.append("".join(current))
    return items


def _parse_mutations(values: Sequence[Sequence[str]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    parameterized_prefixes = ("append=", "prepend=", "replace=")
    simple_rules = CUSTOM_RULE_FIELDS.keys() - {"append", "prepend", "replace"}

    def begins_rule(item: str) -> bool:
        candidate = item.strip()
        return candidate in simple_rules or candidate.startswith(parameterized_prefixes)

    for parts in values:
        for part_index, raw_value in enumerate(parts):
            value = raw_value.lstrip()
            if not value:
                raise ConfigError("--mutation cannot be empty")
            items = _split_mutation_commas(value)
            item_index = 0
            while item_index < len(items):
                item = items[item_index]
                if item.lstrip().startswith(parameterized_prefixes):
                    rule = item.lstrip()
                    item_index += 1
                    if rule.startswith("replace="):
                        if item_index >= len(items):
                            raise ConfigError("replace mutation uses replace=FROM,TO")
                        rule += "," + items[item_index]
                        item_index += 1
                    while item_index < len(items) and not begins_rule(items[item_index]):
                        rule += "," + items[item_index]
                        item_index += 1
                    parsed.append(_parse_mutation(rule))
                    continue
                if item.strip():
                    parsed.append(_parse_mutation(item.strip()))
                elif not (
                    item_index == len(items) - 1
                    and part_index < len(parts) - 1
                ):
                    raise ConfigError(
                        "--mutation contains an empty item; use a comma-separated "
                        "list such as uppercase,lowercase"
                    )
                item_index += 1
    return parsed


def _mapping_from_quick_args(args: argparse.Namespace) -> dict[str, Any]:
    wordlists: dict[str, dict[str, Any]] = {}
    for definition in args.wordlist:
        name, path = _parse_wordlist_definition(definition)
        if name in wordlists:
            raise ConfigError(f"Wordlist is defined more than once: {name}")
        wordlists[name] = {"path": path}

    positive = lambda raw: _parse_positive_cli_int(raw, "wordlist length")
    _apply_wordlist_pairs(
        wordlists, args.wl_min_length, "min_length", "--wl-min-length", positive
    )
    _apply_wordlist_pairs(
        wordlists, args.wl_max_length, "max_length", "--wl-max-length", positive
    )

    def max_lines(raw: str) -> str | int:
        return "all" if raw == "all" else _parse_positive_cli_int(raw, "--wl-max-lines")

    _apply_wordlist_pairs(
        wordlists, args.wl_max_lines, "max_lines", "--wl-max-lines", max_lines
    )
    _apply_wordlist_pairs(
        wordlists, args.wl_encoding, "encoding", "--wl-encoding"
    )

    def category(raw: str) -> str:
        if raw not in FILTER_CATEGORIES:
            allowed = ", ".join(sorted(FILTER_CATEGORIES))
            raise ConfigError(f"Unknown filter category {raw!r}; expected {allowed}")
        return raw

    _apply_wordlist_pairs(
        wordlists,
        args.wl_require,
        "require",
        "--wl-require",
        category,
        append=True,
    )
    _apply_wordlist_pairs(
        wordlists,
        args.wl_forbid,
        "forbid",
        "--wl-forbid",
        category,
        append=True,
    )

    charsets: dict[str, str] = {}
    for name, characters in args.charset:
        if name in charsets:
            raise ConfigError(f"Charset is defined more than once: {name}")
        charsets[name] = characters
    for number in range(1, 5):
        characters = getattr(args, f"charset{number}")
        if characters is not None:
            key = str(number)
            if key in charsets:
                raise ConfigError(f"Charset is defined more than once: {key}")
            charsets[key] = characters

    data: dict[str, Any] = {
        "version": 2,
        "wordlists": wordlists,
        "charsets": charsets,
        "patterns": list(args.pattern),
        "generation": {
            "confirm_above": args.confirm_above,
        },
        "result_filters": {
            "forbid_control_characters": True,
        },
        "output": {
            "path": args.output,
            "encoding": args.encoding,
            "overwrite": args.force,
        },
    }
    if args.max_passwords is not None:
        data["generation"]["max_passwords"] = args.max_passwords
    if args.zip_wordlists:
        zip_wordlists: list[list[str]] = []
        for raw_pair in args.zip_wordlists:
            names = [name.strip() for name in raw_pair.split(",")]
            if len(names) != 2 or not all(names):
                raise ConfigError(
                    "--zip-wordlists: укажите два имени через запятую, "
                    "например names,years"
                )
            zip_wordlists.append(names)
        data["generation"]["zip_wordlists"] = zip_wordlists
    if args.result_min_length is not None:
        data["result_filters"]["min_length"] = args.result_min_length
    if args.result_max_length is not None:
        data["result_filters"]["max_length"] = args.result_max_length

    if args.mutation or args.rule_file:
        data["mutations"] = {
            "mode": args.mutation_mode,
            "include_original": args.include_original,
            "default_apply": True,
            "rules": _parse_mutations(args.mutation),
            "rule_files": [
                {"path": path, "max_rules": "all"}
                for path in args.rule_file
            ],
        }
    return data


def _rebase_mapping_for_save(data: dict[str, Any], target: Path) -> dict[str, Any]:
    """Make CLI paths valid relative to the directory of a saved config."""

    saved = copy.deepcopy(data)

    def rebase(raw_path: str) -> str:
        if raw_path == "-":
            return raw_path
        absolute = Path(raw_path)
        if not absolute.is_absolute():
            absolute = (Path.cwd() / absolute).resolve()
        try:
            relative = Path(os.path.relpath(absolute, target.parent))
            return relative.as_posix()
        except ValueError:
            return absolute.as_posix()

    for wordlist in saved.get("wordlists", {}).values():
        wordlist["path"] = rebase(str(wordlist["path"]))
    for rule_file in saved.get("mutations", {}).get("rule_files", []):
        rule_file["path"] = rebase(str(rule_file["path"]))
    output = saved.get("output", {})
    if "path" in output:
        output["path"] = rebase(str(output["path"]))
    return saved


def _format_count(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def _format_optional_filter(value: int | None) -> str:
    return "none" if value is None else str(value)


def _format_filter_categories(categories: frozenset[str]) -> str:
    return ",".join(sorted(categories)) or "none"


def _format_filters(filters: Filters, *, include_control_characters: bool) -> str:
    values = [
        f"min_length={_format_optional_filter(filters.min_length)}",
        f"max_length={_format_optional_filter(filters.max_length)}",
        f"require={_format_filter_categories(filters.require)}",
        f"forbid={_format_filter_categories(filters.forbid)}",
    ]
    if include_control_characters:
        values.append(
            "forbid_control_characters="
            + ("true" if filters.forbid_control_characters else "false")
        )
    return "; ".join(values)


def _print_plan(config: GeneratorConfig, plan: GenerationPlan) -> None:
    print("Generation plan", file=sys.stderr)
    if plan.wordlist_counts:
        print("\nWordlists:", file=sys.stderr)
        for name, count in plan.wordlist_counts.items():
            print(f"  {name}: {_format_count(count)}", file=sys.stderr)
            print(
                "    Filters: "
                + _format_filters(
                    config.wordlists[name].filters,
                    include_control_characters=False,
                ),
                file=sys.stderr,
            )
    if config.generation.zip_wordlists:
        print("\nПопарные словари:", file=sys.stderr)
        for left, right in config.generation.zip_wordlists:
            print(
                f"  {left} + {right}: "
                f"{_format_count(plan.paired_wordlist_counts[(left, right)])} пар",
                file=sys.stderr,
            )
    print("\nGlobal filters:", file=sys.stderr)
    print(
        "  "
        + _format_filters(
            config.result_filters,
            include_control_characters=True,
        ),
        file=sys.stderr,
    )
    print("\nPatterns:", file=sys.stderr)
    for pattern in plan.patterns:
        if pattern.apply_mutations:
            if pattern.estimate_is_upper_bound:
                count_text = (
                    f"{_format_count(pattern.base_candidates)} base -> <= "
                    f"{_format_count(pattern.estimated_candidates)} "
                    "after mutations (upper bound)"
                )
            else:
                count_text = (
                    f"{_format_count(pattern.base_candidates)} base -> "
                    f"{_format_count(pattern.estimated_candidates)} "
                    "after mutations (exact)"
                )
        else:
            count_text = _format_count(pattern.estimated_candidates)
        print(
            f"  {pattern.index:>2}. [{pattern.value}]: {count_text}",
            file=sys.stderr,
        )
    print(
        "\nВсего парольных кандидатов ДО применения фильтров и дедупликации: "
        f"{_format_count(plan.estimated_candidates)}",
        file=sys.stderr,
    )
    if plan.estimate_is_upper_bound:
        print("Оценка является верхней границей.", file=sys.stderr)
    if config.output.path == Path("-"):
        output_mode = "stdout"
    elif config.output.overwrite:
        output_mode = "atomic replacement"
    else:
        output_mode = "atomic merge"
    print(f"Output: {config.output.path} ({output_mode})", file=sys.stderr)
    if config.generation.max_passwords is not None:
        print(
            "Лимит паролей в итоговом файле: "
            f"{_format_count(config.generation.max_passwords)}",
            file=sys.stderr,
        )


def _read_confirmation(prompt: str) -> bool:
    print(prompt, end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline()
    if answer == "":
        return False
    return answer.strip().lower() in {"y", "yes", "д", "да"}


def _confirm_generation(
    config: GeneratorConfig,
    plan: GenerationPlan,
    assume_yes: bool,
) -> None:
    estimated_for_run = plan.estimated_candidates
    if config.generation.max_passwords is not None:
        estimated_for_run = min(
            estimated_for_run,
            config.generation.max_passwords,
        )
    if assume_yes:
        return
    if not sys.stdin.isatty():
        if estimated_for_run > config.generation.confirm_above:
            raise ConfigError(
                "Generation exceeds confirm_above in non-interactive mode; "
                "use --yes after reviewing --plan"
            )
        return
    estimate = _format_count(estimated_for_run)
    if config.generation.max_passwords is not None:
        if not _read_confirmation(
            f"Начать генерацию? Лимит итоговых паролей: {estimate}. [y/N] "
        ):
            raise ConfigError("Generation cancelled by user")
        return
    if plan.estimate_is_upper_bound:
        estimate = f"до {estimate}"
    if not _read_confirmation(
        "Начать генерацию? "
        f"До фильтров и дедупликации: {estimate}. [y/N] "
    ):
        raise ConfigError("Generation cancelled by user")


def _print_stats(stats: GenerationStats) -> None:
    print("Generation statistics", file=sys.stderr)
    print(f"  Base candidates:      {_format_count(stats.base_candidates)}", file=sys.stderr)
    print(f"  After mutations:      {_format_count(stats.mutation_candidates)}", file=sys.stderr)
    print(f"  Filtered:             {_format_count(stats.filtered_candidates)}", file=sys.stderr)
    print(f"  Duplicates:           {_format_count(stats.duplicate_candidates)}", file=sys.stderr)
    if stats.existing_candidates:
        preserved = stats.existing_candidates - stats.existing_duplicate_candidates
        print(f"  Existing preserved:   {_format_count(preserved)}", file=sys.stderr)
        print(
            f"  Existing duplicates:  {_format_count(stats.existing_duplicate_candidates)}",
            file=sys.stderr,
        )
    print(f"  New written:          {_format_count(stats.written_candidates)}", file=sys.stderr)


def _run_config(
    config: GeneratorConfig,
    *,
    plan_only: bool,
    check_only: bool,
    assume_yes: bool,
    show_stats: bool,
    prepared_plan: GenerationPlan | None = None,
) -> int:
    plan = prepared_plan if prepared_plan is not None else build_plan(config)
    if check_only:
        print("Config is valid", file=sys.stderr)
        return 0
    _print_plan(config, plan)
    if plan_only:
        return 0
    _confirm_generation(config, plan, assume_yes)
    stats = write_candidates(config, plan)
    if show_stats:
        _print_stats(stats)
    else:
        print(f"New candidates written: {stats.written_candidates}", file=sys.stderr)
    if config.output.path == Path("-"):
        print("[РЕЗУЛЬТАТ] Пароли выведены в stdout", file=sys.stderr)
    else:
        print(f"[РЕЗУЛЬТАТ] Пароли сохранены: {config.output.path}", file=sys.stderr)
    return 0


def _handle_quick(args: argparse.Namespace) -> int:
    if args.overwrite_config and args.save_config is None:
        raise ConfigError("--overwrite-config requires --save-config PATH")
    data = _mapping_from_quick_args(args)
    config = config_from_mapping(data, base_path=Path.cwd())
    # Compile patterns, validate mutation rules, and strictly decode every
    # referenced wordlist before persisting an equivalent configuration.
    plan = build_plan(config)
    if args.save_config is not None:
        target = args.save_config.resolve()
        if target.suffix.lower() not in {".yaml", ".yml"}:
            raise ConfigError("--save-config path must use .yaml or .yml")
        if config.output.path != Path("-") and config.output.path.resolve() == target:
            raise ConfigError("Saved config path cannot be the same as the output path")
        for wordlist in config.wordlists.values():
            if target == wordlist.path.resolve():
                raise ConfigError(
                    f"Saved config path cannot overwrite wordlist {wordlist.name}: {target}"
                )
        if config.mutations is not None:
            for rule_path in config.mutations.rule_paths:
                if target == rule_path.resolve():
                    raise ConfigError(
                        f"Saved config path cannot overwrite hashcat rule file: {target}"
                    )
        if target.exists() and not args.overwrite_config:
            raise ConfigError(
                f"Config file already exists: {target}; use --overwrite-config"
            )
        dump_yaml_mapping(
            _rebase_mapping_for_save(data, target),
            target,
            overwrite=args.overwrite_config,
        )
        print(f"Saved config: {target}", file=sys.stderr)
    return _run_config(
        config,
        plan_only=args.plan,
        check_only=False,
        assume_yes=args.yes,
        show_stats=args.stats,
        prepared_plan=plan,
    )


def _handle_from_config(args: argparse.Namespace) -> int:
    source_path = args.config_path.resolve()
    config = load_config(source_path)
    output = config.output
    if args.output is not None:
        path = Path(args.output)
        if args.output != "-" and not path.is_absolute():
            path = (Path.cwd() / path).resolve()
        if path != Path("-") and path.resolve() == source_path:
            raise ConfigError(f"Output path cannot overwrite the config file: {source_path}")
        output = replace(output, path=path)
    if args.force:
        output = replace(output, overwrite=True)
    config = replace(config, output=output)
    return _run_config(
        config,
        plan_only=args.plan,
        check_only=args.check,
        assume_yes=args.yes,
        show_stats=args.stats,
    )


def main(argv: Sequence[str] | None = None) -> int:
    # Python launched from Windows PowerShell can inherit cp1251 while the
    # pipeline itself expects UTF-8. Use one deterministic encoding for help
    # and diagnostics; candidate stdout is adjusted to output.encoding later.
    configure_text_stream(sys.stdout, encoding="utf-8", errors="backslashreplace")
    configure_text_stream(sys.stderr, encoding="utf-8", errors="backslashreplace")
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        values = ["-h"]
    if values[0] == "from-config":
        parser = build_from_config_parser()
        values = values[1:]
    else:
        parser = build_parser()
    try:
        args = parser.parse_args(values)
        return int(args.handler(args))
    except ConfigError as exc:
        print(f"passgen: error: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(f"passgen: I/O error: {exc}", file=sys.stderr)
        return 3
    except GenerationInterrupted as exc:
        if exc.partial_path is not None:
            print(
                "\n[ПРЕРВАНО] Сохранено новых паролей: "
                f"{_format_count(exc.written_candidates)}; "
                f"неполный файл: {exc.partial_path}",
                file=sys.stderr,
            )
        elif exc.save_error is not None:
            print(
                f"\npassgen: прервано; неполный файл не сохранён: {exc.save_error}",
                file=sys.stderr,
            )
        else:
            print("\npassgen: interrupted", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print("\npassgen: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
