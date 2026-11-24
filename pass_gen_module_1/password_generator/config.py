"""Strict YAML v2 configuration model for passgen."""

from __future__ import annotations

import codecs
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Iterator, Mapping

import yaml

from .atomic import publish_file
from .limits import (
    MAX_CANDIDATE_LENGTH,
    MAX_HASHCAT_RULE_LENGTH,
    MAX_MUTATION_OPERATIONS,
)


class ConfigError(ValueError):
    """Raised when a passgen configuration is invalid."""


WORDLIST_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
FILTER_CATEGORIES = frozenset({"digits", "lowercase", "uppercase", "special"})
MUTATION_MODES = frozenset({"independent", "chained"})

LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz"
LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CYRILLIC_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
CYRILLIC_UPPER = CYRILLIC_LOWER.upper()
DIGITS = "0123456789"
SPECIAL = " " + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

BUILTIN_CHARSETS: dict[str, str] = {
    "l": LATIN_LOWER,
    "u": LATIN_UPPER,
    "d": DIGITS,
    "s": SPECIAL,
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "latin_lower": LATIN_LOWER,
    "latin_upper": LATIN_UPPER,
    "cyrillic_lower": CYRILLIC_LOWER,
    "cyrillic_upper": CYRILLIC_UPPER,
    "digits": DIGITS,
    "special": SPECIAL,
    "hex_lower": "0123456789abcdef",
    "hex_upper": "0123456789ABCDEF",
}
BUILTIN_CHARSETS["a"] = LATIN_LOWER + LATIN_UPPER + DIGITS + SPECIAL
BUILTIN_CHARSETS["ascii_all"] = BUILTIN_CHARSETS["a"]


def unique_characters(value: str) -> str:
    return "".join(dict.fromkeys(value))


def _has_category(word: str, category: str) -> bool:
    if category == "digits":
        return any(char.isdigit() for char in word)
    if category == "lowercase":
        return any(char.isalpha() and char.islower() for char in word)
    if category == "uppercase":
        return any(char.isalpha() and char.isupper() for char in word)
    if category == "special":
        return any(not char.isalnum() for char in word)
    raise AssertionError(f"Unhandled category: {category}")


@dataclass(frozen=True)
class Filters:
    min_length: int | None = None
    max_length: int | None = None
    require: frozenset[str] = field(default_factory=frozenset)
    forbid: frozenset[str] = field(default_factory=frozenset)
    forbid_control_characters: bool = False

    def matches(self, value: str) -> bool:
        if self.min_length is not None and len(value) < self.min_length:
            return False
        if self.max_length is not None and len(value) > self.max_length:
            return False
        if self.forbid_control_characters and any(
            ord(char) < 32 or ord(char) == 127 for char in value
        ):
            return False
        if any(not _has_category(value, category) for category in self.require):
            return False
        if any(_has_category(value, category) for category in self.forbid):
            return False
        return True


@dataclass(frozen=True)
class WordlistSpec:
    name: str
    path: Path
    encoding: str = "utf-8"
    max_lines: int | None = None
    filters: Filters = field(default_factory=Filters)

    def iter_rows(self) -> Iterator[str | None]:
        """Yield one value per physical row; excluded rows keep their position."""

        with self.path.open("r", encoding=self.encoding, errors="strict") as handle:
            line_number = 0
            while self.max_lines is None or line_number < self.max_lines:
                raw_line = handle.readline(MAX_CANDIDATE_LENGTH + 2)
                if raw_line == "":
                    break
                line_number += 1
                word = raw_line.rstrip("\r\n")
                if len(word) > MAX_CANDIDATE_LENGTH:
                    raise ConfigError(
                        f"Wordlist line is too long at {self.path}:{line_number}; "
                        f"maximum is {MAX_CANDIDATE_LENGTH:,} characters"
                    )
                yield word if word and self.filters.matches(word) else None

    def iter_words(self) -> Iterator[str]:
        for word in self.iter_rows():
            if word is not None:
                yield word

    def count_words(self) -> int:
        return sum(1 for _ in self.iter_words())


@dataclass(frozen=True)
class MutationOperation:
    kind: str
    value: Any
    source: str


@dataclass(frozen=True)
class MutationConfig:
    mode: str = "independent"
    include_original: bool = True
    default_apply: bool = False
    operations: tuple[MutationOperation, ...] = ()
    rule_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class PatternSpec:
    value: str
    apply_mutations: bool


@dataclass(frozen=True)
class GenerationSettings:
    confirm_above: int = 1_000_000
    max_passwords: int | None = None
    zip_wordlists: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class OutputSettings:
    path: Path
    encoding: str = "utf-8"
    overwrite: bool = False


@dataclass(frozen=True)
class GeneratorConfig:
    base_path: Path
    wordlists: Mapping[str, WordlistSpec]
    charsets: Mapping[str, str]
    patterns: tuple[PatternSpec, ...]
    mutations: MutationConfig | None
    generation: GenerationSettings
    output: OutputSettings
    result_filters: Filters
    source_data: Mapping[str, Any]


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


# PyYAML follows YAML 1.1 and otherwise treats ``yes``, ``no``, ``on`` and
# ``off`` as booleans. Config v2 deliberately follows YAML 1.2 here so only
# explicit true/false values satisfy strict boolean fields.
UniqueKeySafeLoader.yaml_implicit_resolvers = {
    first_character: [
        (tag, expression)
        for tag, expression in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for first_character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
UniqueKeySafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)
UniqueKeySafeLoader.yaml_implicit_resolvers = {
    first_character: [
        (tag, expression)
        for tag, expression in resolvers
        if tag != "tag:yaml.org,2002:int"
    ]
    for first_character, resolvers in UniqueKeySafeLoader.yaml_implicit_resolvers.items()
}
UniqueKeySafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^[-+]?(?:0|[1-9](?:_?[0-9])*)$"),
    list("-+0123456789"),
)


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConfigError(
                f"YAML mapping key must be a scalar at line {key_node.start_mark.line + 1}"
            ) from exc
        if duplicate:
            raise ConfigError(
                f"Duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}"
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{context} must be a mapping")
    return value


def _check_keys(value: Mapping[str, Any], allowed: Iterable[str], context: str) -> None:
    unknown = sorted(set(value) - set(allowed), key=str)
    if unknown:
        raise ConfigError(f"Unknown key(s) in {context}: {', '.join(map(str, unknown))}")


def _validate_encoding(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context} must be a non-empty string")
    try:
        codec = codecs.lookup(value)
    except LookupError as exc:
        raise ConfigError(f"Unknown encoding in {context}: {value}") from exc
    if not getattr(codec, "_is_text_encoding", False):
        raise ConfigError(f"{context} must name a text encoding, got: {value}")
    return value


def _strict_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{context} must be true or false")
    return value


def _positive_int(value: Any, context: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{context} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ConfigError(f"{context} must be {qualifier}")
    return value


def _optional_positive_int(value: Any, context: str) -> int | None:
    if value is None:
        return None
    return _positive_int(value, context)


def _string_list(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{context} must be a list of strings")
    return list(value)


def _parse_filters(
    data: Mapping[str, Any],
    context: str,
    *,
    allow_control_flag: bool = False,
) -> Filters:
    allowed = {"min_length", "max_length", "require", "forbid"}
    if allow_control_flag:
        allowed.add("forbid_control_characters")
    _check_keys(data, allowed, context)
    min_length = _optional_positive_int(data.get("min_length"), f"{context}.min_length")
    max_length = _optional_positive_int(data.get("max_length"), f"{context}.max_length")
    if min_length is not None and max_length is not None and min_length > max_length:
        raise ConfigError(f"{context}.min_length cannot exceed max_length")
    require = frozenset(_string_list(data.get("require"), f"{context}.require"))
    forbid = frozenset(_string_list(data.get("forbid"), f"{context}.forbid"))
    unknown_categories = sorted((require | forbid) - FILTER_CATEGORIES)
    if unknown_categories:
        raise ConfigError(
            f"Unknown filter categories in {context}: {', '.join(unknown_categories)}"
        )
    conflicts = sorted(require & forbid)
    if conflicts:
        raise ConfigError(
            f"Categories cannot be both required and forbidden in {context}: "
            + ", ".join(conflicts)
        )
    forbid_controls = allow_control_flag
    if allow_control_flag and "forbid_control_characters" in data:
        forbid_controls = _strict_bool(
            data["forbid_control_characters"],
            f"{context}.forbid_control_characters",
        )
    return Filters(
        min_length=min_length,
        max_length=max_length,
        require=require,
        forbid=forbid,
        forbid_control_characters=forbid_controls,
    )


def _resolve_path(base_path: Path, value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{context} must be a non-empty path string")
    path = Path(value)
    if not path.is_absolute():
        path = base_path / path
    return path.resolve()


def _parse_max_lines(value: Any, context: str) -> int | None:
    if value == "all":
        return None
    if value is None:
        raise ConfigError(f"{context} must be a positive integer or 'all'")
    return _positive_int(value, context)


CUSTOM_RULE_FIELDS: dict[str, tuple[set[str], set[str]]] = {
    "append": ({"type", "value"}, set()),
    "prepend": ({"type", "value"}, set()),
    "replace": ({"type", "from", "to"}, set()),
    "url_encode_specials": ({"type"}, set()),
    "base64_encode": ({"type"}, set()),
    "uppercase": ({"type"}, set()),
    "uppercase_all": ({"type"}, set()),
    "lowercase": ({"type"}, set()),
    "lowercase_all": ({"type"}, set()),
    "capitalize_first": ({"type"}, set()),
    "reverse": ({"type"}, set()),
    "ru_to_eng": ({"type"}, set()),
}


def _parse_custom_rule(value: Any, context: str) -> MutationOperation:
    data = _mapping(value, context)
    action = data.get("type")
    if not isinstance(action, str) or action not in CUSTOM_RULE_FIELDS:
        raise ConfigError(f"Unknown mutation type in {context}: {action!r}")
    required, optional = CUSTOM_RULE_FIELDS[action]
    _check_keys(data, required | optional, context)
    missing = sorted(required - set(data))
    if missing:
        raise ConfigError(f"Missing key(s) in {context}: {', '.join(missing)}")
    string_fields = {
        "append": ("value",),
        "prepend": ("value",),
        "replace": ("from", "to"),
    }.get(action, ())
    for field_name in string_fields:
        if not isinstance(data[field_name], str):
            raise ConfigError(f"{context}.{field_name} must be a string")
    if action == "replace" and data.get("from") == "":
        raise ConfigError(f"{context}.from cannot be empty")
    return MutationOperation(kind="custom", value=dict(data), source=context)


def _read_rule_file(
    base_path: Path,
    value: Any,
    context: str,
    *,
    operation_budget: int,
) -> tuple[list[MutationOperation], Path]:
    data = _mapping(value, context)
    _check_keys(data, {"path", "encoding", "max_rules"}, context)
    if "path" not in data:
        raise ConfigError(f"{context}.path is required")
    path = _resolve_path(base_path, data["path"], f"{context}.path")
    if not path.is_file():
        raise ConfigError(f"Hashcat rule file not found: {path}")
    encoding = _validate_encoding(data.get("encoding", "utf-8"), f"{context}.encoding")
    max_rules = _parse_max_lines(data.get("max_rules", "all"), f"{context}.max_rules")
    if max_rules is not None and max_rules > MAX_MUTATION_OPERATIONS:
        raise ConfigError(
            f"{context}.max_rules cannot exceed the safety limit "
            f"({MAX_MUTATION_OPERATIONS:,})"
        )
    operations: list[MutationOperation] = []
    with path.open("r", encoding=encoding, errors="strict") as handle:
        line_number = 0
        while True:
            raw_line = handle.readline(MAX_HASHCAT_RULE_LENGTH + 2)
            if raw_line == "":
                break
            line_number += 1
            rule = raw_line.rstrip("\r\n")
            if len(rule) > MAX_HASHCAT_RULE_LENGTH:
                raise ConfigError(
                    f"Hashcat rule is too long at {path}:{line_number}; "
                    f"maximum is {MAX_HASHCAT_RULE_LENGTH:,} characters"
                )
            if not rule.strip() or rule.lstrip().startswith("#"):
                continue
            if len(operations) >= operation_budget:
                raise ConfigError(
                    "Total mutation operation safety limit exceeded "
                    f"({MAX_MUTATION_OPERATIONS:,})"
                )
            operations.append(
                MutationOperation(
                    kind="hashcat",
                    value=rule,
                    source=f"{path}:{line_number}",
                )
            )
            if max_rules is not None and len(operations) >= max_rules:
                break
    return operations, path


def config_from_mapping(
    raw_data: Mapping[str, Any],
    *,
    base_path: Path,
) -> GeneratorConfig:
    data = _mapping(dict(raw_data), "config")
    _check_keys(
        data,
        {
            "version",
            "output",
            "generation",
            "result_filters",
            "charsets",
            "wordlists",
            "mutations",
            "patterns",
        },
        "config",
    )
    if data.get("version") != 2:
        raise ConfigError("config.version must be 2")

    wordlists_data = _mapping(data.get("wordlists", {}), "wordlists")
    wordlists: dict[str, WordlistSpec] = {}
    for raw_name, raw_wordlist in wordlists_data.items():
        if not isinstance(raw_name, str) or not WORDLIST_NAME_RE.fullmatch(raw_name):
            raise ConfigError(f"Invalid wordlist name: {raw_name!r}")
        context = f"wordlists.{raw_name}"
        item = _mapping(raw_wordlist, context)
        _check_keys(
            item,
            {
                "path",
                "encoding",
                "max_lines",
                "min_length",
                "max_length",
                "require",
                "forbid",
            },
            context,
        )
        if "path" not in item:
            raise ConfigError(f"{context}.path is required")
        path = _resolve_path(base_path, item["path"], f"{context}.path")
        if not path.is_file():
            raise ConfigError(f"Wordlist file not found: {path}")
        encoding = _validate_encoding(item.get("encoding", "utf-8"), f"{context}.encoding")
        filters_data = {
            key: item[key]
            for key in ("min_length", "max_length", "require", "forbid")
            if key in item
        }
        wordlists[raw_name] = WordlistSpec(
            name=raw_name,
            path=path,
            encoding=encoding,
            max_lines=_parse_max_lines(item.get("max_lines", "all"), f"{context}.max_lines"),
            filters=_parse_filters(filters_data, context),
        )

    custom_charsets_data = _mapping(data.get("charsets", {}), "charsets")
    charsets = dict(BUILTIN_CHARSETS)
    for raw_name, raw_value in custom_charsets_data.items():
        if isinstance(raw_name, str):
            name = raw_name
        elif (
            isinstance(raw_name, int)
            and not isinstance(raw_name, bool)
            and raw_name in {1, 2, 3, 4}
        ):
            name = str(raw_name)
        else:
            raise ConfigError(
                f"Invalid charset name type/value: {raw_name!r}; "
                "use a string name or integer 1..4"
            )
        if name in BUILTIN_CHARSETS:
            raise ConfigError(f"Built-in charset cannot be overwritten: {name}")
        if name.isdigit() and name not in {"1", "2", "3", "4"}:
            raise ConfigError("Numeric custom charsets are limited to 1, 2, 3 and 4")
        if not (name in {"1", "2", "3", "4"} or WORDLIST_NAME_RE.fullmatch(name)):
            raise ConfigError(f"Invalid charset name: {name!r}")
        if not isinstance(raw_value, str) or not raw_value:
            raise ConfigError(f"charsets.{name} must be a non-empty string")
        charsets[name] = unique_characters(raw_value)

    mutations: MutationConfig | None = None
    if "mutations" in data:
        mutation_data = _mapping(data["mutations"], "mutations")
        _check_keys(
            mutation_data,
            {"mode", "include_original", "default_apply", "rules", "rule_files"},
            "mutations",
        )
        mode = mutation_data.get("mode", "independent")
        if mode not in MUTATION_MODES:
            raise ConfigError("mutations.mode must be independent or chained")
        include_original = _strict_bool(
            mutation_data.get("include_original", True),
            "mutations.include_original",
        )
        default_apply = _strict_bool(
            mutation_data.get("default_apply", False),
            "mutations.default_apply",
        )
        raw_rules = mutation_data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ConfigError("mutations.rules must be a list")
        if len(raw_rules) > MAX_MUTATION_OPERATIONS:
            raise ConfigError(
                "mutations.rules exceeds the safety limit "
                f"({MAX_MUTATION_OPERATIONS:,})"
            )
        operations = [
            _parse_custom_rule(rule, f"mutations.rules[{index}]")
            for index, rule in enumerate(raw_rules)
        ]
        raw_rule_files = mutation_data.get("rule_files", [])
        if not isinstance(raw_rule_files, list):
            raise ConfigError("mutations.rule_files must be a list")
        rule_paths: list[Path] = []
        for index, rule_file in enumerate(raw_rule_files):
            file_operations, rule_path = _read_rule_file(
                base_path,
                rule_file,
                f"mutations.rule_files[{index}]",
                operation_budget=MAX_MUTATION_OPERATIONS - len(operations),
            )
            operations.extend(file_operations)
            rule_paths.append(rule_path)
        if not operations and not include_original:
            raise ConfigError("mutations would produce no candidates")
        mutations = MutationConfig(
            mode=mode,
            include_original=include_original,
            default_apply=default_apply,
            operations=tuple(operations),
            rule_paths=tuple(rule_paths),
        )

    raw_patterns = data.get("patterns")
    if not isinstance(raw_patterns, list) or not raw_patterns:
        raise ConfigError("patterns must be a non-empty list")
    default_apply = mutations.default_apply if mutations else False
    patterns: list[PatternSpec] = []
    for index, raw_pattern in enumerate(raw_patterns):
        context = f"patterns[{index}]"
        if isinstance(raw_pattern, str):
            value = raw_pattern
            apply_mutations = default_apply
        else:
            item = _mapping(raw_pattern, context)
            _check_keys(item, {"value", "apply_mutations"}, context)
            value = item.get("value")
            if "apply_mutations" in item:
                apply_mutations = _strict_bool(
                    item["apply_mutations"], f"{context}.apply_mutations"
                )
            else:
                apply_mutations = default_apply
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{context}.value must be a non-empty string")
        if apply_mutations and mutations is None:
            raise ConfigError(f"{context} enables mutations, but mutations are not configured")
        patterns.append(PatternSpec(value=value, apply_mutations=apply_mutations))

    generation_data = _mapping(data.get("generation", {}), "generation")
    if "deduplicate" in generation_data:
        raise ConfigError(
            "generation.deduplicate was removed; exact disk deduplication is always enabled"
        )
    _check_keys(
        generation_data,
        {"confirm_above", "max_passwords", "zip_wordlists"},
        "generation",
    )
    confirm_above = _positive_int(
        generation_data.get("confirm_above", 1_000_000),
        "generation.confirm_above",
        allow_zero=True,
    )
    max_passwords = (
        _positive_int(generation_data["max_passwords"], "generation.max_passwords")
        if "max_passwords" in generation_data else None
    )
    raw_zip_wordlists = generation_data.get("zip_wordlists", [])
    if not isinstance(raw_zip_wordlists, list):
        raise ConfigError("generation.zip_wordlists должен быть списком пар имён")
    zip_wordlists: list[tuple[str, str]] = []
    paired_names: set[str] = set()
    for index, raw_pair in enumerate(raw_zip_wordlists):
        context = f"generation.zip_wordlists[{index}]"
        if not isinstance(raw_pair, list) or len(raw_pair) != 2:
            raise ConfigError(f"{context}: нужны ровно два имени словарей")
        left, right = raw_pair
        if left == right:
            raise ConfigError(f"{context}: укажите два разных имени словарей")
        for name in (left, right):
            if not isinstance(name, str) or not WORDLIST_NAME_RE.fullmatch(name):
                raise ConfigError(f"{context}: некорректное имя словаря {name!r}")
            if name not in wordlists:
                raise ConfigError(f"{context}: словарь {name!r} не подключён")
            if name in paired_names:
                raise ConfigError(
                    f"Словарь {name!r} указан в нескольких попарных группах"
                )
            paired_names.add(name)
        zip_wordlists.append((left, right))

    result_filters_data = _mapping(data.get("result_filters", {}), "result_filters")
    result_filters = _parse_filters(
        result_filters_data,
        "result_filters",
        allow_control_flag=True,
    )

    output_data = _mapping(data.get("output", {}), "output")
    _check_keys(output_data, {"path", "encoding", "overwrite"}, "output")
    raw_output_path = output_data.get("path", "candidates.txt")
    if raw_output_path == "-":
        output_path = Path("-")
    else:
        output_path = _resolve_path(base_path, raw_output_path, "output.path")
    output_encoding = _validate_encoding(output_data.get("encoding", "utf-8"), "output.encoding")
    overwrite = _strict_bool(output_data.get("overwrite", False), "output.overwrite")

    return GeneratorConfig(
        base_path=base_path.resolve(),
        wordlists=wordlists,
        charsets=charsets,
        patterns=tuple(patterns),
        mutations=mutations,
        generation=GenerationSettings(
            confirm_above=confirm_above,
            max_passwords=max_passwords,
            zip_wordlists=tuple(zip_wordlists),
        ),
        output=OutputSettings(
            path=output_path,
            encoding=output_encoding,
            overwrite=overwrite,
        ),
        result_filters=result_filters,
        source_data=dict(raw_data),
    )


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8-sig")
        loaded = yaml.load(text, Loader=UniqueKeySafeLoader)
    except ConfigError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read YAML config {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError("Top-level YAML value must be a mapping")
    return loaded


def load_config(path: Path) -> GeneratorConfig:
    path = path.resolve()
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise ConfigError("Configuration file must use .yaml or .yml")
    data = load_yaml_mapping(path)
    config = config_from_mapping(data, base_path=path.parent)
    if config.output.path != Path("-") and config.output.path.resolve() == path:
        raise ConfigError(f"Output path cannot overwrite the config file: {path}")
    return config


def dump_yaml_mapping(
    data: Mapping[str, Any],
    path: Path,
    *,
    overwrite: bool = False,
) -> None:
    """Atomically save YAML without exposing a truncated configuration file."""

    path = path.resolve()
    if path.exists() and not overwrite:
        raise ConfigError(f"Config file already exists and overwrite is disabled: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        dict(data),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    descriptor, raw_temporary_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".part",
        dir=str(path.parent),
    )
    temporary_path = Path(raw_temporary_path)
    completed = False
    try:
        handle = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            errors="strict",
            newline="\n",
        )
        descriptor = -1
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            publish_file(temporary_path, path, overwrite=overwrite)
        except FileExistsError as exc:
            raise ConfigError(
                f"Config file appeared while saving and overwrite is disabled: {path}"
            ) from exc
        completed = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not completed:
            temporary_path.unlink(missing_ok=True)
