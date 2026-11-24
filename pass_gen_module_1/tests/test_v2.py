from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from password_generator.cli import build_from_config_parser, build_parser, main
from password_generator.config import (
    BUILTIN_CHARSETS,
    ConfigError,
    MutationConfig,
    MutationOperation,
    WordlistSpec,
    config_from_mapping,
    load_yaml_mapping,
    load_config,
)
from password_generator.help_loader import _deep_merge, help_value, load_help
from password_generator.limits import MAX_CANDIDATE_LENGTH
from password_generator.mutations import (
    MutationEngine,
    apply_hashcat_rule,
    url_encode_specials,
)
from password_generator.patterns import compile_pattern
from password_generator.pipeline import (
    DiskDeduplicator,
    GenerationStats,
    build_plan,
    iter_candidates,
    write_candidates,
)


class InteractiveInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class PatternTests(unittest.TestCase):
    def test_hashcat_builtin_charset_sizes(self) -> None:
        self.assertEqual(len(BUILTIN_CHARSETS["s"]), 33)
        self.assertEqual(len(BUILTIN_CHARSETS["a"]), 95)

    def test_short_charset_does_not_consume_literal_suffix(self) -> None:
        compiled = compile_pattern(
            "word?dkey",
            wordlists={},
            charsets=BUILTIN_CHARSETS,
        )
        self.assertEqual(compiled.cardinality({}), 10)
        values = list(compiled.generate({}))
        self.assertEqual(values[0], "word0key")
        self.assertEqual(values[-1], "word9key")

    def test_escaping_and_named_charset(self) -> None:
        compiled = compile_pattern(
            "??{{x}}?{cyrillic_upper}",
            wordlists={},
            charsets=BUILTIN_CHARSETS,
        )
        self.assertEqual(compiled.cardinality({}), 33)
        self.assertTrue(next(compiled.generate({})).startswith("?{x}"))

    def test_repeated_wordlist_name_reuses_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "names.txt"
            path.write_text("admin\nuser\n", encoding="utf-8")
            source = WordlistSpec(name="names", path=path)
            compiled = compile_pattern(
                "{names}_{names}",
                wordlists={"names": source},
                charsets=BUILTIN_CHARSETS,
            )
            self.assertEqual(list(compiled.generate({"names": source})), ["admin_admin", "user_user"])

    def test_zipped_wordlists_bind_matching_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names_path = base / "names.txt"
            years_path = base / "years.txt"
            names_path.write_text("admin\nuser\n", encoding="utf-8")
            years_path.write_text("2025\n2026\n", encoding="utf-8")
            sources = {
                "names": WordlistSpec(name="names", path=names_path),
                "years": WordlistSpec(name="years", path=years_path),
            }
            compiled = compile_pattern(
                "{names}{years}", wordlists=sources, charsets=BUILTIN_CHARSETS,
                zip_wordlists=(("names", "years"),),
            )
            ordinary = compile_pattern(
                "{names}{years}", wordlists=sources, charsets=BUILTIN_CHARSETS,
            )
            self.assertEqual(
                list(ordinary.generate(sources)),
                ["admin2025", "admin2026", "user2025", "user2026"],
            )
            self.assertEqual(
                compiled.cardinality(
                    {"names": 2, "years": 2}, {("names", "years"): 2}
                ),
                2,
            )
            self.assertEqual(
                list(compiled.generate(sources)), ["admin2025", "user2026"]
            )

    def test_two_zip_pairs_remain_independent_of_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            sources = {}
            for name, words in {
                "first": "a\nb\n", "second": "1\n2\n",
                "third": "x\ny\n", "fourth": "3\n4\n",
            }.items():
                path = base / f"{name}.txt"
                path.write_text(words, encoding="utf-8")
                sources[name] = WordlistSpec(name=name, path=path)
            compiled = compile_pattern(
                "{first}{second}{third}{fourth}",
                wordlists=sources, charsets=BUILTIN_CHARSETS,
                zip_wordlists=(("first", "second"), ("third", "fourth")),
            )
            self.assertEqual(
                list(compiled.generate(sources)),
                ["a1x3", "a1y4", "b2x3", "b2y4"],
            )

    def test_render_length_is_checked_before_join(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.txt"
            path.write_text("x" * (MAX_CANDIDATE_LENGTH // 2 + 1), encoding="utf-8")
            source = WordlistSpec(name="large", path=path)
            compiled = compile_pattern(
                "{large}{large}",
                wordlists={"large": source},
                charsets=BUILTIN_CHARSETS,
            )
            with self.assertRaises(ConfigError):
                next(compiled.generate({"large": source}))


class ConfigTests(unittest.TestCase):
    def test_zip_wordlists_rejects_overlapping_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for name in ("a", "b", "c"):
                (base / f"{name}.txt").write_text("word\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "нескольких попарных группах"):
                config_from_mapping(
                    {
                        "version": 2,
                        "wordlists": {
                            name: {"path": f"{name}.txt"}
                            for name in ("a", "b", "c")
                        },
                        "patterns": ["{a}{b}{c}"],
                        "generation": {
                            "zip_wordlists": [["a", "b"], ["b", "c"]],
                        },
                    },
                    base_path=base,
                )

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text("version: 2\nversion: 2\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_yaml_mapping(path)

    def test_max_lines_counts_physical_lines_before_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text("x\nabcd\nefgh\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {
                        "words": {
                            "path": "words.txt",
                            "max_lines": 2,
                            "min_length": 4,
                        }
                    },
                    "patterns": ["{words}"],
                },
                base_path=base,
            )
            self.assertEqual(config.wordlists["words"].count_words(), 1)

    def test_wordlist_line_has_a_hard_read_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "words.txt"
            path.write_text("x" * (MAX_CANDIDATE_LENGTH + 1), encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {"words": {"path": "words.txt"}},
                    "patterns": ["{words}"],
                },
                base_path=base,
            )
            with self.assertRaises(ConfigError):
                config.wordlists["words"].count_words()

    def test_unknown_config_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {"version": 2, "patterns": ["abc"], "unknown": True},
                    base_path=Path(directory),
                )

    def test_yaml_uses_explicit_true_false_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "version: 2\npatterns: [safe]\noutput:\n  overwrite: yes\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_yaml_rejects_ambiguous_leading_zero_integer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text("safe\n", encoding="utf-8")
            path = base / "config.yaml"
            path.write_text(
                "version: 2\n"
                "wordlists:\n"
                "  words:\n"
                "    path: words.txt\n"
                "    max_lines: 010\n"
                "patterns: ['{words}']\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_mutation_arguments_must_be_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {
                        "version": 2,
                        "mutations": {
                            "rules": [{"type": "append", "value": 2026}],
                        },
                        "patterns": ["safe"],
                    },
                    base_path=Path(directory),
                )

    def test_deduplication_is_not_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {"version": 2, "patterns": ["safe"]},
                base_path=Path(directory),
            )
            self.assertFalse(hasattr(config.generation, "deduplicate"))
            self.assertTrue(config.result_filters.forbid_control_characters)
            with self.assertRaisesRegex(ConfigError, "always enabled"):
                config_from_mapping(
                    {
                        "version": 2,
                        "patterns": ["safe"],
                        "generation": {"deduplicate": "disk"},
                    },
                    base_path=Path(directory),
                )

    def test_default_control_filter_matches_documented_ascii_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {"version": 2, "patterns": ["safe"]},
                base_path=Path(directory),
            )
        for codepoint in tuple(range(0x20)) + (0x7F,):
            with self.subTest(codepoint=codepoint):
                self.assertFalse(config.result_filters.matches("safe" + chr(codepoint)))
        for codepoint in (0x80, 0x9F):
            with self.subTest(codepoint=codepoint):
                self.assertTrue(config.result_filters.matches("safe" + chr(codepoint)))

    def test_explicit_null_max_lines_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("safe\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {
                        "version": 2,
                        "wordlists": {
                            "words": {"path": "words.txt", "max_lines": None},
                        },
                        "patterns": ["{words}"],
                    },
                    base_path=Path(directory),
                )

    def test_non_string_named_charset_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {
                        "version": 2,
                        "charsets": {None: "abc"},
                        "patterns": ["safe"],
                    },
                    base_path=Path(directory),
                )

    def test_non_text_output_codec_is_rejected_during_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {
                        "version": 2,
                        "patterns": ["safe"],
                        "output": {"encoding": "base64_codec"},
                    },
                    base_path=Path(directory),
                )

    def test_non_text_wordlist_codec_is_rejected_during_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text("safe\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                config_from_mapping(
                    {
                        "version": 2,
                        "wordlists": {
                            "words": {
                                "path": "words.txt",
                                "encoding": "hex_codec",
                            },
                        },
                        "patterns": ["{words}"],
                    },
                    base_path=base,
                )


class MutationTests(unittest.TestCase):
    def test_url_encode_specials_encodes_slash(self) -> None:
        self.assertEqual(url_encode_specials("a/b c"), "a%2Fb%20c")

    def test_url_encode_specials_preserves_url_unreserved_characters(self) -> None:
        self.assertEqual(url_encode_specials("a_-.~Я"), "a_-.~Я")

    def test_hashcat_expansion_is_stopped_before_large_allocation(self) -> None:
        with self.assertRaises(ConfigError):
            apply_hashcat_rule("password", "pZ", max_length=100)

    def test_syntax_validation_does_not_assume_eight_character_input(self) -> None:
        config = MutationConfig(
            mode="independent",
            include_original=False,
            operations=(
                MutationOperation("hashcat", "ddddddddddddddddd", "test"),
            ),
        )
        engine = MutationEngine(config, max_candidate_length=200_000)
        self.assertEqual(len(next(engine.mutate("x"))), 131_072)

    def test_independent_mode(self) -> None:
        config = MutationConfig(
            mode="independent",
            include_original=True,
            operations=(
                MutationOperation("custom", {"type": "capitalize_first"}, "test"),
                MutationOperation("custom", {"type": "uppercase"}, "test"),
            ),
        )
        self.assertEqual(list(MutationEngine(config).mutate("aDmin")), ["aDmin", "ADmin", "ADMIN"])

    def test_chained_mode_emits_only_original_and_final(self) -> None:
        config = MutationConfig(
            mode="chained",
            include_original=True,
            operations=(
                MutationOperation("custom", {"type": "capitalize_first"}, "test"),
                MutationOperation(
                    "custom",
                    {"type": "replace", "from": "A", "to": "@"},
                    "test",
                ),
                MutationOperation("custom", {"type": "reverse"}, "test"),
            ),
        )
        self.assertEqual(list(MutationEngine(config).mutate("admin")), ["admin", "nimd@"])


class PipelineTests(unittest.TestCase):
    def test_plan_accepts_base_candidate_at_hard_length_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["x" * MAX_CANDIDATE_LENGTH],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].base_candidates, 1)

    def test_plan_rejects_oversized_literal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["x" * (MAX_CANDIDATE_LENGTH + 1)],
                },
                base_path=Path(directory),
            )
            with self.assertRaisesRegex(
                ConfigError,
                r"Pattern 1.*1,000,001 characters.*1,000,000",
            ):
                build_plan(config)

    def test_plan_rejects_oversized_repeated_wordlist_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            word = "x" * (MAX_CANDIDATE_LENGTH // 2 + 1)
            (base / "large.txt").write_text(word + "\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {
                        "large": {
                            "path": "large.txt",
                        },
                    },
                    "patterns": ["{large}{large}"],
                },
                base_path=base,
            )
            with self.assertRaisesRegex(
                ConfigError,
                r"1,000,002 characters.*1,000,000",
            ):
                build_plan(config)

    def test_nul_cr_lf_are_rejected_even_when_control_filter_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for character in ("\x00", "\r", "\n"):
                with self.subTest(character=repr(character)):
                    config = config_from_mapping(
                        {
                            "version": 2,
                            "patterns": ["safe" + character],
                            "result_filters": {
                                "forbid_control_characters": False,
                            },
                        },
                        base_path=Path(directory),
                    )
                    plan = build_plan(config)
                    with self.assertRaisesRegex(ConfigError, "NUL/CR/LF"):
                        list(iter_candidates(config, plan, GenerationStats()))

    def test_uppercase_plan_counts_only_candidates_that_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "charsets": {"1": "@!"},
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": ["1337?1?1?1"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].base_candidates, 8)
            self.assertEqual(plan.patterns[0].estimated_candidates, 8)
            self.assertFalse(plan.patterns[0].estimate_is_upper_bound)

    def test_no_original_with_noop_uppercase_estimates_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "charsets": {"1": "@!"},
                    "mutations": {
                        "mode": "independent",
                        "include_original": False,
                        "default_apply": True,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": ["1337?1?1?1"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].estimated_candidates, 0)
            self.assertFalse(plan.patterns[0].estimate_is_upper_bound)

    def test_uppercase_plan_counts_partial_charset_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": ["?a"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].base_candidates, 95)
            self.assertEqual(plan.patterns[0].estimated_candidates, 121)
            self.assertFalse(plan.patterns[0].estimate_is_upper_bound)

    def test_uppercase_plan_counts_mixed_custom_charset_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "charsets": {"1": "a@"},
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": ["?1?1?1"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].base_candidates, 8)
            self.assertEqual(plan.patterns[0].estimated_candidates, 15)

    def test_uppercase_plan_analyzes_filtered_wordlist_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text("admin\nADMIN\n123\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {"words": {"path": "words.txt"}},
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": ["{words}"],
                },
                base_path=base,
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].base_candidates, 3)
            self.assertEqual(plan.patterns[0].estimated_candidates, 4)

    def test_each_referenced_wordlist_is_scanned_once_while_planning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text("admin\nADMIN\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {"words": {"path": "words.txt"}},
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [
                            {"type": "uppercase"},
                            {"type": "lowercase"},
                            {"type": "capitalize_first"},
                        ],
                    },
                    "patterns": ["{words}", "{words}{words}"],
                },
                base_path=base,
            )
            original_iter_words = WordlistSpec.iter_words
            opened: list[str] = []

            def counted_iter_words(spec: WordlistSpec):
                opened.append(spec.name)
                yield from original_iter_words(spec)

            with mock.patch.object(WordlistSpec, "iter_words", counted_iter_words):
                build_plan(config)
            self.assertEqual(opened, ["words"])

    def test_repeated_independent_mutations_count_before_global_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [
                            {"type": "uppercase"},
                            {"type": "uppercase"},
                        ],
                    },
                    "patterns": ["admin"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].estimated_candidates, 3)
            stats = GenerationStats()
            self.assertEqual(
                list(iter_candidates(config, plan, stats)),
                ["admin", "ADMIN", "ADMIN"],
            )
            self.assertEqual(stats.mutation_candidates, 3)

    def test_supported_symbolic_estimates_match_streamed_mutations(self) -> None:
        rules = [
            {"type": "uppercase"},
            {"type": "lowercase"},
            {"type": "capitalize_first"},
            {"type": "ru_to_eng"},
            {"type": "url_encode_specials"},
            {"type": "append", "value": ""},
            {"type": "append", "value": "!"},
            {"type": "prepend", "value": ""},
            {"type": "prepend", "value": "!"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "words.txt").write_text(
                "admin\nADMIN\nйцу\na/b\n_-.~\nß\n",
                encoding="utf-8",
            )
            (base / "other.txt").write_text("X\n_\n", encoding="utf-8")
            for rule in rules:
                with self.subTest(rule=rule):
                    config = config_from_mapping(
                        {
                            "version": 2,
                            "charsets": {"1": "a@"},
                            "wordlists": {
                                "words": {"path": "words.txt"},
                                "other": {"path": "other.txt"},
                            },
                            "mutations": {
                                "mode": "independent",
                                "include_original": True,
                                "default_apply": True,
                                "rules": [rule],
                            },
                            "patterns": ["{words}?1{words}{other}"],
                        },
                        base_path=base,
                    )
                    plan = build_plan(config)
                    stats = GenerationStats()
                    list(iter_candidates(config, plan, stats))
                    self.assertFalse(plan.patterns[0].estimate_is_upper_bound)
                    self.assertEqual(
                        plan.patterns[0].estimated_candidates,
                        stats.mutation_candidates,
                    )

    def test_unknown_mutation_effect_remains_an_upper_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": True,
                        "rules": [{"type": "reverse"}],
                    },
                    "patterns": ["aba"],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            self.assertEqual(plan.patterns[0].estimated_candidates, 2)
            self.assertTrue(plan.patterns[0].estimate_is_upper_bound)

    def test_disk_deduplication_translates_sqlite_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            deduplicator = DiskDeduplicator(Path(directory))
            real_connection = deduplicator._connection
            fake_connection = mock.Mock()
            fake_connection.execute.side_effect = sqlite3.OperationalError("disk full")
            deduplicator._connection = fake_connection
            try:
                with self.assertRaises(ConfigError):
                    deduplicator.add("candidate")
            finally:
                deduplicator._connection = real_connection
                deduplicator.close()

    def test_atomic_output_and_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_text("old\nsame\nold\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["same", "new", "same"],
                    "generation": {"confirm_above": 100},
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            plan = build_plan(config)
            stats = write_candidates(config, plan)
            self.assertEqual(output.read_text(encoding="utf-8"), "old\nsame\nnew\n")
            self.assertEqual(stats.existing_candidates, 3)
            self.assertEqual(stats.existing_duplicate_candidates, 1)
            self.assertEqual(stats.duplicate_candidates, 2)
            self.assertEqual(stats.written_candidates, 1)

            second_stats = write_candidates(config, plan)
            self.assertEqual(output.read_text(encoding="utf-8"), "old\nsame\nnew\n")
            self.assertEqual(second_stats.written_candidates, 0)
            self.assertEqual(second_stats.duplicate_candidates, 3)

    def test_force_atomically_replaces_instead_of_merging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_text("old\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["same", "same"],
                    "output": {"path": "result.txt", "overwrite": True},
                },
                base_path=base,
            )
            stats = write_candidates(config, build_plan(config))
            self.assertEqual(output.read_text(encoding="utf-8"), "same\n")
            self.assertEqual(stats.existing_candidates, 0)
            self.assertEqual(stats.duplicate_candidates, 1)

    def test_merge_normalizes_missing_final_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_text("old", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["new"],
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            write_candidates(config, build_plan(config))
            self.assertEqual(output.read_bytes(), b"old\nnew\n")

    def test_utf16_merge_writes_one_bom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_bytes("старый\r\n".encode("utf-16"))
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["новый"],
                    "output": {"path": "result.txt", "encoding": "utf-16"},
                },
                base_path=base,
            )
            write_candidates(config, build_plan(config))
            raw = output.read_bytes()
            self.assertEqual(raw.count(b"\xff\xfe") + raw.count(b"\xfe\xff"), 1)
            self.assertEqual(output.read_text(encoding="utf-16"), "старый\nновый\n")

    def test_generation_failure_leaves_existing_output_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            original = b"old\r\n"
            output.write_bytes(original)
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["new"],
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )

            def fail_after_partial_write(handle, *_: object) -> None:
                handle.write("partial\n")
                raise ConfigError("injected failure")

            with mock.patch(
                "password_generator.pipeline._write_stream",
                side_effect=fail_after_partial_write,
            ):
                with self.assertRaisesRegex(ConfigError, "injected failure"):
                    write_candidates(config, build_plan(config))
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(list(base.glob("*.part")), [])
            self.assertEqual(list(base.glob("*.sqlite3")), [])

    def test_zip_wordlists_detects_length_change_after_plan_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            left = base / "left.txt"
            right = base / "right.txt"
            output = base / "result.txt"
            left.write_text("admin\nuser\n", encoding="utf-8")
            right.write_text("2025\n2026\n", encoding="utf-8")
            output.write_text("original\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "wordlists": {
                        "left": {"path": "left.txt"},
                        "right": {"path": "right.txt"},
                    },
                    "patterns": ["{left}{right}"],
                    "generation": {"zip_wordlists": [["left", "right"]]},
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            plan = build_plan(config)
            right.write_text("2025\n2026\n2027\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "изменилось после построения плана"):
                write_candidates(config, plan)
            self.assertEqual(output.read_text(encoding="utf-8"), "original\n")

    def test_interrupt_saves_new_candidates_as_separate_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            stderr = io.StringIO()

            def interrupt_after_one(handle, _config, _plan, _dedup, stats) -> None:
                handle.write("ready\ncut-off")
                stats.written_candidates += 1
                raise KeyboardInterrupt

            with (
                mock.patch(
                    "password_generator.pipeline._write_stream",
                    side_effect=interrupt_after_one,
                ),
                redirect_stderr(stderr),
            ):
                result = main(["-p", "ready", "-o", str(output)])
            partial = base / "result.partial.txt"
            self.assertEqual(result, 130)
            self.assertFalse(output.exists())
            self.assertEqual(partial.read_text(encoding="utf-8"), "ready\n")
            self.assertIn(str(partial), stderr.getvalue())
            self.assertEqual(list(base.glob("*.part")), [])

    def test_interrupt_preserves_existing_output_and_prior_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_text("old\n", encoding="utf-8")
            prior_partial = base / "result.partial.txt"
            prior_partial.write_text("prior\n", encoding="utf-8")
            stderr = io.StringIO()

            def interrupt_after_one(handle, _config, _plan, _dedup, stats) -> None:
                handle.write("new\n")
                stats.written_candidates += 1
                raise KeyboardInterrupt

            with (
                mock.patch(
                    "password_generator.pipeline._write_stream",
                    side_effect=interrupt_after_one,
                ),
                redirect_stderr(stderr),
            ):
                result = main(["-p", "new", "-o", str(output)])
            partial = base / "result.partial-2.txt"
            self.assertEqual(result, 130)
            self.assertEqual(output.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(prior_partial.read_text(encoding="utf-8"), "prior\n")
            self.assertEqual(partial.read_text(encoding="utf-8"), "old\nnew\n")
            self.assertIn(str(partial), stderr.getvalue())

    def test_interrupt_keeps_complete_lines_with_utf16_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            stderr = io.StringIO()

            def interrupt_after_one(handle, _config, _plan, _dedup, stats) -> None:
                handle.write("готово\nобрыв")
                stats.written_candidates += 1
                raise KeyboardInterrupt

            with (
                mock.patch(
                    "password_generator.pipeline._write_stream",
                    side_effect=interrupt_after_one,
                ),
                redirect_stderr(stderr),
            ):
                result = main([
                    "-p", "готово", "-o", str(output), "--encoding", "utf-16"
                ])
            self.assertEqual(result, 130)
            self.assertEqual(
                (base / "result.partial.txt").read_text(encoding="utf-16"),
                "готово\n",
            )

    def test_wrong_existing_encoding_leaves_original_bytes_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            original = b"\xff\xfe\xff"
            output.write_bytes(original)
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["new"],
                    "output": {"path": "result.txt", "encoding": "utf-8"},
                },
                base_path=base,
            )
            with self.assertRaises(UnicodeDecodeError):
                write_candidates(config, build_plan(config))
            self.assertEqual(output.read_bytes(), original)

    def test_deduplicator_close_failure_happens_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            original = b"old\n"
            output.write_bytes(original)
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["new"],
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            real_close = DiskDeduplicator.close

            def close_then_fail(instance: DiskDeduplicator) -> None:
                real_close(instance)
                raise ConfigError("injected close failure")

            with mock.patch.object(
                DiskDeduplicator,
                "close",
                autospec=True,
                side_effect=close_then_fail,
            ):
                with self.assertRaisesRegex(ConfigError, "injected close failure"):
                    write_candidates(config, build_plan(config))
            self.assertEqual(output.read_bytes(), original)

    def test_existing_output_race_does_not_overwrite_external_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            output.write_text("old\n", encoding="utf-8")
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["ours"],
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            from password_generator import pipeline

            real_write_stream = pipeline._write_stream

            def competing_write(*args: object, **kwargs: object) -> None:
                real_write_stream(*args, **kwargs)
                output.write_text("competitor\n", encoding="utf-8")

            with mock.patch(
                "password_generator.pipeline._write_stream",
                side_effect=competing_write,
            ):
                with self.assertRaisesRegex(ConfigError, "changed during generation"):
                    write_candidates(config, build_plan(config))
            self.assertEqual(output.read_text(encoding="utf-8"), "competitor\n")

    def test_output_lock_path_cannot_alias_a_rule_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            lock_path = base / ".result.txt.passgen.lock"
            lock_path.write_bytes(b"")
            config = config_from_mapping(
                {
                    "version": 2,
                    "mutations": {
                        "rule_files": [
                            {"path": lock_path.name, "max_rules": "all"},
                        ],
                    },
                    "patterns": ["safe"],
                    "output": {"path": "result.txt"},
                },
                base_path=base,
            )
            with self.assertRaisesRegex(ConfigError, "lock path"):
                write_candidates(config, build_plan(config))
            self.assertEqual(lock_path.read_bytes(), b"")
            self.assertFalse((base / "result.txt").exists())

    def test_no_clobber_publish_loses_race_without_overwriting_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "result.txt"
            config = config_from_mapping(
                {
                    "version": 2,
                    "patterns": ["ours"],
                    "output": {"path": "result.txt", "overwrite": False},
                },
                base_path=base,
            )
            plan = build_plan(config)

            def competing_publish(source: object, destination: object, **_: object) -> None:
                Path(destination).write_text("competitor\n", encoding="utf-8")
                raise FileExistsError(str(destination))

            with mock.patch(
                "password_generator.atomic.os.link",
                side_effect=competing_publish,
            ):
                with self.assertRaises(ConfigError):
                    write_candidates(config, plan)
            self.assertEqual(output.read_text(encoding="utf-8"), "competitor\n")

    def test_pattern_mutations_are_selective(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = config_from_mapping(
                {
                    "version": 2,
                    "mutations": {
                        "mode": "independent",
                        "include_original": True,
                        "default_apply": False,
                        "rules": [{"type": "uppercase"}],
                    },
                    "patterns": [
                        {"value": "admin", "apply_mutations": True},
                        "user",
                    ],
                },
                base_path=Path(directory),
            )
            plan = build_plan(config)
            stats = GenerationStats()
            self.assertEqual(list(iter_candidates(config, plan, stats)), ["admin", "ADMIN", "user"])


class CliTests(unittest.TestCase):
    def test_check_rejects_oversized_wordlist_composition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            word = "x" * (MAX_CANDIDATE_LENGTH // 2 + 1)
            (base / "large.txt").write_text(word + "\n", encoding="utf-8")
            config_path = base / "oversized.yaml"
            config_path.write_text(
                "version: 2\n"
                "wordlists:\n"
                "  large:\n"
                "    path: large.txt\n"
                "patterns:\n"
                '  - "{large}{large}"\n',
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["from-config", str(config_path), "--check"])
            self.assertEqual(result, 2)
            self.assertIn(
                "base candidate of 1,000,002 characters",
                stderr.getvalue(),
            )
            self.assertNotIn("Config is valid", stderr.getvalue())
            self.assertLess(len(stderr.getvalue()), 4096)

    def test_check_rejects_existing_directory_as_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "output"
            output.mkdir()
            config_path = base / "directory-output.yaml"
            config_path.write_text(
                "version: 2\n"
                "patterns:\n"
                "  - safe\n"
                "output:\n"
                "  path: output\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["from-config", str(config_path), "--check"])
            self.assertEqual(result, 2)
            self.assertIn("Output must be a regular file", stderr.getvalue())
            self.assertNotIn("Config is valid", stderr.getvalue())
            self.assertFalse((base / ".output.passgen.lock").exists())

    def test_check_allows_missing_output_parent_without_creating_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config_path = base / "missing-parent.yaml"
            config_path.write_text(
                "version: 2\n"
                "patterns:\n"
                "  - safe\n"
                "output:\n"
                "  path: nested/result.txt\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["from-config", str(config_path), "--check"])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertIn("Config is valid", stderr.getvalue())
            self.assertFalse((base / "nested").exists())

    def test_all_help_parsers_build(self) -> None:
        self.assertIsNotNone(build_parser())
        self.assertIsNotNone(build_from_config_parser())

    def test_from_config_check_and_plan_are_mutually_exclusive(self) -> None:
        parser = build_from_config_parser()
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            parser.parse_args(["config.yaml", "--check", "--plan"])

    def test_all_shipped_configs_validate(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        config_paths = sorted((project_root / "test_configs").glob("*.yaml"))
        config_paths.extend(sorted(project_root.glob("config_*.yaml")))
        self.assertIn(project_root / "config_template.yaml", config_paths)
        self.assertGreater(len(config_paths), 1)
        for config_path in config_paths:
            with self.subTest(config=config_path.name):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    result = main(["from-config", str(config_path), "--check"])
                self.assertEqual(result, 0, stderr.getvalue())

    def test_editable_help_resource_is_loaded(self) -> None:
        self.assertIn("ПАТТЕРНЫ", help_value("quick.description"))

    def test_unified_help_is_localized_from_editable_resource(self) -> None:
        quick_rendered = build_parser().format_help()
        heading, _, body = help_value("quick.description").rstrip().partition("\n")
        body = body.lstrip("\n")
        quick_expected = (
            f"{heading}\n\n"
            f"{help_value('common.usage')}: {help_value('quick.usage')}\n\n"
            f"{body}\n"
        )
        self.assertEqual(quick_rendered, quick_expected)
        self.assertEqual(build_from_config_parser().format_help(), quick_expected)
        for option in (
            "PASSGEN — ГЕНЕРАТОР ПАРОЛЕЙ",
            "ОСНОВНОЕ",
            "ПАТТЕРНЫ",
            "СЛОВАРИ",
            "МУТАЦИИ",
            "ВЫВОД И ОГРАНИЧЕНИЯ",
            "--rule-file",
            "--charset NAME",
            "--wl-max-lines",
            "--yes",
            "--stats",
        ):
            self.assertIn(option, quick_expected)
        for obsolete in ("from-config", "--save-config", "YAML-конфигурация"):
            self.assertNotIn(obsolete, quick_expected)
        self.assertIn(
            "--wordlist names dictionaries/names.txt",
            quick_expected,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["from-config", "--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue(), quick_expected)

    def test_malformed_help_branch_keeps_fallback(self) -> None:
        defaults = {"main": {"description": "fallback"}}
        self.assertEqual(
            _deep_merge(defaults, {"main": "broken"}),
            defaults,
        )

    def test_missing_help_package_uses_builtin_fallback(self) -> None:
        with mock.patch(
            "password_generator.help_loader.resources.files",
            side_effect=ModuleNotFoundError("missing help package"),
        ):
            self.assertIn("Быстрая генерация", load_help()["quick"]["description"])

    def test_output_lock_reports_filesystem_open_failure(self) -> None:
        from password_generator import pipeline

        output = Path("/tmp/passgen-lock-permission-test.txt")
        failure = OSError(errno.EROFS, "Read-only file system")
        with mock.patch("password_generator.pipeline.os.open", side_effect=failure):
            with self.assertRaisesRegex(
                ConfigError,
                "Cannot open output lock .*Read-only file system",
            ):
                with pipeline._OutputLock(output):
                    pass

    @unittest.skipIf(os.name == "nt", "POSIX flock behaviour is tested on POSIX")
    def test_output_lock_reports_an_active_writer(self) -> None:
        from password_generator import pipeline

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.txt"
            with pipeline._OutputLock(output):
                with self.assertRaisesRegex(
                    ConfigError,
                    "Another passgen process is writing output",
                ):
                    with pipeline._OutputLock(output):
                        pass

    def test_quick_plan_does_not_create_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "never-created.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "Password?d",
                        "--output",
                        str(output),
                        "--plan",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())
            self.assertIn(
                "Всего парольных кандидатов ДО применения фильтров "
                "и дедупликации: 10",
                stderr.getvalue(),
            )
            self.assertIn("[Password?d]: 10", stderr.getvalue())

    def test_plan_shows_wordlist_and_global_filters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("admin\nadmin1\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p",
                        "{words}",
                        "--wordlist",
                        "words",
                        str(wordlist),
                        "--wl-min-length",
                        "words",
                        "3",
                        "--wl-max-length",
                        "words",
                        "10",
                        "--wl-require",
                        "words",
                        "lowercase",
                        "--wl-forbid",
                        "words",
                        "digits",
                        "--result-min-length",
                        "5",
                        "--result-max-length",
                        "20",
                        "--plan",
                    ]
                )
            rendered = stderr.getvalue()
            self.assertEqual(result, 0, rendered)
            self.assertIn(
                "Filters: min_length=3; max_length=10; "
                "require=lowercase; forbid=digits",
                rendered,
            )
            self.assertIn(
                "Global filters:\n"
                "  min_length=5; max_length=20; require=none; forbid=none; "
                "forbid_control_characters=true",
                rendered,
            )

    def test_plan_wraps_every_pattern_in_square_brackets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p",
                        "?d'@20267?s",
                        "-p",
                        "22?d",
                        "-p",
                        "{govno}",
                        "--wordlist",
                        "govno",
                        str(wordlist),
                        "--plan",
                    ]
                )
            rendered = stderr.getvalue()
            self.assertEqual(result, 0, rendered)
            self.assertIn("[?d'@20267?s]: 330", rendered)
            self.assertIn("[22?d]: 10", rendered)
            self.assertIn("[{govno}]: 1", rendered)
            self.assertNotIn("\"?d'@20267?s\"", rendered)

    def test_plan_is_shown_by_default_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["-p", "safe", "-o", str(output)])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "safe\n")
            self.assertIn("Generation plan", stderr.getvalue())
            self.assertIn("New candidates written: 1", stderr.getvalue())
            self.assertIn(f"[РЕЗУЛЬТАТ] Пароли сохранены: {output}", stderr.getvalue())

    def test_zip_wordlists_cli_pairs_rows_instead_of_cartesian_product(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names = base / "names.txt"
            years = base / "years.txt"
            output = base / "passwords.txt"
            names.write_text("admin\nuser\n", encoding="utf-8")
            years.write_text("2025\n2026\n", encoding="utf-8")
            args = [
                "-p", "{names}{years}",
                "--wordlist", "names", str(names),
                "--wordlist", "years", str(years),
                "--zip-wordlists", "names,years",
                "-o", str(output),
            ]
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(args)
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"), "admin2025\nuser2026\n"
            )
            self.assertIn("names + years: 2 пар", stderr.getvalue())

    def test_zip_wordlists_filters_drop_whole_physical_pair_without_shifting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names = base / "names.txt"
            years = base / "years.txt"
            output = base / "passwords.txt"
            names.write_text("admin\nx\nuser\n", encoding="utf-8")
            years.write_text("2025\n2026\n2027\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "{names}{years}",
                    "--wordlist", "names", str(names),
                    "--wordlist", "years", str(years),
                    "--wl-min-length", "names", "4",
                    "--zip-wordlists", "names,years",
                    "-o", str(output),
                ])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"), "admin2025\nuser2027\n"
            )
            self.assertIn("names + years: 2 пар", stderr.getvalue())

    def test_zip_wordlists_rejects_unequal_filtered_lengths_in_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names = base / "names.txt"
            years = base / "years.txt"
            output = base / "passwords.txt"
            names.write_text("admin\nuser\n", encoding="utf-8")
            years.write_text("2025\n2026\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "{names}{years}",
                    "--wordlist", "names", str(names),
                    "--wordlist", "years", str(years),
                    "--wl-max-lines", "years", "1",
                    "--zip-wordlists", "names,years",
                    "-o", str(output), "--plan",
                ])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertIn("разное число физических строк", stderr.getvalue())

    def test_zip_wordlists_rejects_pattern_with_only_one_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            names = base / "names.txt"
            years = base / "years.txt"
            names.write_text("admin\n", encoding="utf-8")
            years.write_text("2025\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "{names}",
                    "--wordlist", "names", str(names),
                    "--wordlist", "years", str(years),
                    "--zip-wordlists", "names,years", "--plan",
                ])
            self.assertEqual(result, 2)
            self.assertIn("должна содержать оба попарных словаря", stderr.getvalue())

    def test_stats_show_saved_file_after_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["-p", "admin", "-o", str(output), "--stats"])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertIn("Generation statistics", stderr.getvalue())
            self.assertTrue(stderr.getvalue().rstrip().endswith(
                f"[РЕЗУЛЬТАТ] Пароли сохранены: {output}"
            ))

    def test_max_passwords_stops_after_unique_output_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "admin", "-p", "admin", "-p", "Admin?d?d",
                    "--max-passwords", "3", "-o", str(output), "--stats",
                ])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "admin\nAdmin00\nAdmin01\n")
            self.assertIn("Лимит паролей в итоговом файле: 3", stderr.getvalue())
            self.assertIn("New written:          3", stderr.getvalue())

    def test_max_passwords_counts_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            output.write_text("old\nold\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "admin", "-p", "Admin?d", "--max-passwords", "2",
                    "-o", str(output), "--stats",
                ])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "old\nadmin\n")

    def test_max_passwords_rejects_oversized_existing_output_without_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            original = "old1\nold2\nold3\n"
            output.write_text(original, encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "admin", "--max-passwords", "2", "-o", str(output),
                ])
            self.assertEqual(result, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), original)
            self.assertIn("use --force to replace it", stderr.getvalue())

    def test_max_passwords_with_force_replaces_oversized_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            output.write_text("old1\nold2\nold3\n", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "Admin?d", "--max-passwords", "2",
                    "-o", str(output), "--force",
                ])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "Admin0\nAdmin1\n")

    def test_max_passwords_requires_positive_value(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["-p", "admin", "--max-passwords", "0", "--plan"])
        self.assertEqual(result, 2)
        self.assertIn("generation.max_passwords", stderr.getvalue())

    def test_max_passwords_limits_stdout_without_diagnostics_in_data(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["-p", "?d?d", "--max-passwords", "2", "-o", "-"])
        self.assertEqual(result, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "00\n01\n")
        self.assertIn("Лимит паролей в итоговом файле: 2", stderr.getvalue())

    def test_max_passwords_is_used_for_noninteractive_confirmation_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main([
                    "-p", "?d?d?d", "--max-passwords", "2",
                    "--confirm-above", "2", "-o", str(output),
                ])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "000\n001\n")

    def test_interactive_confirmation_accepts_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            user_input = InteractiveInput("y\n")
            with (
                mock.patch.object(sys, "stdin", user_input),
                redirect_stderr(stderr),
            ):
                result = main(["-p", "admin", "-p", "admin", "-o", str(output)])
            rendered = stderr.getvalue()
            self.assertEqual(result, 0, rendered)
            self.assertEqual(output.read_text(encoding="utf-8"), "admin\n")
            self.assertIn(
                "Начать генерацию? До фильтров и дедупликации: 2. [y/N]",
                rendered,
            )
            self.assertNotIn("Exact result", rendered)

    def test_interactive_confirmation_decline_keeps_output_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "generated.txt"
            stderr = io.StringIO()
            user_input = InteractiveInput("n\n")
            with (
                mock.patch.object(sys, "stdin", user_input),
                mock.patch("password_generator.cli.write_candidates") as write,
                redirect_stderr(stderr),
            ):
                result = main(["-p", "admin", "-o", str(output)])
            self.assertEqual(result, 2)
            write.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn("Generation cancelled by user", stderr.getvalue())
            self.assertEqual(list(base.glob("*.part")), [])
            self.assertEqual(list(base.glob("*.sqlite3")), [])

    def test_interactive_stdout_keeps_confirmation_out_of_candidates(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()
        user_input = InteractiveInput("y\n")
        with (
            mock.patch.object(sys, "stdin", user_input),
            redirect_stderr(stderr),
            redirect_stdout(stdout),
        ):
            result = main(["-p", "admin", "-p", "admin", "-o", "-"])
        self.assertEqual(result, 0, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "admin\n")
        self.assertIn("[РЕЗУЛЬТАТ] Пароли выведены в stdout", stderr.getvalue())
        self.assertIn(
            "Начать генерацию? До фильтров и дедупликации: 2. [y/N]",
            stderr.getvalue(),
        )

    def test_plan_only_does_not_read_interactive_input(self) -> None:
        class FailingInteractiveInput(InteractiveInput):
            def readline(self, *_: object, **__: object) -> str:
                raise AssertionError("--plan must not request confirmation")

        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", FailingInteractiveInput()),
            redirect_stderr(stderr),
        ):
            result = main(["-p", "admin", "-o", "-", "--plan"])
        self.assertEqual(result, 0, stderr.getvalue())
        self.assertIn(
            "Всего парольных кандидатов ДО применения фильтров "
            "и дедупликации: 1",
            stderr.getvalue(),
        )

    def test_yes_does_not_read_interactive_input(self) -> None:
        class FailingInteractiveInput(InteractiveInput):
            def readline(self, *_: object, **__: object) -> str:
                raise AssertionError("--yes must not request confirmation")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "stdin", FailingInteractiveInput()),
                redirect_stderr(stderr),
            ):
                result = main(["-p", "admin", "-o", str(output), "--yes"])
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "admin\n")

    def test_large_noninteractive_run_stops_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated.txt"
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "stdin", io.StringIO()),
                redirect_stderr(stderr),
            ):
                result = main(
                    [
                        "-p",
                        "?d",
                        "-o",
                        str(output),
                        "--confirm-above",
                        "1",
                    ]
                )
            rendered = stderr.getvalue()
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertIn("exceeds confirm_above", rendered)

    def test_generate_subcommand_was_removed(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            main(["generate", "-p", "safe", "--plan"])
        self.assertIn("unrecognized arguments: generate", stderr.getvalue())

    def test_quick_plan_reports_noop_uppercase_exactly(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(
                [
                    "-p",
                    "1337?1?1?1",
                    "--charset1",
                    "@!",
                    "--mutation",
                    "uppercase",
                    "--plan",
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("8 base -> 8 after mutations (exact)", stderr.getvalue())
        self.assertNotIn("upper bound", stderr.getvalue())

    def test_saved_cli_config_rebases_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wordlist = base / "words.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            nested = base / "saved"
            config_path = nested / "quick.yaml"
            output = base / "result.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "{words}",
                        "--wordlist",
                        "words",
                        str(wordlist),
                        "--output",
                        str(output),
                        "--save-config",
                        str(config_path),
                        "--plan",
                    ]
                )
            self.assertEqual(result, 0)
            loaded = load_config(config_path)
            self.assertEqual(loaded.wordlists["words"].path, wordlist.resolve())

    def test_output_override_cannot_overwrite_source_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            original = "version: 2\npatterns: [safe]\n"
            config_path.write_text(original, encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "from-config",
                        str(config_path),
                        "--output",
                        str(config_path),
                        "--force",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertEqual(config_path.read_text(encoding="utf-8"), original)

    def test_saved_config_cannot_share_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "same.yaml"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "safe",
                        "--output",
                        str(target),
                        "--save-config",
                        str(target),
                        "--force",
                        "--plan",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertFalse(target.exists())

    def test_saved_config_cannot_overwrite_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            original = "admin\n"
            wordlist.write_text(original, encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "{words}",
                        "--wordlist",
                        "words",
                        str(wordlist),
                        "--save-config",
                        str(wordlist),
                        "--force",
                        "--plan",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertEqual(wordlist.read_text(encoding="utf-8"), original)

    def test_invalid_pattern_is_not_saved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "invalid.yaml"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "?9",
                        "--save-config",
                        str(target),
                        "--plan",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertFalse(target.exists())

    def test_saved_config_requires_yaml_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.toml"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "--pattern",
                        "safe",
                        "--save-config",
                        str(target),
                        "--plan",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertFalse(target.exists())

    def test_overwrite_config_requires_save_config(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(
                ["--pattern", "safe", "--overwrite-config", "--plan"]
            )
        self.assertEqual(result, 2)
        self.assertIn("requires --save-config", stderr.getvalue())

    def test_comma_separated_and_repeated_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p",
                        "admin",
                        "--mutation",
                        "uppercase,",
                        "reverse",
                        "--mutation",
                        "replace=a,@",
                        "-o",
                        str(output),
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "admin\nADMIN\nnimda\n@dmin\n",
            )

    def test_comma_separated_parameterized_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p", "admin",
                        "--mutation", "uppercase,replace=a,@,append=2026,reverse",
                        "-o", str(output),
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "admin\nADMIN\n@dmin\nadmin2026\nnimda\n",
            )

    def test_escaped_comma_in_parameterized_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p", "admin",
                        "--mutation", r"append=foo\,reverse,uppercase",
                        "-o", str(output),
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "admin\nadminfoo,reverse\nADMIN\n",
            )

    def test_escaped_comma_in_replace_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    ["-p", "a,b", "--mutation", r"replace=a\,b,x", "-o", str(output)]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "a,b\nx\n")

    def test_unrecognized_comma_segment_remains_append_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    ["-p", "admin", "--mutation", "append=foo,bar", "-o", str(output)]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(output.read_text(encoding="utf-8"), "admin\nadminfoo,bar\n")

    def test_parameterized_mutation_preserves_trailing_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.txt"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "-p",
                        "admin",
                        "--mutation",
                        "append= ",
                        "-o",
                        str(output),
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                "admin\nadmin \n",
            )

    def test_stdout_is_utf8_even_with_legacy_python_io_encoding(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONIOENCODING"] = "cp1251"
        script = (
            "from password_generator.cli import main; "
            "raise SystemExit(main(['-p', '?1', "
            "'--charset1', 'йц', '-o', '-']))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        self.assertEqual(completed.stdout, "й\nц\n".encode("utf-8"))

    def test_stdout_honors_explicit_output_encoding(self) -> None:
        script = (
            "from password_generator.cli import main; "
            "raise SystemExit(main(['-p', '?1', "
            "'--charset1', 'й', '-o', '-', '--encoding', 'utf-16', "
            "]))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        self.assertEqual(completed.stdout, "й\n".encode("utf-16"))


if __name__ == "__main__":
    unittest.main()
