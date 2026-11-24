from __future__ import annotations

import unittest

from logingen.config import config_from_dict
from logingen.generator import generate
from logingen.inference import infer_person_pattern_candidates, infer_person_patterns
from logingen.translit import transliterate_variants


class TransliterationTests(unittest.TestCase):
    def test_transliterates_cyrillic_name(self) -> None:
        config = config_from_dict({})
        self.assertEqual(transliterate_variants("Иванов", config.transliteration), ("ivanov",))

    def test_supports_configurable_variants(self) -> None:
        config = config_from_dict({"transliteration": {"х": ["h", "kh"]}})
        self.assertEqual(transliterate_variants("Харитон", config.transliteration), ("hariton", "khariton"))

    def test_generates_common_spelling_variants_by_default(self) -> None:
        config = config_from_dict({})
        self.assertEqual(transliterate_variants("Сергей", config.transliteration), ("sergey", "sergei"))
        self.assertEqual(transliterate_variants("Щука", config.transliteration), ("schuka", "shchuka"))
        self.assertEqual(transliterate_variants("Пётр", config.transliteration), ("petr", "pyotr"))

    def test_limit_prioritizes_single_letter_alternatives(self) -> None:
        config = config_from_dict({})
        self.assertEqual(
            transliterate_variants("Йёя", config.transliteration, max_variants=4),
            ("yeya", "yeia", "yyoya", "ieya"),
        )


class GeneratorTests(unittest.TestCase):
    def test_generates_login_variants_from_found_person(self) -> None:
        config = config_from_dict(
            {
                "output": {"kind": "login"},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{firstname}.{lastname}"]},
                "people": [{"firstname": "Сергей", "lastname": "Щербаков"}],
            }
        )

        result = generate(config)

        self.assertEqual(
            result.candidates,
            (
                "sergey.scherbakov",
                "sergey.shcherbakov",
                "sergei.scherbakov",
                "sergei.shcherbakov",
            ),
        )

    def test_generates_login_and_email_patterns(self) -> None:
        config = config_from_dict(
            {
                "company": "Компания",
                "domains": ["company.ru"],
                "output": {"kind": "both"},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{f}.{lastname}", "{lastname}.{firstname}"]},
                "people": [{"firstname": "Иван", "lastname": "Иванов", "patronymic": "Иванович"}],
            }
        )

        result = generate(config)

        self.assertIn("i.ivanov", result.candidates)
        self.assertIn("i.ivanov@company.ru", result.candidates)
        self.assertIn("ivanov.ivan", result.candidates)
        self.assertIn("ivanov.ivan@company.ru", result.candidates)

    def test_respects_per_person_and_total_limits(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "limits": {"total": 2, "per_person": 2},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{f}.{lastname}", "{firstname}.{lastname}", "{lastname}.{f}"]},
                "people": [{"firstname": "Иван", "lastname": "Иванов"}],
            }
        )

        result = generate(config)

        self.assertEqual(result.candidates, ("i.ivanov", "ivan.ivanov"))

    def test_uses_popular_name_files_when_people_are_empty(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "email"},
                "limits": {"total": 2, "per_person": 1},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{f}.{lastname}"]},
                "people": [],
            }
        )

        result = generate(config)

        self.assertEqual(result.candidates[0], "a.ivanov@company.ru")
        self.assertIn("popular name-list fallback", result.stats.warnings[0])

    def test_uses_popular_patronymics_when_person_has_no_patronymic(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "limits": {"total": 5, "per_person": 5},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{f}{p}.{lastname}"]},
                "people": [{"firstname": "sergey", "lastname": "ivanov"}],
            }
        )

        result = generate(config)

        self.assertIn("sa.ivanov", result.candidates)
        self.assertIn("ss.ivanov", result.candidates)
        self.assertTrue(any("popular patronymics fallback" in warning for warning in result.stats.warnings))

    def test_warns_and_skips_person_when_required_fio_part_is_missing(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "generation": {
                    "include_technical_words": False,
                    "use_default_people_when_empty": False,
                },
                "patterns": {"person": ["{f}.{lastname}"]},
                "people": [{"firstname": "Ivan"}],
            }
        )

        result = generate(config)

        self.assertEqual(result.candidates, ())
        self.assertTrue(any("missing lastname" in warning for warning in result.stats.warnings))

    def test_allows_missing_fio_part_when_pattern_does_not_need_it(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{firstname}"]},
                "people": [{"firstname": "Ivan"}],
            }
        )

        result = generate(config)

        self.assertEqual(result.candidates, ("ivan",))

    def test_expands_digit_masks_after_person_pattern(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "limits": {"total": 20, "per_person": 20},
                "generation": {"include_technical_words": False},
                "patterns": {"person": ["{f}.{lastname}?d2026"]},
                "people": [{"firstname": "Ivan", "lastname": "Ivanov"}],
            }
        )

        result = generate(config)

        self.assertIn("i.ivanov02026", result.candidates)
        self.assertIn("i.ivanov92026", result.candidates)

    def test_expands_custom_charset_masks(self) -> None:
        config = config_from_dict(
            {
                "domains": ["company.ru"],
                "output": {"kind": "login"},
                "limits": {"total": 20, "per_person": 20},
                "generation": {
                    "include_technical_words": False,
                    "custom_charsets": {"1": "ab"},
                },
                "patterns": {"person": ["{f}{lastname}?1?1"]},
                "people": [{"firstname": "Ivan", "lastname": "Ivanov"}],
            }
        )

        result = generate(config)

        self.assertIn("iivanovaa", result.candidates)
        self.assertIn("iivanovbb", result.candidates)

    def test_expands_selected_candidate_formats(self) -> None:
        config = config_from_dict(
            {
                "company": "magnit",
                "domains": ["magnit.ru"],
                "output": {"kind": "login"},
                "limits": {"total": 20, "per_person": 20},
                "generation": {
                    "include_technical_words": False,
                    "candidate_formats": [
                        "{login}",
                        "{mail}",
                        "{netbios}\\{login}",
                        "{login}@{ad_domain}",
                    ],
                    "ad_domain": "corp.magnit.ru",
                    "netbios": "MAGNIT",
                },
                "patterns": {"person": ["{f}.{lastname}"]},
                "people": [{"firstname": "Ivan", "lastname": "Ivanov"}],
            }
        )

        result = generate(config)

        self.assertEqual(
            result.candidates[:4],
            (
                "i.ivanov",
                "i.ivanov@magnit.ru",
                "MAGNIT\\i.ivanov",
                "i.ivanov@corp.magnit.ru",
            ),
        )

    def test_infers_pattern_from_public_email_and_person(self) -> None:
        config = config_from_dict(
            {
                "patterns": {"person": ["{f}.{lastname}", "{firstname}.{lastname}"]},
                "people": [{"firstname": "Иван", "lastname": "Иванов"}],
            }
        )

        patterns = infer_person_patterns(("i.ivanov@example.ru",), config.people, config)

        self.assertEqual(patterns, ("{f}.{lastname}",))

    def test_infers_structural_initial_pattern_without_people(self) -> None:
        config = config_from_dict({})

        candidates = infer_person_pattern_candidates(
            ("morozova_uv@example.ru", "dzhafarov_sy@example.ru", "info@example.ru"),
            (),
            config,
        )

        self.assertEqual(candidates[0].pattern, "{lastname}_{f}{p}")
        self.assertEqual(candidates[0].matched_count, 2)

    def test_infers_structural_two_letter_firstname_prefix_pattern_without_people(self) -> None:
        config = config_from_dict({})

        candidates = infer_person_pattern_candidates(
            ("se.ivanov@example.ru", "pa.petrov@example.ru", "info@example.ru"),
            (),
            config,
        )

        self.assertEqual(candidates[0].pattern, "{f2}.{lastname}")
        self.assertEqual(candidates[0].matched_count, 2)


if __name__ == "__main__":
    unittest.main()
