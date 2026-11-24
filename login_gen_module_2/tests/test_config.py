from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from logingen.config import config_from_dict
from logingen.models import AutoConfig, DEFAULT_USER_AGENT


class ConfigTests(unittest.TestCase):
    def test_browser_crawl_is_enabled_by_default(self) -> None:
        config = config_from_dict({})

        self.assertTrue(config.auto.browser_crawl)
        self.assertTrue(config.auto.browser_manual_access)
        self.assertEqual(config.auto.browser_user_data_dir, Path("output/browser_profile"))

    def test_default_user_agent_is_browser_like_in_cli_and_config(self) -> None:
        self.assertEqual(AutoConfig().user_agent, DEFAULT_USER_AGENT)
        self.assertEqual(config_from_dict({}).auto.user_agent, DEFAULT_USER_AGENT)
        self.assertTrue(DEFAULT_USER_AGENT.startswith("Mozilla/5.0 "))

    def test_explicit_user_agent_still_overrides_default(self) -> None:
        self.assertEqual(
            config_from_dict({"auto": {"user_agent": "MyAuditClient/1.0"}}).auto.user_agent,
            "MyAuditClient/1.0",
        )

    def test_legacy_generated_user_agent_is_migrated_to_browser_default(self) -> None:
        self.assertEqual(
            config_from_dict({"auto": {"user_agent": "logingen/0.1 authorized-public-audit"}}).auto.user_agent,
            DEFAULT_USER_AGENT,
        )

    def test_loads_technical_words_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "technical_words"
            path.write_text("admin\n# comment\nsupport\nadmin\n", encoding="utf-8")

            config = config_from_dict({"technical_words_path": str(path), "technical_words": ["helpdesk"]})

        self.assertEqual(config.technical_words, ("helpdesk", "admin", "support"))

    def test_missing_technical_words_file_is_config_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "Technical words file not found"):
            config_from_dict({"technical_words_path": "missing-technical-words"})


if __name__ == "__main__":
    unittest.main()
