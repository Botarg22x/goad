import _support

from pathlib import Path
from unittest import TestCase

from goad.config import ConfigError, load_config, parse_config


class ConfigTests(TestCase):
    def test_shipped_pipeline_example_is_valid(self):
        config = load_config(_support.PROJECT_ROOT / "examples" / "pipeline.toml")
        self.assertTrue(all(stage.enabled for stage in config.stages.values()))
        self.assertEqual(config.stages["logins"].cwd, "login_gen_module_2")
        self.assertNotIn("--config", config.stages["logins"].args)
        self.assertEqual(config.stages["logins"].args[:4], (
            "--company", "SignCorp", "--domain", "signcorp.test"
        ))
        self.assertIn("config_generator.yaml", config.stages["passwords"].args)
        self.assertIn("katana", config.stages["discover"].args)
        self.assertEqual(config.stages["check"].args[0], "plan")

    def test_valid_config_defaults_unspecified_stages_to_disabled(self):
        config = parse_config(
            {
                "schema_version": 1,
                "output_dir": "out",
                "stages": {
                    "passwords": {"args": ["--count", "10"], "cwd": "module1"},
                },
            },
            base_dir=Path("/tmp/example"),
        )
        self.assertTrue(config.stages["passwords"].enabled)
        self.assertFalse(config.stages["check"].enabled)
        self.assertEqual(config.stages["passwords"].args, ("--count", "10"))
        self.assertEqual(config.stages["passwords"].cwd, "module1")

    def test_rejects_unknown_stage(self):
        with self.assertRaisesRegex(ConfigError, "unknown stage"):
            parse_config(
                {"schema_version": 1, "stages": {"typo": {}}},
                base_dir=Path.cwd(),
            )

    def test_rejects_non_string_argument(self):
        with self.assertRaisesRegex(ConfigError, "array of strings"):
            parse_config(
                {
                    "schema_version": 1,
                    "stages": {"logins": {"args": [1]}},
                },
                base_dir=Path.cwd(),
            )

