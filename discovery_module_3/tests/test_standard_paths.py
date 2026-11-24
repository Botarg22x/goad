from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from authpoints.standard_paths import (
    MAX_STANDARD_PATHS,
    expand_standard_paths,
    load_standard_paths,
)


class StandardPathsTests(unittest.TestCase):
    def test_loads_packaged_defaults(self) -> None:
        paths = load_standard_paths(None)
        self.assertIn("/login", paths)
        self.assertIn("/wp-login.php", paths)
        self.assertIn("/robots.txt", paths)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertTrue(all(path.startswith("/") and not path.startswith("//") for path in paths))

    def test_custom_file_replaces_defaults_and_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.txt"
            path.write_text(
                "\ufeff# custom paths\n/custom-login\n\n/custom-login\n /portal/auth \n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_standard_paths(path),
                ["/custom-login", "/portal/auth"],
            )

    def test_rejects_unsafe_paths(self) -> None:
        unsafe = [
            "login",
            "//outside.test/login",
            "https://outside.test/login",
            "/login#fragment",
            "/../login",
            "/safe/%2e%2e/login",
            "/safe/%252e%252e/login",
            "/%2f%2foutside.test/login",
            "/logout",
            "/bad\x00path",
            "/bad%0apath",
            "/bad\\path",
            "/bad%escape",
        ]
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(ValueError):
                expand_standard_paths(["https://example.test/"], [value])

    def test_query_credentials_in_custom_paths_are_not_blocked(self) -> None:
        paths = [
            "/next?password=secret",
            "/next?continue=https%3A%2F%2Fexample.test%2F%3Ftoken%3Dsecret",
        ]
        self.assertEqual(
            expand_standard_paths(["https://example.test/"], paths),
            ["https://example.test" + path for path in paths],
        )

    def test_rejects_more_than_limit(self) -> None:
        paths = [f"/login/{index}" for index in range(MAX_STANDARD_PATHS + 1)]
        with self.assertRaisesRegex(ValueError, "more than 2000"):
            expand_standard_paths(["https://example.test/"], paths)

    def test_expands_each_unique_origin_and_preserves_nonstandard_ports(self) -> None:
        expanded = expand_standard_paths(
            [
                "https://Example.test:8443/base?ignored=yes",
                "https://example.test:8443/another",
                "http://[::1]:8080/root",
            ],
            ["/login", "/auth?client_id=public", "/login"],
        )
        self.assertEqual(
            expanded,
            [
                "https://example.test:8443/login",
                "https://example.test:8443/auth?client_id=public",
                "http://[::1]:8080/login",
                "http://[::1]:8080/auth?client_id=public",
            ],
        )

    def test_rejects_invalid_origin(self) -> None:
        with self.assertRaises(ValueError):
            expand_standard_paths(["ftp://example.test/"], ["/login"])


if __name__ == "__main__":
    unittest.main()
