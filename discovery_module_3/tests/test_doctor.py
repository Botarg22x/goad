from __future__ import annotations

import unittest

from authpoints.doctor import _parse_version


class DoctorTests(unittest.TestCase):
    def test_parses_katana_versions(self) -> None:
        self.assertEqual(_parse_version("katana version v1.6.1"), (1, 6, 1))
        self.assertEqual(_parse_version("v2.0.0-dev"), (2, 0, 0))
        self.assertIsNone(_parse_version("development build"))


if __name__ == "__main__":
    unittest.main()
