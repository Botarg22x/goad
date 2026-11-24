from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from authchecker.loaders import (
    _remove_line_ending,
    iter_credentials,
    load_logins,
    load_passwords,
)


class LoaderTests(unittest.TestCase):
    def test_password_loader_strips_only_crlf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.txt")
            path.write_bytes(b"  padded  \r\n\tTabbed\n\r\nlast ")
            self.assertEqual(
                list(load_passwords(path)),
                ["  padded  ", "\tTabbed", "", "last "],
            )

    def test_password_loader_removes_exactly_one_physical_ending(self) -> None:
        self.assertEqual(_remove_line_ending("value\r\r\n"), "value\r")
        self.assertEqual(_remove_line_ending("value\n\n"), "value\n")

    def test_password_encoding_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "passwords.txt")
            path.write_bytes("пароль\r\n".encode("cp1251"))
            self.assertEqual(list(load_passwords(path, encoding="cp1251")), ["пароль"])

    def test_logins_are_strict_utf8_and_preserve_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "logins.txt")
            path.write_bytes(" пользователь \r\nadmin\n".encode("utf-8"))
            self.assertEqual(list(load_logins(path)), [" пользователь ", "admin"])
            path.write_bytes(b"\xff\n")
            with self.assertRaises(UnicodeDecodeError):
                list(load_logins(path))

    def test_credentials_are_streamed_as_cartesian_product(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            logins = Path(directory, "logins.txt")
            passwords = Path(directory, "passwords.txt")
            logins.write_text("alice\nbob\n", encoding="utf-8", newline="")
            passwords.write_text("one\ntwo\n", encoding="utf-8", newline="")
            pairs = [(item.username, item.password) for item in iter_credentials(logins, passwords)]
            self.assertEqual(
                pairs,
                [("alice", "one"), ("alice", "two"), ("bob", "one"), ("bob", "two")],
            )

    def test_inline_logins_can_replace_login_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            passwords = Path(directory, "passwords.txt")
            passwords.write_text("one\ntwo\n", encoding="utf-8", newline="")
            pairs = [
                (item.username, item.password)
                for item in iter_credentials(
                    None,
                    passwords,
                    login_values=("alice", "bob"),
                )
            ]
            self.assertEqual(
                pairs,
                [("alice", "one"), ("alice", "two"), ("bob", "one"), ("bob", "two")],
            )

    def test_inline_passwords_can_replace_password_file(self) -> None:
        pairs = [
            (item.username, item.password)
            for item in iter_credentials(
                None,
                None,
                login_values=("alice", "bob"),
                password_values=("wrong", "password123"),
            )
        ]
        self.assertEqual(
            pairs,
            [
                ("alice", "wrong"),
                ("alice", "password123"),
                ("bob", "wrong"),
                ("bob", "password123"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
