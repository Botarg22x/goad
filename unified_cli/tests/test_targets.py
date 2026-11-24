from __future__ import annotations

import _support  # noqa: F401

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from goad.targets import load_target_urls


class TargetFileTests(TestCase):
    def load(self, value: str) -> tuple[str, ...]:
        with TemporaryDirectory() as directory:
            path = Path(directory, "targets.txt")
            path.write_bytes(value.encode("utf-8"))
            return load_target_urls(path)

    def test_bom_crlf_comments_and_stable_canonical_deduplication(self):
        targets = self.load(
            "\ufeff# Точные страницы входа\r\n\r\n"
            "  HTTPS://Example.COM:443/login?from=one#fragment  \r\n"
            "https://example.com/login?from=one#fragment\r\n"
            "\t# второй сайт\r\n"
            "http://SECOND.example:80/session\r\n"
            "https://example.com/login?from=two\r\n"
        )
        self.assertEqual(targets, (
            "https://example.com/login?from=one#fragment",
            "http://second.example/session",
            "https://example.com/login?from=two",
        ))

    def test_ip_localhost_idna_and_nondefault_ports(self):
        targets = self.load(
            "http://127.0.0.1:8080/login\n"
            "http://[0:0:0:0:0:0:0:1]:9090/account\n"
            "https://[2001:DB8::1]:443/auth\n"
            "http://LOCALHOST/login\n"
            "https://пример.рф/вход?назад=главная\n"
            "https://example.com./account\n"
        )
        self.assertEqual(targets, (
            "http://127.0.0.1:8080/login",
            "http://[::1]:9090/account",
            "https://[2001:db8::1]/auth",
            "http://localhost/login",
            "https://xn--e1afmkfd.xn--p1ai/вход?назад=главная",
            "https://example.com/account",
        ))

    def test_path_query_escaping_order_and_case_are_preserved(self):
        target = "https://EXAMPLE.com/A%20B/../Login?X=One&x=two&x=%2F&token=private#ignored"
        self.assertEqual(self.load(target), ("https://example.com/A%20B/../Login?X=One&x=two&x=%2F&token=private#ignored",))

    def test_spa_fragments_remain_distinct_exact_targets(self):
        self.assertEqual(self.load(
            "https://example.com/#/login\n"
            "HTTPS://EXAMPLE.COM:443/#/register\n"
            "https://example.com/#/login\n"
        ), ("https://example.com/#/login", "https://example.com/#/register"))

    def test_bad_url_reports_line_number_without_echoing_url_or_secrets(self):
        invalid = [
            "example.com/login?token=private-secret",
            "ftp://example.com/login?token=private-secret",
            "//example.com/login?token=private-secret",
            "https:///login?token=private-secret",
            "https://user:private-secret@example.com/login",
            "https://private-secret@example.com/login",
            "https://@example.com/login?token=private-secret",
            "https://example.com/private-secret path",
            "https://example.com/private-secret\tpath",
            "https://example.com/private-secret\x00path",
            "https://example.com/private-secret\x7fpath",
            "https://example.com/private-secret\x85path",
            "https://example.com/private-secret\u200bpath",
            "https://example.com/private-secret\u2028path",
            "https://example.com\\private-secret/path",
        ]
        for target in invalid:
            with self.subTest(target=target), self.assertRaises(ValueError) as raised:
                self.load("# header\n" + target + "\n")
            self.assertIn("строке 2", str(raised.exception))
            self.assertNotIn("private-secret", str(raised.exception))
            self.assertNotIn(target, str(raised.exception))

    def test_invalid_hosts_and_ports_are_rejected(self):
        invalid = (
            "http://bad_host/login", "http://-bad.example/login", "http://bad-.example/login",
            "http://bad..example/login", "http://example.com../login",
            "http://" + "a" * 64 + ".example/login", "http://%65xample.com/login",
            "http://127.1/login", "http://999.0.0.1/login", "http://127.000.0.1/login",
            "http://999.0.0.1./login", "http://999。0。0。1/login", "http://xn--a.com/login",
            "http://2130706433/login", "http://0x7f000001/login",
            "http://example.com:/login", "http://example.com:abc/login",
            "http://example.com:0/login", "http://example.com:65536/login",
            "http://example.com:-1/login", "http://example.com:+80/login",
            "http://::1/login", "http://[::1]junk/login", "http://[::1]:/login",
            "http://[::1/login", "http://[127.0.0.1]/login", "http://[fe80::1%25eth0]/login",
        )
        for target in invalid:
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "строке 1"):
                self.load(target)

    def test_entire_file_is_validated_before_any_targets_are_returned(self):
        with self.assertRaisesRegex(ValueError, "строке 3"):
            self.load("https://valid.example/login\nhttps://also-valid.example/login\nnot-a-url\n")

    def test_no_dns_or_network_is_used_for_valid_or_invalid_targets(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("no DNS")), patch("socket.socket", side_effect=AssertionError("no network")):
            self.assertEqual(self.load("https://does-not-exist.invalid/login"), ("https://does-not-exist.invalid/login",))
            with self.assertRaises(ValueError):
                self.load("https://bad_host/login")

    def test_missing_directory_empty_and_invalid_utf8_have_clear_russian_errors(self):
        with TemporaryDirectory() as directory:
            path = Path(directory, "targets.txt")
            with self.assertRaisesRegex(ValueError, "не найден"):
                load_target_urls(path)
            with self.assertRaisesRegex(ValueError, "каталог"):
                load_target_urls(Path(directory))
            for content in (b"", b"\xef\xbb\xbf\r\n# comment\r\n  \t\r\n"):
                path.write_bytes(content)
                with self.assertRaisesRegex(ValueError, "пуст"):
                    load_target_urls(path)
            path.write_bytes(b"https://valid.example/login\n\xff\xfe")
            with self.assertRaisesRegex(ValueError, "UTF-8"):
                load_target_urls(path)

    def test_permission_error_is_not_exposed_as_a_traceback_or_raw_exception(self):
        with patch.object(Path, "read_bytes", side_effect=PermissionError("sensitive operating-system details")):
            with self.assertRaisesRegex(ValueError, "Нет доступа") as raised:
                load_target_urls(Path("targets.txt"))
            self.assertNotIn("sensitive", str(raised.exception))

    def test_embedded_carriage_return_is_not_accepted_as_a_line_separator(self):
        with self.assertRaisesRegex(ValueError, "строке 1"):
            self.load("https://example.com/login\rhttps://other.example/login\n")
