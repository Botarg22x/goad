from __future__ import annotations

import base64
import hashlib
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authchecker.browser_tls import browser_tls_args


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for browser CA support")
class BrowserTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.ca = cls.root / "ca.pem"
        cls.leaf = cls.root / "leaf.pem"
        cls._openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Local Browser TLS Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(cls.root / "ca.key"), "-out", str(cls.ca),
        )
        cls._openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-keyout", str(cls.root / "leaf.key"),
            "-out", str(cls.root / "leaf.csr"),
        )
        cls._openssl(
            "x509", "-req", "-in", str(cls.root / "leaf.csr"),
            "-CA", str(cls.ca), "-CAkey", str(cls.root / "ca.key"),
            "-CAcreateserial", "-days", "1", "-copy_extensions", "copy",
            "-out", str(cls.leaf),
        )
        cls.leaf_der = ssl.PEM_cert_to_DER_cert(cls.leaf.read_text())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    @staticmethod
    def _openssl(*args: str) -> bytes:
        return subprocess.run(
            ["openssl", *args], capture_output=True, check=True, timeout=10,
        ).stdout

    def _private_key_pin(self, filename: str) -> str:
        public_key = self._openssl(
            "pkey", "-in", str(self.root / filename), "-pubout", "-outform", "DER",
        )
        return base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii")

    def test_native_tls_is_untouched_without_explicit_ca(self) -> None:
        with patch("authchecker.browser_tls.http.client.HTTPSConnection") as connection:
            self.assertEqual(
                browser_tls_args(
                    "https://example.test/login", ca_cert=None,
                    proxy=None, timeout_seconds=5,
                ),
                [],
            )
        connection.assert_not_called()

    def test_https_proxy_preflight_checks_ca_and_hostname_without_http_request(self) -> None:
        with patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.sock.getpeercert.return_value = self.leaf_der
            arguments = browser_tls_args(
                "https://localhost:8443/login?next=profile",
                ca_cert=self.ca, proxy="http://127.0.0.1:8085", timeout_seconds=5,
            )
        factory.assert_called_once()
        self.assertEqual(factory.call_args.args, ("127.0.0.1", 8085))
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(len(context.get_ca_certs()), 1)
        connection.set_tunnel.assert_called_once_with("localhost", 8443)
        connection.connect.assert_called_once_with()
        connection.request.assert_not_called()
        connection.send.assert_not_called()
        connection.close.assert_called_once_with()
        pins = arguments[0].split("=", 1)[1].split(",")
        self.assertEqual(pins, [
            self._private_key_pin("leaf.key"), self._private_key_pin("ca.key"),
        ])
        self.assertNotIn("--ignore-certificate-errors", arguments)

    def test_rejected_tls_never_returns_pin_and_always_closes_connection(self) -> None:
        with (
            patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory,
            patch("authchecker.browser_tls._certificate_spki_pin") as derive,
        ):
            connection = factory.return_value
            connection.connect.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
            with self.assertRaisesRegex(ValueError, "TLS preflight failed"):
                browser_tls_args(
                    "https://localhost/login", ca_cert=self.ca,
                    proxy=None, timeout_seconds=5,
                )
        derive.assert_not_called()
        connection.close.assert_called_once_with()

    def test_plain_http_does_not_preflight_or_disable_certificate_checks(self) -> None:
        with patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory:
            self.assertEqual(
                browser_tls_args(
                    "http://localhost/login", ca_cert=self.ca,
                    proxy="http://127.0.0.1:8085", timeout_seconds=5,
                ),
                [],
            )
        factory.assert_not_called()

    def test_missing_ca_fails_before_network(self) -> None:
        with patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory:
            with self.assertRaisesRegex(ValueError, "file not found"):
                browser_tls_args(
                    "https://localhost/login", ca_cert=self.root / "absent.pem",
                    proxy=None, timeout_seconds=5,
                )
        factory.assert_not_called()

    def test_non_http_proxy_is_rejected(self) -> None:
        with patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory:
            with self.assertRaisesRegex(ValueError, "--proxy must be http"):
                browser_tls_args(
                    "https://localhost/login", ca_cert=self.ca,
                    proxy="socks5://127.0.0.1:1080", timeout_seconds=5,
                )
        factory.assert_not_called()

    def test_unavailable_openssl_has_actionable_error_before_network(self) -> None:
        with (
            patch("authchecker.browser_tls.shutil.which", return_value=None),
            patch("authchecker.browser_tls.http.client.HTTPSConnection") as factory,
        ):
            with self.assertRaisesRegex(ValueError, "requires the openssl executable"):
                browser_tls_args(
                    "https://localhost/login", ca_cert=self.ca,
                    proxy=None, timeout_seconds=5,
                )
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
