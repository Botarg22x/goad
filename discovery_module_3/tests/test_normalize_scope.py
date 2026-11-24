from __future__ import annotations

import unittest

from authpoints.normalize import (
    credential_query_keys, is_logout_url, normalize_url,
)
from authpoints.scope import Scope


class NormalizeTests(unittest.TestCase):
    def test_normalizes_and_redacts_url(self) -> None:
        self.assertEqual(
            normalize_url(
                "HTTPS://ExAmPle.Test:443/login?token=secret&next=%2Fhome#fragment",
                redact_query=True,
            ),
            "https://example.test/login?token=REDACTED&next=%2Fhome",
        )

    def test_rejects_userinfo_and_non_http_scheme(self) -> None:
        with self.assertRaises(ValueError):
            normalize_url("https://user:password@example.test/")
        with self.assertRaises(ValueError):
            normalize_url("file:///etc/passwd")
        with self.assertRaises(ValueError):
            normalize_url("https://example.test/\nhttps://outside.test/")

    def test_ipv6_url(self) -> None:
        self.assertEqual(normalize_url("http://[2001:db8::1]:80"), "http://[2001:db8::1]/")

    def test_limits_url_length_without_echoing_secret(self) -> None:
        secret = "do-not-print"
        with self.assertRaises(ValueError) as caught:
            normalize_url("https://example.test/?token=" + secret + "x" * 9000)
        self.assertNotIn(secret, str(caught.exception))

    def test_redaction_matches_whole_key_and_covers_sso_values(self) -> None:
        normalized = normalize_url(
            "https://example.test/callback?outside=ok&postcode=123&author=me&"
            "state=abc&nonce=def&SAMLResponse=payload&RelayState=return",
            redact_query=True,
        )
        self.assertIn("outside=ok", normalized)
        self.assertIn("postcode=123", normalized)
        self.assertIn("author=me", normalized)
        self.assertIn("state=REDACTED", normalized)
        self.assertIn("nonce=REDACTED", normalized)
        self.assertIn("SAMLResponse=REDACTED", normalized)
        self.assertIn("RelayState=REDACTED", normalized)

    def test_distinguishes_credentials_from_navigation_parameters(self) -> None:
        keys = credential_query_keys(
            "https://example.test/?token=secret&state=opaque&return_url=%2Fhome"
        )
        self.assertEqual(keys, ["token"])

    def test_redacts_namespaced_session_and_presigned_credentials(self) -> None:
        url = (
            "https://example.test/?user_password=P1&auth_token=T1&session_id=S1&"
            "password%5Bconfirmation%5D=P2&otp=123456&PHPSESSID=P3&SAMLart=A&"
            "X-Amz-Credential=AKIA%2Fscope&X-Amz-Signature=signed&outside=ok"
        )
        normalized = normalize_url(url, redact_query=True)
        for secret in ("P1", "T1", "S1", "P2", "123456", "P3", "AKIA", "signed"):
            self.assertNotIn(secret, normalized)
        self.assertIn("outside=ok", normalized)
        keys = credential_query_keys(url)
        self.assertIn("user_password", keys)
        self.assertIn("X-Amz-Signature", keys)
        self.assertIn("PHPSESSID", keys)
        self.assertIn("SAMLart", keys)

    def test_compact_and_semicolon_credentials_are_blocked_and_redacted(self) -> None:
        names = [
            "apikey",
            "accesskey",
            "keypairid",
            "authtoken",
            "accesstoken",
            "refreshtoken",
            "idtoken",
            "clientsecret",
            "clientpassword",
            "userpassword",
            "csrftoken",
            "sessionkey",
            "x-api-key",
            "clientassertion",
            "ssotoken",
            "oauthtoken",
            "privatetoken",
            "verificationtoken",
            "onetimepassword",
            "csrfmiddlewaretoken",
            "accesskeyid",
            "awsaccesskeyid",
        ]
        for name in names:
            url = f"https://example.test/login?{name}=do-not-send"
            self.assertEqual(credential_query_keys(url), [name], name)
            self.assertNotIn("do-not-send", normalize_url(url, redact_query=True), name)

        semicolon_url = "https://example.test/login?outside=ok;api%255Fkey=secret"
        self.assertEqual(credential_query_keys(semicolon_url), ["api%5Fkey"])
        self.assertNotIn("secret", normalize_url(semicolon_url, redact_query=True))

    def test_encoded_matrix_and_action_logout_urls_are_blocked(self) -> None:
        logout_urls = [
            "https://example.test/log%6fut",
            "https://example.test/sign%2dout",
            "https://example.test/logout;jsessionid=value",
            "https://example.test/logout.php",
            "https://example.test/wp-login.php?action=logout",
            "https://example.test/account?do=signout",
            "https://example.test/logout.json",
            "https://example.test/logout.xml",
            "https://example.test/logout.action",
            "https://example.test/user.logout",
            "https://example.test/api/logout-v2",
            "https://example.test/?task=user.logout",
            "https://example.test/end-session",
            "https://example.test/endsession",
            "https://example.test/disconnect",
        ]
        for url in logout_urls:
            self.assertTrue(is_logout_url(url), url)

    def test_nested_encoded_credentials_are_blocked_and_redacted(self) -> None:
        urls = [
            "https://example.test/?next=%2Fcallback%3Ftoken%3Dsecret",
            "https://example.test/?next=%252Fcallback%253Ftoken%253Dsecret",
            "https://example.test/?next=x%26access_token%3Dsecret",
        ]
        for url in urls:
            self.assertTrue(credential_query_keys(url), url)
            normalized = normalize_url(url, redact_query=True)
            self.assertNotIn("secret", normalized)
            self.assertIn("REDACTED", normalized)

    def test_default_preserves_query_tokens(self) -> None:
        url = "https://example.test/login?access_token=raw-token&state=opaque"
        self.assertEqual(normalize_url(url), url)

class ScopeTests(unittest.TestCase):
    def test_exact_host_default_and_optional_subdomains(self) -> None:
        exact = Scope.from_inputs(["example.test"], [])
        self.assertTrue(exact.allows_url("https://example.test/login"))
        self.assertFalse(exact.allows_url("https://admin.example.test/login"))

        recursive = Scope.from_inputs(["example.test"], [], include_subdomains=True)
        self.assertTrue(recursive.allows_url("https://admin.example.test/login"))
        self.assertFalse(recursive.allows_url("https://notexample.test/login"))

    def test_network_scope_and_large_network_guard(self) -> None:
        scope = Scope.from_inputs(["192.0.2.0/24"], [])
        self.assertTrue(scope.allows_host("192.0.2.55"))
        self.assertFalse(scope.allows_host("192.0.3.1"))
        with self.assertRaises(ValueError):
            Scope.from_inputs(["10.0.0.0/8"], [])

    def test_nmap_octet_ranges_cannot_bypass_network_guard(self) -> None:
        for target in (
            "0-255.0-255.0-255.0-255",
            "192.168.0-255.1-254",
        ):
            with self.assertRaisesRegex(ValueError, "octet ranges"):
                Scope.from_inputs([target], [])

        scope = Scope.from_inputs(["internal-01.example.test"], [])
        self.assertIn("internal-01.example.test", scope.hosts)

    def test_network_guard_applies_to_aggregate_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "network scope"):
            Scope.from_inputs(
                ["192.0.0.0/21", "198.51.96.0/21", "203.0.112.0/21"],
                [],
            )


if __name__ == "__main__":
    unittest.main()
