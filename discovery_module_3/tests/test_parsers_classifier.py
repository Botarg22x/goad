from __future__ import annotations

import unittest
from pathlib import Path

from authpoints.classifier import classify_service, classify_web, web_seed_from_service
from authpoints.models import FindingKind, Report, ServiceObservation, Source, WebObservation
from authpoints.parsers.katana_jsonl import parse_katana_jsonl
from authpoints.parsers.nmap_xml import parse_nmap_xml


FIXTURES = Path(__file__).parent / "fixtures"


class NmapParserTests(unittest.TestCase):
    def test_accepts_standard_nmap_doctype(self) -> None:
        xml = b"""<?xml version='1.0' encoding='UTF-8'?>
        <!DOCTYPE nmaprun>
        <nmaprun><host><status state='up'/>
        <address addr='192.0.2.8' addrtype='ipv4'/><ports>
        <port protocol='tcp' portid='22'><state state='open'/>
        <service name='ssh'/></port></ports></host></nmaprun>"""
        self.assertEqual(parse_nmap_xml(xml)[0].port, 22)

    def test_parses_only_open_services(self) -> None:
        services = parse_nmap_xml((FIXTURES / "nmap.xml").read_bytes())
        self.assertEqual([service.port for service in services], [22, 443, 3306])
        self.assertEqual(web_seed_from_service(services[1]), "https://example.test/")

        ssh = classify_service(services[0])
        mysql = classify_service(services[2])
        self.assertIsNotNone(ssh)
        self.assertIsNotNone(mysql)
        assert ssh is not None and mysql is not None
        self.assertEqual(ssh.kind, FindingKind.NETWORK_SERVICE)
        self.assertEqual(ssh.auth_type, "ssh")
        self.assertEqual(mysql.auth_type, "mysql")
        self.assertTrue(ssh.metadata["protocol_verified"])
        self.assertFalse(mysql.metadata["protocol_verified"])

    def test_rejects_dtd(self) -> None:
        malicious = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "x">]><nmaprun />'
        with self.assertRaises(ValueError):
            parse_nmap_xml(malicious)

        utf16 = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE nmaprun [<!ENTITY secret "unsafe">]>'
            '<nmaprun>&secret;</nmaprun>'
        ).encode("utf-16")
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            parse_nmap_xml(utf16)

        delayed = (
            b'<?xml version="1.0"?>'
            + b" " * 5000
            + b'<!DOCTYPE x [<!ENTITY e "EXPANDED">]><nmaprun><host><status state="up"/>'
            + b'<address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" '
            + b'portid="22"><state state="open"/><service name="ssh" product="&e;"/>'
            + b"</port></ports></host></nmaprun>"
        )
        with self.assertRaises(ValueError):
            parse_nmap_xml(delayed)

        external = b'<!DOCTYPE nmaprun SYSTEM "file:///unsafe"><nmaprun />'
        with self.assertRaises(ValueError):
            parse_nmap_xml(external)

    def test_uses_address_instead_of_ptr_name(self) -> None:
        xml = b"""<nmaprun><host><status state='up'/><address addr='192.0.2.9' addrtype='ipv4'/>
        <hostnames><hostname name='ptr.example.test' type='PTR'/></hostnames><ports>
        <port protocol='tcp' portid='80'><state state='open'/><service name='http'/></port>
        </ports></host></nmaprun>"""
        service = parse_nmap_xml(xml)[0]
        self.assertEqual(service.host, "192.0.2.9")
        self.assertEqual(web_seed_from_service(service), "http://192.0.2.9/")

    def test_confident_plain_http_on_tls_like_port_stays_http(self) -> None:
        service = ServiceObservation(
            host="example.test",
            port=8443,
            transport="tcp",
            state="open",
            service="http",
            detection_method="probed",
            service_confidence=10,
        )
        self.assertEqual(web_seed_from_service(service), "http://example.test:8443/")

    def test_open_port_table_service_is_reported_with_explicit_evidence(self) -> None:
        service = ServiceObservation(
            host="example.test",
            port=22,
            transport="tcp",
            state="open",
            service="ssh",
            detection_method="table",
            service_confidence=3,
        )
        finding = classify_service(service)
        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.auth_type, "ssh")
        self.assertFalse(finding.metadata["protocol_verified"])
        self.assertEqual(finding.evidence[0].rule_id, "nmap.service.port_mapping")

    def test_classifies_udp_and_infrastructure_auth_surfaces(self) -> None:
        cases = [
            ("kerberos-sec", 88, "udp", "kerberos"),
            ("radius", 1812, "udp", "radius"),
            ("snmp", 161, "udp", "snmp"),
            ("amqp", 5672, "tcp", "amqp"),
            ("oracle-tns", 1521, "tcp", "oracle"),
            ("openvpn", 1194, "udp", "openvpn"),
        ]
        for service_name, port, transport, scheme in cases:
            finding = classify_service(
                ServiceObservation(
                    host="192.0.2.10",
                    port=port,
                    transport=transport,
                    state="open",
                    service=service_name,
                    detection_method="probed",
                    service_confidence=10,
                )
            )
            self.assertIsNotNone(finding, service_name)
            assert finding is not None
            self.assertEqual(finding.protocol, scheme)
            self.assertEqual(finding.auth_type, scheme)
            expected_endpoint_scheme = (
                scheme if transport == "tcp" else f"{scheme}+{transport}"
            )
            self.assertTrue(
                finding.endpoint.startswith(expected_endpoint_scheme + "://")
            )


class KatanaClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        data = (FIXTURES / "katana.jsonl").read_text(encoding="utf-8")
        self.observations, self.errors = parse_katana_jsonl(data)

    def test_login_form_and_http_challenge(self) -> None:
        self.assertEqual(self.errors, [])
        login_findings = classify_web(self.observations[0])
        challenge_findings = classify_web(self.observations[1])
        self.assertTrue(any(item.kind == FindingKind.WEB_LOGIN for item in login_findings))
        login = next(item for item in login_findings if item.kind == FindingKind.WEB_LOGIN)
        self.assertEqual(login.auth_type, "password_form")
        self.assertEqual(login.metadata["form_action"], "https://example.test/session")
        self.assertEqual(login.metadata["form_method"], "POST")
        self.assertTrue(any(item.kind == FindingKind.HTTP_AUTH for item in challenge_findings))
        challenge = next(
            item for item in challenge_findings if item.kind == FindingKind.HTTP_AUTH
        )
        self.assertEqual(challenge.auth_type, "http_basic")

    def test_basic_after_digest_is_detected_without_treating_parameters_as_schemes(self) -> None:
        observation = WebObservation(
            url="https://example.test/private",
            source=Source.KATANA,
            status_code=401,
            headers={
                "www-authenticate": 'Digest realm="a,b", qop="auth,auth-int", Basic realm="Lab"',
            },
        )

        self.assertEqual(
            {item.auth_type for item in classify_web(observation)},
            {"http_digest", "http_basic"},
        )

    def test_path_or_page_text_alone_does_not_confirm_login(self) -> None:
        cases = [
            WebObservation(
                url="https://example.test/login",
                source=Source.HTTP_PROBE,
                status_code=200,
            ),
            WebObservation(
                url="https://example.test/sso/login",
                source=Source.HTTP_PROBE,
                status_code=200,
                title="Sign in",
            ),
        ]
        for observation in cases:
            with self.subTest(url=observation.url):
                self.assertEqual(classify_web(observation), [])

    def test_explicit_passwordless_form_is_confirmed(self) -> None:
        body = (
            "<form action='/otp'><input name='email'>"
            "<button>Send sign in code</button></form>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/signin", body)
        )
        self.assertEqual(errors, [])
        finding = next(
            item
            for item in classify_web(observations[0])
            if item.kind == FindingKind.WEB_LOGIN
        )
        self.assertEqual(finding.auth_type, "passwordless_form")

    def test_identifier_kind_distinguishes_email_username_and_unknown(self) -> None:
        cases = (
            (
                "email",
                "<form action='/session'><input name='email' type='email'>"
                "<input name='password' type='password'><button>Sign in</button></form>",
            ),
            (
                "username",
                "<form action='/session'><input name='username' autocomplete='username'>"
                "<input name='password' type='password'><button>Sign in</button></form>",
            ),
            (
                "unknown",
                "<form action='/session'><input name='account'>"
                "<input name='password' type='password'><button>Sign in</button></form>",
            ),
        )

        for expected, body in cases:
            with self.subTest(expected=expected):
                observations, errors = parse_katana_jsonl(
                    json_record(f"https://example.test/{expected}", body)
                )
                self.assertEqual(errors, [])
                finding = next(
                    item
                    for item in classify_web(observations[0])
                    if item.kind == FindingKind.WEB_LOGIN
                )
                self.assertEqual(finding.metadata["identifier_kind"], expected)

    def test_signup_otp_action_is_not_mistaken_for_signin_form(self) -> None:
        body = (
            "<html><head><title>Welcome</title></head><body>"
            "<form action='/signups/send_email_otp'>"
            "<input name='email'><button>Continue</button>"
            "<span>Already have an account? Sign in</span></form>"
            "<form action='/sessions/start'>"
            "<input name='login'><button>Sign in</button></form>"
            "</body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/session/new", body)
        )
        self.assertEqual(errors, [])
        finding = next(
            item for item in classify_web(observations[0])
            if item.kind == FindingKind.WEB_LOGIN
        )
        self.assertEqual(finding.auth_type, "passwordless_form")
        self.assertEqual(finding.metadata["form_action"], "https://example.test/sessions/start")

    def test_client_rendered_login_is_confirmed_by_path_and_client_markers(self) -> None:
        body = (
            "<html><head><title>Sign In</title>"
            "<link rel='stylesheet' href='/assets/login.css'></head>"
            "<body><div id='application_root'></div>"
            "<script>new CLoginPromptManager('/login');</script></body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/login/", body)
        )
        self.assertEqual(errors, [])

        finding = next(
            item
            for item in classify_web(observations[0])
            if item.kind == FindingKind.WEB_LOGIN
        )

        self.assertEqual(finding.auth_type, "js_login")
        self.assertTrue(finding.metadata["client_rendered"])
        rule_ids = {evidence.rule_id for evidence in finding.evidence}
        self.assertIn("url.login_path", rule_ids)
        self.assertIn("html.client_login_marker", rule_ids)
        self.assertIn("html.login_asset", rule_ids)

    def test_epic_style_signin_prompt_marks_client_rendered_login(self) -> None:
        body = (
            "<html><head><title>Epic Games</title></head>"
            "<body><div id='root'></div>"
            "<script>if (!window.ue.signinprompt) { window.ue.signinprompt = {}; }"
            "</script></body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://www.epicgames.com/id/login", body)
        )
        self.assertEqual(errors, [])

        finding = next(
            item
            for item in classify_web(observations[0])
            if item.kind == FindingKind.WEB_LOGIN
        )
        self.assertEqual(finding.auth_type, "js_login")

    def test_saml_request_form_is_confirmed(self) -> None:
        body = (
            "<form action='https://id.example.test/saml/consume' method='post'>"
            "<input type='hidden' name='SAMLRequest'></form>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/sso", body)
        )
        self.assertEqual(errors, [])
        finding = next(
            item for item in classify_web(observations[0]) if item.kind == FindingKind.SSO
        )
        self.assertEqual(finding.auth_type, "saml")

    def test_logout_is_not_a_login(self) -> None:
        self.assertEqual(classify_web(self.observations[2]), [])

    def test_discovers_sso_link_and_redacts_parameters(self) -> None:
        findings = classify_web(self.observations[3])
        sso = next(item for item in findings if item.kind == FindingKind.SSO)
        self.assertEqual(sso.host, "id.example.test")
        self.assertEqual(sso.auth_type, "oauth2")
        self.assertIn("client_id=demo", sso.endpoint)
        self.assertIn("redirect_uri=https%3A%2F%2Fexample.test%2Fcallback", sso.endpoint)

    def test_plain_url_and_malformed_record_are_isolated(self) -> None:
        observations, errors = parse_katana_jsonl(
            "https://example.test/signin\n{broken json}\n"
        )
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(classify_web(observations[0]), [])

    def test_katana_request_error_is_not_silently_treated_as_a_page(self) -> None:
        observations, errors = parse_katana_jsonl(
            '{"request":{"method":"GET","endpoint":"https://example.test/"},'
            '"error":"hybrid: could not create target"}'
        )
        self.assertEqual(observations, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("could not create target", errors[0])

    def test_same_site_wide_form_is_merged_across_pages(self) -> None:
        body = (
            "<form action='/session' method='post'><input name='username'>"
            "<input name='password' type='password'><button>Log in</button></form>"
        )
        data = "\n".join(
            (
                json_record("https://example.test/one", body),
                json_record("https://example.test/two", body),
            )
        )
        observations, errors = parse_katana_jsonl(data)
        self.assertEqual(errors, [])
        report = Report(scope=["example.test"])
        for observation in observations:
            for finding in classify_web(observation):
                report.add_or_merge_finding(finding)

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(
            report.findings[0].metadata["discovered_on"],
            ["https://example.test/one", "https://example.test/two"],
        )

    def test_localized_forms_with_dynamic_names_share_semantic_fingerprint(self) -> None:
        bodies = (
            (
                "https://example.test/login?locale=en",
                "<form action='/session?locale=en' method='post'>"
                "<input name='generated-r4' autocomplete='username'>"
                "<input name='generated-r5' type='password' "
                "autocomplete='current-password'><button>Log in</button></form>",
            ),
            (
                "https://example.test/login?locale=de",
                "<form action='/session?locale=de' method='post'>"
                "<input name='generated-r19' autocomplete='username'>"
                "<input name='generated-r20' type='password' "
                "autocomplete='current-password'><button>Anmelden</button></form>",
            ),
        )
        observations, errors = parse_katana_jsonl(
            "\n".join(json_record(url, body) for url, body in bodies)
        )
        self.assertEqual(errors, [])
        report = Report(scope=["example.test"])
        for observation in observations:
            for finding in classify_web(observation):
                report.add_or_merge_finding(finding)

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.metadata["auth_field_roles"], ["identifier", "password"])
        self.assertEqual(
            finding.metadata["discovered_on"],
            [
                "https://example.test/login?locale=en",
                "https://example.test/login?locale=de",
            ],
        )

    def test_same_route_with_different_field_roles_stays_separate(self) -> None:
        password = (
            "<form action='/session' method='post'>"
            "<input name='username' autocomplete='username'>"
            "<input name='password' type='password'><button>Log in</button></form>"
        )
        password_and_otp = (
            "<form action='/session' method='post'>"
            "<input name='username' autocomplete='username'>"
            "<input name='password' type='password'>"
            "<input name='otp' autocomplete='one-time-code'>"
            "<button>Log in</button></form>"
        )
        observations, errors = parse_katana_jsonl(
            "\n".join(
                (
                    json_record("https://example.test/login?flow=password", password),
                    json_record("https://example.test/login?flow=mfa", password_and_otp),
                )
            )
        )
        self.assertEqual(errors, [])
        report = Report(scope=["example.test"])
        for observation in observations:
            for finding in classify_web(observation):
                report.add_or_merge_finding(finding)

        self.assertEqual(len(report.findings), 2)
        self.assertEqual(
            {tuple(finding.metadata["auth_field_roles"]) for finding in report.findings},
            {
                ("identifier", "password"),
                ("identifier", "one_time_code", "password"),
            },
        )

    def test_js_route_variants_are_merged_and_upgraded_by_rendered_form(self) -> None:
        client_body = (
            "<html><head><link rel='stylesheet' href='/assets/login.css'></head>"
            "<body><script>new CLoginPromptManager('/login');</script></body></html>"
        )
        rendered_body = (
            "<form action='/session' method='post'>"
            "<input name='generated-a' autocomplete='username'>"
            "<input name='generated-b' type='password' "
            "autocomplete='current-password'><button>Log in</button></form>"
        )
        observations, errors = parse_katana_jsonl(
            "\n".join(
                (
                    json_record("https://example.test/login?locale=en", client_body),
                    json_record("https://example.test/login?locale=de", client_body),
                    json_record("https://example.test/login?locale=fr", rendered_body),
                )
            )
        )
        self.assertEqual(errors, [])
        report = Report(scope=["example.test"])
        for observation in observations:
            for finding in classify_web(observation):
                report.add_or_merge_finding(finding)

        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.auth_type, "password_form")
        self.assertIn("auth_fingerprint", finding.metadata)
        self.assertEqual(
            finding.metadata["discovered_on"],
            [
                "https://example.test/login?locale=en",
                "https://example.test/login?locale=de",
                "https://example.test/login?locale=fr",
            ],
        )

    def test_oversized_json_values_are_isolated(self) -> None:
        huge_integer = (
            '{"request":{"endpoint":"https://example.test/"},"n":'
            + "9" * 5000
            + "}"
        )
        observations, errors = parse_katana_jsonl(huge_integer)
        self.assertEqual(observations, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("parser limits", errors[0])

    def test_registration_is_not_reported_as_login(self) -> None:
        data = (
            '{"request":{"endpoint":"https://example.test/register"},'
            '"response":{"status_code":200,"headers":{"content_type":"text/html"},'
            '"body":"<form><input name=\'email\'><input type=\'password\' '
            'autocomplete=\'new-password\'><button>Create account</button></form>"}}'
        )
        observations, errors = parse_katana_jsonl(data)
        self.assertEqual(errors, [])
        self.assertEqual(classify_web(observations[0]), [])

    def test_login_with_misleading_new_password_autocomplete_is_a_password_form(self) -> None:
        body = (
            "<html><head><title>Test Login Page</title></head><body>"
            "<a href='/login'>Login</a>"
            "<form id='login' action='/authenticate' method='post'>"
            "<input name='username' type='text' autocomplete='OFF'>"
            "<input name='password' type='password' autocomplete='new-password'>"
            "<button type='submit'>Login</button></form></body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/login", body)
        )
        self.assertEqual(errors, [])
        findings = classify_web(observations[0])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.auth_type, "password_form")
        self.assertEqual(finding.metadata["form_action"], "https://example.test/authenticate")
        self.assertEqual(finding.metadata["form_method"], "POST")
        self.assertEqual(
            [field["name"] for field in finding.metadata["fields"][:2]],
            ["username", "password"],
        )

    def test_signup_form_is_not_login_even_with_login_page_title(self) -> None:
        body = (
            "<html><head><title>Login or register</title></head><body>"
            "<form action='/register' method='post'>"
            "<input name='username'><input name='password' type='password' "
            "autocomplete='new-password'><button>Sign up</button></form>"
            "</body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/login", body)
        )
        self.assertEqual(errors, [])
        self.assertEqual(classify_web(observations[0]), [])

    def test_new_password_form_needs_login_action_not_just_login_page_title(self) -> None:
        body = (
            "<html><head><title>Login or create account</title></head><body>"
            "<form action='/account' method='post'>"
            "<input name='username'><input name='password' type='password' "
            "autocomplete='new-password'><button>Continue</button></form>"
            "</body></html>"
        )
        observations, errors = parse_katana_jsonl(
            json_record("https://example.test/login", body)
        )
        self.assertEqual(errors, [])
        self.assertEqual(classify_web(observations[0]), [])

    def test_registration_change_password_or_orphan_fields_are_not_login(self) -> None:
        bodies = [
            "<form><input name='username'><input type='password' name='password'>"
            "<button>Create account</button></form>",
            "<form><input type='password' autocomplete='current-password'>"
            "<input type='password' autocomplete='new-password'>"
            "<button>Change password</button></form>",
            "<input name='email'><div>Welcome</div><input type='password'>",
            "<form><input name='email'><button>Subscribe</button></form>",
            "<form><input name='username'><input type='password' disabled>"
            "<button>Continue</button></form>",
            "<form><input name='username'><input type='password' style='display: none'>"
            "<button>Continue</button></form>",
        ]
        for body in bodies:
            data = json_record("https://example.test/account", body)
            observations, errors = parse_katana_jsonl(data)
            self.assertEqual(errors, [])
            self.assertEqual(classify_web(observations[0]), [], body)

    def test_login_form_with_forgot_password_link_is_still_login(self) -> None:
        body = (
            "<form><input name='username'><input type='password' name='password'>"
            "<button>Log in</button><a href='/forgot-password'>Forgot password?</a></form>"
        )
        observations, _ = parse_katana_jsonl(json_record("https://example.test/portal", body))
        finding = next(
            item for item in classify_web(observations[0]) if item.kind == FindingKind.WEB_LOGIN
        )
        self.assertIn("form_action", finding.metadata)

    def test_bare_401_is_not_a_confirmed_challenge(self) -> None:
        findings = classify_web(
            WebObservation(
                url="https://example.test/api/private",
                source=Source.HTTP_PROBE,
                status_code=401,
            )
        )
        self.assertEqual(findings, [])

    def test_bare_403_is_not_a_confirmed_auth_gate(self) -> None:
        observation = WebObservation(
            url="https://example.test/private",
            source=Source.KATANA,
            status_code=403,
        )
        self.assertEqual(classify_web(observation), [])

    def test_unavailable_login_and_sso_paths_are_discarded(self) -> None:
        cases = [
            ("https://example.test/sso/login", 404),
            ("https://example.test/login", 410),
            ("https://example.test/account/login", 500),
            ("https://example.test/accounts/login", 503),
        ]
        for url, status_code in cases:
            with self.subTest(url=url, status_code=status_code):
                observation = WebObservation(
                    url=url,
                    source=Source.HTTP_PROBE,
                    status_code=status_code,
                )
                self.assertEqual(classify_web(observation), [])

    def test_oauth_authorize_without_oauth_path_and_callback_suppression(self) -> None:
        authorize = WebObservation(
            url=(
                "https://identity.example.test/authorize?client_id=demo&response_type=code&"
                "redirect_uri=https%3A%2F%2Fexample.test%2Fcallback&state=opaque"
            ),
            source=Source.KATANA,
        )
        findings = classify_web(authorize)
        self.assertTrue(any(item.kind == FindingKind.SSO for item in findings))
        sso = next(item for item in findings if item.kind == FindingKind.SSO)
        self.assertIn("state=opaque", sso.endpoint)

        callback = WebObservation(
            url="https://example.test/oauth/callback?code=secret&state=opaque",
            source=Source.URL_LIST,
        )
        self.assertEqual(classify_web(callback), [])

        token_endpoint = WebObservation(
            url="https://identity.example.test/oauth/token",
            source=Source.URL_LIST,
        )
        self.assertEqual(classify_web(token_endpoint), [])

    def test_json_body_and_null_headers_are_not_treated_as_html_or_challenge(self) -> None:
        data = (
            '{"request":{"endpoint":"https://example.test/api"},'
            '"response":{"status_code":200,"headers":{"content_type":"application/json",'
            '"www_authenticate":null,"location":null},'
            '"body":"<form><input name=\'username\'><input type=\'password\'></form>"}}'
        )
        observations, errors = parse_katana_jsonl(data)
        self.assertEqual(errors, [])
        self.assertEqual(observations[0].forms, [])
        self.assertEqual(observations[0].headers, {"content-type": "application/json"})
        self.assertEqual(classify_web(observations[0]), [])

    def test_auth_header_on_200_is_not_a_challenge(self) -> None:
        observation = WebObservation(
            url="https://example.test/api",
            source=Source.KATANA,
            status_code=200,
            headers={"www-authenticate": "Basic realm=test"},
        )
        self.assertFalse(
            any(item.kind == FindingKind.HTTP_AUTH for item in classify_web(observation))
        )

    def test_internal_login_redirect_requires_target_confirmation(self) -> None:
        data = (
            '{"request":{"endpoint":"https://example.test/private"},'
            '"response":{"status_code":302,"headers":{"location":"/login"}}}'
        )
        observations, errors = parse_katana_jsonl(data)
        self.assertEqual(errors, [])
        self.assertEqual(classify_web(observations[0]), [])


def json_record(url: str, body: str) -> str:
    import json

    return json.dumps(
        {
            "request": {"endpoint": url},
            "response": {
                "status_code": 200,
                "headers": {"content_type": "text/html"},
                "body": body,
            },
        }
    )


if __name__ == "__main__":
    unittest.main()
