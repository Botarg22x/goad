from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from .models import (
    Evidence,
    Finding,
    FindingKind,
    FormObservation,
    ServiceObservation,
    Source,
    WebObservation,
)
from .normalize import host_for_uri, normalize_hostname, normalize_url
from .login_templates import match_login_template, match_page_template
from .template_request import parse_raw_request


_NETWORK_SERVICES: dict[str, tuple[str, str]] = {
    "ssh": ("ssh", "remote_access"),
    "ms-wbt-server": ("rdp", "remote_access"),
    "rdp": ("rdp", "remote_access"),
    "vnc": ("vnc", "remote_access"),
    "telnet": ("telnet", "remote_access"),
    "rlogin": ("rlogin", "remote_access"),
    "wsman": ("winrm", "remote_access"),
    "wsmans": ("winrms", "remote_access"),
    "ftp": ("ftp", "file_transfer"),
    "ftps": ("ftps", "file_transfer"),
    "microsoft-ds": ("smb", "file_sharing"),
    "netbios-ssn": ("smb", "file_sharing"),
    "smb": ("smb", "file_sharing"),
    "rsync": ("rsync", "file_transfer"),
    "nfs": ("nfs", "file_sharing"),
    "ldap": ("ldap", "directory"),
    "ldaps": ("ldaps", "directory"),
    "kerberos-sec": ("kerberos", "identity"),
    "kpasswd5": ("kerberos-password", "identity"),
    "radius": ("radius", "aaa"),
    "radius-acct": ("radius-acct", "aaa"),
    "tacacs": ("tacacs", "aaa"),
    "tacacs-ds": ("tacacs", "aaa"),
    "smtp": ("smtp", "mail"),
    "submission": ("smtp", "mail"),
    "imap": ("imap", "mail"),
    "imaps": ("imaps", "mail"),
    "pop3": ("pop3", "mail"),
    "pop3s": ("pop3s", "mail"),
    "mysql": ("mysql", "database"),
    "postgresql": ("postgresql", "database"),
    "ms-sql-s": ("mssql", "database"),
    "mongodb": ("mongodb", "database"),
    "redis": ("redis", "database"),
    "oracle-tns": ("oracle", "database"),
    "cassandra": ("cassandra", "database"),
    "couchdb": ("couchdb", "database"),
    "memcached": ("memcached", "database"),
    "amqp": ("amqp", "messaging"),
    "amqps": ("amqps", "messaging"),
    "mqtt": ("mqtt", "messaging"),
    "mqtts": ("mqtts", "messaging"),
    "stomp": ("stomp", "messaging"),
    "xmpp-client": ("xmpp", "messaging"),
    "snmp": ("snmp", "management"),
    "snmptrap": ("snmptrap", "management"),
    "isakmp": ("ike", "vpn"),
    "openvpn": ("openvpn", "vpn"),
    "pptp": ("pptp", "vpn"),
    "l2tp": ("l2tp", "vpn"),
    "sip": ("sip", "communications"),
    "sips": ("sips", "communications"),
    "socks": ("socks", "proxy"),
    "docker": ("docker", "infrastructure"),
    "kubernetes-api": ("kubernetes", "infrastructure"),
}

_WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt"}
_EMAIL_IDENTIFIER_NAME = re.compile(r"(?:^|[_\-.])(?:e?mail)(?:$|[_\-.])", re.I)
_USERNAME_IDENTIFIER_NAME = re.compile(
    r"(?:^|[_\-.])(?:user(?:name)?|login)(?:$|[_\-.])",
    re.I,
)
_TLS_PORTS = {443, 4443, 7443, 8443, 9443}
_AUTH_SEGMENTS = {
    "auth",
    "login",
    "log-in",
    "signin",
    "sign-in",
    "sign_in",
    "authenticate",
    "wp-login.php",
}
_AUTH_SUFFIXES = {
    "account/login",
    "accounts/login",
    "admin/login",
    "user/login",
    "users/sign_in",
    "session/new",
    "sessions/new",
    "cas/login",
    "saml/login",
}
_SSO_SEGMENTS = {"sso", "oauth", "oauth2", "openid", "oidc", "saml", "adfs"}
_NON_LOGIN_SEGMENTS = {
    "logout",
    "signout",
    "sign-out",
    "logoff",
    "register",
    "registration",
    "registrations",
    "signup",
    "signups",
    "sign-up",
    "forgot-password",
    "password-reset",
    "reset-password",
    "change-password",
}
_STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
}
_LOGIN_TEXT = re.compile(
    r"\b(?:log\s*in|sign\s*in|username|user\s*name|authentication)\b|"
    r"(?:войти|вход|авторизац|аутентификац|имя пользователя|парол)",
    re.IGNORECASE,
)
_CLIENT_LOGIN_MARKER = re.compile(
    r"\b(?:c?loginpromptmanager|loginmanager|loginprompt|signinprompt|login_base_url|"
    r"login[_-]?(?:component|container|feature|root|widget)|"
    r"auth[_-]?(?:component|container|feature|root|widget))\b",
    re.IGNORECASE,
)
_LOGIN_ASSET = re.compile(
    r"(?:^|[/_.-])(?:login|signin|sign-in|auth)(?:[/_.-]|$)",
    re.IGNORECASE,
)
_SIGNIN_ACTION_TEXT = re.compile(
    r"\b(?:log\s*in|sign\s*in)\b|(?:войти|вход|авторизац|аутентификац)",
    re.IGNORECASE,
)
_REGISTRATION_TEXT = re.compile(
    r"\b(?:create\s+(?:an?\s+)?account|sign\s*up|register|registration)\b|"
    r"(?:регистрац|создать\s+аккаунт|новый\s+пользователь)",
    re.IGNORECASE,
)
_PASSWORD_MAINTENANCE_TEXT = re.compile(
    r"\b(?:(?:forgot|reset|change|recover|set)\s+(?:your\s+)?password)\b|"
    r"(?:восстанов|сброс|сменить\s+парол|изменить\s+парол)",
    re.IGNORECASE,
)
_IDENTIFIER_NAME = re.compile(r"(?:user(?:name)?|login|email|e-mail|account)", re.IGNORECASE)
_CONFIRM_PASSWORD_NAME = re.compile(r"(?:confirm|repeat|verify|again|confirmation)", re.IGNORECASE)
_ONE_TIME_CODE_NAME = re.compile(
    r"(?:otp|totp|one.?time|verification.?code|mfa.?code|2fa.?code)",
    re.IGNORECASE,
)
_SSO_NON_ENTRY_SEGMENTS = {
    "token",
    "revoke",
    "revocation",
    "introspect",
    "introspection",
    "userinfo",
    "metadata",
    "jwks",
    "jwks.json",
    "certs",
    "callback",
    "cb",
    "acs",
    "consume",
    "openid-configuration",
}


def is_web_service(service: ServiceObservation) -> bool:
    name = service.service.lower()
    return (
        name in _WEB_SERVICE_NAMES
        or "http" in name.split("/")
        or name.startswith("ssl/http")
    )


def web_seed_from_service(service: ServiceObservation) -> str | None:
    if not is_web_service(service):
        return None
    explicit_tls = (
        service.tunnel == "ssl"
        or service.service.startswith("ssl/")
        or "https" in service.service
    )
    confident_plain_http = (
        service.service in {"http", "http-alt", "http-proxy"}
        and service.detection_method == "probed"
        and (service.service_confidence or 0) >= 7
        and not explicit_tls
    )
    tls = explicit_tls or (service.port in _TLS_PORTS and not confident_plain_http)
    scheme = "https" if tls else "http"
    host = normalize_hostname(service.host)
    default_port = 443 if scheme == "https" else 80
    authority = host_for_uri(host)
    if service.port != default_port:
        authority = f"{authority}:{service.port}"
    return normalize_url(f"{scheme}://{authority}/")


def classify_service(service: ServiceObservation) -> Finding | None:
    name = service.service.lower()
    definition = _NETWORK_SERVICES.get(name)
    if definition is None or service.state.lower() != "open":
        return None
    scheme, category = definition
    protocol_verified = service.detection_method == "probed" and (
        service.service_confidence is None
        or service.service_confidence >= 7
    )
    evidence = [
        Evidence(
            rule_id=(
                "nmap.service.probed"
                if protocol_verified
                else "nmap.service.port_mapping"
            ),
            group="service",
            source=service.source,
            detail=(
                f"Nmap service probing confirmed open {name} service"
                if protocol_verified
                else f"Nmap found an open port mapped to the {name} service"
            ),
        )
    ]
    host = normalize_hostname(service.host)
    transport = service.transport.lower()
    if transport not in {"tcp", "udp", "sctp"}:
        transport = "unknown"
    endpoint_scheme = scheme if transport == "tcp" else f"{scheme}+{transport}"
    endpoint = f"{endpoint_scheme}://{host_for_uri(host)}:{service.port}"
    metadata = {
        "category": category,
        "service": name,
        "transport": transport,
        "reachable": True,
        "protocol_verified": protocol_verified,
        "detection_method": service.detection_method or "port_mapping",
        "supported_auth_methods": None,
        "vantage": "scanner",
    }
    if service.product:
        metadata["product"] = service.product[:200]
    if service.version:
        metadata["version"] = service.version[:100]
    if service.address:
        metadata["address"] = service.address
    return Finding(
        kind=FindingKind.NETWORK_SERVICE,
        auth_type=scheme,
        endpoint=endpoint,
        host=host,
        port=service.port,
        protocol=scheme,
        evidence=evidence,
        sources=[service.source],
        metadata=metadata,
    )


def classify_web(observation: WebObservation) -> list[Finding]:
    findings: list[Finding] = []
    url = normalize_url(observation.url)
    parts = urlsplit(url)
    host = normalize_hostname(parts.hostname or "")
    port = parts.port or (443 if parts.scheme == "https" else 80)

    challenge_header = observation.headers.get("www-authenticate", "")
    proxy_header = observation.headers.get("proxy-authenticate", "")
    valid_challenge = observation.status_code in {401, 403} and bool(challenge_header)
    valid_proxy_challenge = observation.status_code == 407 and bool(proxy_header)
    if valid_challenge or valid_proxy_challenge:
        header = challenge_header if valid_challenge else proxy_header
        for auth_scheme in _auth_schemes(header):
            auth_type = (
                f"{'proxy' if valid_proxy_challenge else 'http'}_{auth_scheme.lower()}"
                if auth_scheme
                else "http_challenge"
            )
            evidence = [
                Evidence(
                    rule_id="http.auth.challenge",
                    group="protocol",
                    source=observation.source,
                    detail=(
                        f"HTTP {observation.status_code} authentication challenge"
                        + (f" using {auth_scheme}" if auth_scheme else "")
                    ),
                )
            ]
            findings.append(
                Finding(
                    kind=FindingKind.HTTP_AUTH,
                    auth_type=auth_type,
                    endpoint=url,
                    host=host,
                    port=port,
                    protocol=parts.scheme,
                    evidence=evidence,
                    sources=[observation.source],
                    metadata={
                        "status_code": observation.status_code,
                        "authentication_scheme": auth_scheme,
                    },
                )
            )

    if observation.status_code in {404, 410} or (
        observation.status_code is not None
        and 500 <= observation.status_code <= 599
    ):
        return findings

    path_match, path_evidence, is_sso, suppressed = _url_signals(
        url, observation.source
    )
    page_template = match_page_template(observation)
    if page_template is not None:
        fields = [field for form in observation.forms for field in form.fields]
        request = page_template.template.verification["request"]
        action = (urljoin(url, parse_raw_request(request["raw"]).target)
                  if request["action"] == "fixed" else url)
        metadata = {
            "page_url": url, "status_code": observation.status_code,
            "title": observation.title[:200], "form_action": action, "form_method": "POST",
            "credential_fields_source": "template", "detection_mode": "page_template",
            "identifier_kind": "username", "discovered_on": [url],
            "fields": [{"name": f.name, "type": f.field_type, "hidden": f.hidden, "disabled": f.disabled}
                       for f in fields],
            **page_template.metadata(),
        }
        findings.append(Finding(
            kind=FindingKind.WEB_LOGIN, auth_type="password_form", endpoint=url, host=host,
            port=port, protocol=parts.scheme, sources=[observation.source], metadata=metadata,
            evidence=[Evidence(rule_id=f"template.{page_template.template.id}", group="login_template",
                               source=observation.source, detail=page_template.signal)],
        ))
        return findings
    best_form: FormObservation | None = None
    best_auth_type = ""
    best_form_evidence: list[Evidence] = []
    best_template = None
    for form in observation.forms:
        template = match_login_template(observation, form)
        action_suppressed = False
        if form.action:
            _, _, _, action_suppressed = _url_signals(
                form.action, observation.source
            )
        form_context = " ".join((observation.title, form.text))
        login_context = bool(
            observation.knowledgebase_page_type == "login"
            or _SIGNIN_ACTION_TEXT.search(form_context)
            or template is not None
        )
        form_auth_type, form_evidence, form_suppressed = _form_signals(
            form,
            observation.source,
            login_context=login_context,
            context=form_context,
        )
        if form_suppressed or action_suppressed or not form_auth_type:
            continue
        if _LOGIN_TEXT.search(form_context):
            form_evidence.append(
                Evidence(
                    rule_id="html.login_semantics",
                    group="semantics",
                    source=observation.source,
                    detail="page or form contains sign-in terminology",
                )
            )
        if path_match:
            form_evidence.extend(path_evidence)
        if best_form is None or (
            best_auth_type == "passwordless_form"
            and form_auth_type == "password_form"
        ) or (
            best_template is None and template is not None
            and form_auth_type == "password_form"
        ):
            best_form = form
            best_auth_type = form_auth_type
            best_form_evidence = form_evidence
            best_template = template

    if best_form is not None and not suppressed:
        metadata: dict[str, object] = {
            "page_url": url,
            "status_code": observation.status_code,
        }
        if observation.title:
            metadata["title"] = observation.title[:200]
        if best_form is not None:
            metadata.update(_form_metadata(best_form, url))
            metadata["auth_fingerprint"] = _form_fingerprint(
                best_form,
                page_url=url,
                auth_type=best_auth_type,
            )
            metadata["auth_field_roles"] = _form_field_roles(best_form)
            metadata["identifier_kind"] = _identifier_kind(best_form)
            metadata["discovered_on"] = [url]
            if best_template is not None:
                metadata.update(best_template.metadata())
                best_form_evidence.append(Evidence(
                    rule_id=f"template.{best_template.template.id}",
                    group="login_template",
                    source=observation.source,
                    detail=(f"Поля {best_template.username_field}, {best_template.password_field}; "
                            f"{best_template.signal}"),
                ))
        findings.append(
            Finding(
                kind=FindingKind.WEB_LOGIN,
                auth_type=best_auth_type,
                endpoint=url,
                host=host,
                port=port,
                protocol=parts.scheme,
                evidence=best_form_evidence,
                sources=[observation.source],
                metadata=metadata,
            )
        )

    if best_form is None and path_match and not suppressed:
        js_evidence = _client_login_evidence(observation)
        successful_response = bool(
            observation.status_code is not None
            and 200 <= observation.status_code < 300
        )
        if successful_response and js_evidence:
            evidence = [*path_evidence, *js_evidence]
            if _LOGIN_TEXT.search(observation.title):
                evidence.append(
                    Evidence(
                        rule_id="html.login_title",
                        group="semantics",
                        source=observation.source,
                        detail="page title contains sign-in terminology",
                    )
                )
            findings.append(
                Finding(
                    kind=FindingKind.WEB_LOGIN,
                    auth_type="js_login",
                    endpoint=url,
                    host=host,
                    port=port,
                    protocol=parts.scheme,
                    evidence=evidence,
                    sources=[observation.source],
                    metadata={
                        "page_url": url,
                        "status_code": observation.status_code,
                        "title": observation.title[:200],
                        "client_rendered": True,
                        "discovered_on": [url],
                    },
                )
            )

    sso_candidates: list[tuple[str, str]] = []
    if is_sso:
        sso_candidates.append((url, "page"))
    sso_candidates.extend((link, "link") for link in observation.links)
    is_redirect_response = bool(
        observation.status_code is not None
        and 300 <= observation.status_code < 400
    )
    if observation.redirect_target and is_redirect_response:
        sso_candidates.append((observation.redirect_target, "redirect"))
    if observation.blocked_redirect and is_redirect_response:
        sso_candidates.append((observation.blocked_redirect, "blocked_redirect"))
    for form in observation.forms:
        field_names = {field.name.lower() for field in form.fields if field.name}
        if form.action and "samlrequest" in field_names:
            sso_candidates.append((form.action, "saml_form"))
    seen_candidates: set[str] = set()
    for candidate, provenance in sso_candidates:
        try:
            normalized = normalize_url(candidate)
        except ValueError:
            continue
        if normalized in seen_candidates:
            continue
        seen_candidates.add(normalized)
        candidate_path, evidence, candidate_is_sso, candidate_suppressed = _url_signals(
            normalized, observation.source
        )
        candidate_parts = urlsplit(normalized)
        candidate_host = normalize_hostname(candidate_parts.hostname or "")
        external_login = candidate_host != host and candidate_path
        query = parse_qs(candidate_parts.query, keep_blank_values=True)
        query_keys = {key.lower() for key in query}
        strong_oauth = "client_id" in query and "response_type" in query
        strong_saml = "samlrequest" in query_keys or provenance == "saml_form"
        if candidate_suppressed and not strong_saml:
            continue
        server_redirect = provenance in {"redirect", "blocked_redirect"} and (
            candidate_is_sso or external_login
        )
        confirmed_sso_page = (
            provenance == "page"
            and best_form is not None
            and candidate_is_sso
        )
        if provenance == "page" and observation.source == Source.URL_LIST:
            continue
        if not (strong_oauth or strong_saml or server_redirect or confirmed_sso_page):
            continue
        if strong_oauth:
            evidence.append(
                Evidence(
                    rule_id="url.oauth.parameters",
                    group="sso",
                    source=observation.source,
                    detail="OAuth/OIDC authorization parameters are present",
                )
            )
        if strong_saml:
            evidence.append(
                Evidence(
                    rule_id="saml.request",
                    group="sso",
                    source=observation.source,
                    detail="SAML authentication request form or query parameter is present",
                )
            )
        if server_redirect:
            evidence.append(
                Evidence(
                    rule_id="redirect.sso_entry",
                    group="redirect",
                    source=observation.source,
                    detail="the server redirects the client to an SSO entry point",
                )
            )
        if confirmed_sso_page:
            evidence.append(
                Evidence(
                    rule_id="sso.confirmed_form",
                    group="sso",
                    source=observation.source,
                    detail="SSO path contains a confirmed authentication form",
                )
            )
        findings.append(
            Finding(
                kind=FindingKind.SSO,
                auth_type=_sso_auth_type(
                    normalized, query, strong_oauth, strong_saml
                ),
                endpoint=normalized,
                host=candidate_host,
                port=candidate_parts.port
                or (443 if candidate_parts.scheme == "https" else 80),
                protocol=candidate_parts.scheme,
                evidence=evidence,
                sources=[observation.source],
                metadata={
                    "discovered_on": url,
                    "external": candidate_host != host,
                    "provenance": provenance,
                    "status_code": (
                        observation.status_code if provenance == "page" else None
                    ),
                },
            )
        )
    return findings


def _client_login_evidence(observation: WebObservation) -> list[Evidence]:
    evidence: list[Evidence] = []
    if _CLIENT_LOGIN_MARKER.search(observation.text):
        evidence.append(
            Evidence(
                rule_id="html.client_login_marker",
                group="client_rendering",
                source=observation.source,
                detail="page script contains a client-side login component marker",
            )
        )
    login_asset = next(
        (
            link
            for link in observation.links
            if _LOGIN_ASSET.search(unquote(urlsplit(link).path))
        ),
        "",
    )
    if login_asset:
        evidence.append(
            Evidence(
                rule_id="html.login_asset",
                group="client_rendering",
                source=observation.source,
                detail="page loads an authentication-specific client asset",
            )
        )
    return evidence


def _url_signals(url: str, source: str) -> tuple[bool, list[Evidence], bool, bool]:
    try:
        parts = urlsplit(normalize_url(url))
    except ValueError:
        return False, [], False, True
    path = unquote(parts.path).lower().rstrip("/")
    segments = [segment for segment in path.split("/") if segment]
    basename = segments[-1] if segments else ""
    query = parse_qs(parts.query, keep_blank_values=True)
    if any(basename.endswith(extension) for extension in _STATIC_EXTENSIONS):
        return False, [], False, True
    if any(segment in _NON_LOGIN_SEGMENTS for segment in segments):
        return False, [], False, True
    oauth_context = any(segment in _SSO_SEGMENTS for segment in segments)
    callback = (
        basename in _SSO_NON_ENTRY_SEGMENTS
        or "signin-oidc" in segments
        or "signout-callback-oidc" in segments
        or ".well-known" in segments
        or ("code" in segments and oauth_context)
        or "samlresponse" in {key.lower() for key in query}
        or ("code" in query and "client_id" not in query)
    )
    if callback:
        return False, [], False, True
    joined = "/".join(segments)
    oauth_authorize = basename in {"authorize", "authorization"} and (
        "client_id" in query and "response_type" in query
    )
    sso = oauth_context or oauth_authorize or any(
        suffix in joined
        for suffix in ("oauth/authorize", "oauth2/authorize", "saml/login", "adfs/ls")
    )
    login = basename in _AUTH_SEGMENTS or any(joined.endswith(suffix) for suffix in _AUTH_SUFFIXES)
    if login or sso:
        rule = "url.sso_path" if sso else "url.login_path"
        detail = "URL contains an exact SSO path" if sso else "URL contains an exact login path"
        return (
            True,
            [Evidence(rule_id=rule, group="url", source=source, detail=detail)],
            sso,
            False,
        )
    return False, [], False, False


def _form_signals(
    form: FormObservation,
    source: str,
    *,
    login_context: bool,
    context: str,
) -> tuple[str, list[Evidence], bool]:
    usable_fields = [field for field in form.fields if not field.disabled and not field.hidden]
    field_types = {field.field_type for field in usable_fields}
    field_names = [field.name for field in usable_fields]
    autocomplete = {field.autocomplete for field in usable_fields}
    has_password = "password" in field_types
    has_current_password = "current-password" in autocomplete
    has_new_password = "new-password" in autocomplete
    password_fields = [field for field in usable_fields if field.field_type == "password"]
    has_identifier = any(_IDENTIFIER_NAME.search(name) for name in field_names if name) or bool(
        autocomplete & {"username", "email"}
    )
    has_submit = "submit" in field_types or "button" in field_types
    evidence: list[Evidence] = []
    registration_context = bool(_REGISTRATION_TEXT.search(context))
    maintenance_context = bool(_PASSWORD_MAINTENANCE_TEXT.search(context))
    positive_login_context = bool(_SIGNIN_ACTION_TEXT.search(context))
    confirmation_field = any(
        _CONFIRM_PASSWORD_NAME.search(field.name)
        for field in password_fields
        if field.name
    )
    # Some login pages incorrectly mark their only password input as
    # autocomplete="new-password". Do not treat that hint as registration when
    # the rest of this POST form clearly describes a sign-in operation.
    new_password_login = bool(
        has_new_password
        and len(password_fields) == 1
        and has_identifier
        and has_submit
        and form.method.lower() == "post"
        and _SIGNIN_ACTION_TEXT.search(form.text)
        and not registration_context
        and not maintenance_context
        and not confirmation_field
    )
    if (
        (has_new_password and not new_password_login)
        or ((registration_context or maintenance_context) and not positive_login_context)
        or confirmation_field
    ):
        reason = (
            "new-password/confirmation fields or page semantics indicate registration "
            "or password maintenance"
        )
        return (
            "",
            [
                Evidence(
                    rule_id="html.form.auth_related_not_login",
                    group="negative",
                    source=source,
                    detail=reason,
                )
            ],
            True,
        )
    if form.is_orphan:
        return (
            "",
            [
                Evidence(
                    rule_id="html.orphan_fields",
                    group="quality",
                    source=source,
                    detail="inputs outside a form do not confirm a login endpoint",
                )
            ],
            True,
        )
    if has_current_password:
        auth_type = "password_form"
        evidence.append(
            Evidence(
                rule_id="html.form.current_password",
                group="form_structure",
                source=source,
                detail="form contains autocomplete=current-password",
            )
        )
    elif has_password and has_identifier:
        auth_type = "password_form"
        evidence.append(
            Evidence(
                rule_id="html.form.identifier_password",
                group="form_structure",
                source=source,
                detail="one form contains identifier and password fields",
            )
        )
    elif has_password and login_context:
        auth_type = "password_form"
        evidence.append(
            Evidence(
                rule_id="html.form.password_login_context",
                group="form_structure",
                source=source,
                detail="password form has explicit sign-in semantics",
            )
        )
    elif has_identifier and has_submit and login_context:
        auth_type = "passwordless_form"
        evidence.append(
            Evidence(
                rule_id="html.form.identifier_step",
                group="form_structure",
                source=source,
                detail="form is an explicit identifier step of a login flow",
            )
        )
    else:
        auth_type = ""
    return auth_type, evidence, False


def _sso_auth_type(
    url: str,
    query: dict[str, list[str]],
    strong_oauth: bool,
    strong_saml: bool,
) -> str:
    path = unquote(urlsplit(url).path).lower()
    scope = " ".join(query.get("scope", [])).lower()
    if strong_saml or "saml" in path or "adfs" in path:
        return "saml"
    if "oidc" in path or "openid" in path or "openid" in scope:
        return "oidc"
    if strong_oauth or "oauth" in path:
        return "oauth2"
    return "sso_redirect"


def _form_metadata(form: FormObservation, page_url: str) -> dict[str, object]:
    action = form.action
    if action:
        try:
            action = normalize_url(urljoin(page_url, action))
        except ValueError:
            action = ""
    return {
        "form_action": action or page_url,
        "form_method": form.method.upper(),
        "orphan_fields": form.is_orphan,
        "fields": [
            {
                "name": field.name[:100],
                "type": field.field_type[:50],
                "autocomplete": field.autocomplete[:50],
                "disabled": field.disabled,
                "hidden": field.hidden,
            }
            for field in form.fields[:50]
        ],
    }


def _form_fingerprint(
    form: FormObservation,
    *,
    page_url: str,
    auth_type: str,
) -> str:
    # Field names, generated IDs and visible text are deliberately excluded.
    # Frameworks often regenerate them and localized pages translate the text,
    # even though the authentication flow itself is unchanged.
    handler = _url_route_identity(form.action or page_url)
    identity = repr(
        (
            handler,
            auth_type,
            form.method.lower(),
            _form_field_roles(form),
            _identifier_kind(form),
        )
    ).encode("utf-8")
    return "form-" + hashlib.sha256(identity).hexdigest()[:16]


def _form_field_roles(form: FormObservation) -> list[str]:
    usable_fields = [
        field
        for field in form.fields
        if not field.disabled and not field.hidden and field.field_type.lower() != "hidden"
    ]
    has_password = any(field.field_type.lower() == "password" for field in usable_fields)
    roles: list[str] = []
    for field in usable_fields:
        field_type = (field.field_type or "text").lower()
        autocomplete = set(field.autocomplete.lower().split())
        name = field.name.lower()
        if "one-time-code" in autocomplete or _ONE_TIME_CODE_NAME.search(name):
            roles.append("one_time_code")
        elif field_type == "password":
            roles.append(
                "new_password" if "new-password" in autocomplete else "password"
            )
        elif (
            autocomplete & {"username", "email"}
            or field_type in {"email", "tel"}
            or _IDENTIFIER_NAME.search(name)
            or (has_password and field_type in {"text", "search"})
        ):
            roles.append("identifier")
        elif field_type in {"submit", "button", "reset", "image", "checkbox", "radio"}:
            # Submit controls and options such as "remember me" do not change
            # the authentication mechanism.
            continue
        else:
            roles.append(field_type)
    return sorted(roles)


def _identifier_kind(form: FormObservation) -> str:
    """Classify what the form explicitly asks for, without guessing accounts."""

    usable_fields = [
        field
        for field in form.fields
        if not field.disabled and not field.hidden and field.field_type.lower() != "hidden"
    ]
    has_password = any(field.field_type.lower() == "password" for field in usable_fields)
    kinds: set[str] = set()
    for field in usable_fields:
        field_type = (field.field_type or "text").lower()
        autocomplete = set(field.autocomplete.lower().split())
        name = field.name.lower()
        is_identifier = bool(
            autocomplete & {"username", "email"}
            or field_type in {"email", "tel"}
            or _IDENTIFIER_NAME.search(name)
            or (has_password and field_type in {"text", "search"})
        )
        if not is_identifier:
            continue
        if field_type == "email" or "email" in autocomplete or _EMAIL_IDENTIFIER_NAME.search(name):
            kinds.add("email")
        elif "username" in autocomplete or _USERNAME_IDENTIFIER_NAME.search(name):
            kinds.add("username")
        else:
            kinds.add("unknown")
    if kinds == {"email"}:
        return "email"
    if kinds == {"username"}:
        return "username"
    return "unknown"


def _url_route_identity(url: str) -> str:
    """Return origin + path, without query, fragment or a trailing slash."""
    try:
        parts = urlsplit(normalize_url(url))
    except ValueError:
        return url
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme}://{parts.netloc}{path}"


def _auth_schemes(header: str) -> list[str]:
    """Extract challenges, not comma-separated parameters such as Digest qop."""

    segments: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(header):
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "," and not quoted:
            segments.append(header[start:index])
            start = index + 1
    segments.append(header[start:])

    schemes: list[str] = []
    seen: set[str] = set()
    for segment in segments:
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9_-]*)(?=\s|$)", segment)
        if match:
            scheme = match.group(1)
            if scheme.casefold() not in seen:
                schemes.append(scheme)
                seen.add(scheme.casefold())
    return schemes[:8] or [""]
