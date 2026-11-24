from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, unquote_plus, urlencode, urlsplit, urlunsplit


_REPORT_SECRET_TOKENS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "session",
    "sessionid",
    "phpsessid",
    "jsessionid",
    "sessid",
    "sid",
    "code",
    "credential",
    "assertion",
    "jwt",
    "ticket",
    "sig",
    "signature",
    "state",
    "nonce",
    "otp",
    "csrf",
    "xsrf",
    "authorization",
    "samlart",
    "wresult",
    "wctx",
}
_CREDENTIAL_TOKENS = _REPORT_SECRET_TOKENS - {"state", "nonce"}
_REPORT_SECRET_COMPACT = {
    "accesstoken",
    "accesskey",
    "accesskeyid",
    "apikey",
    "apitoken",
    "authcode",
    "authtoken",
    "bearertoken",
    "clientassertion",
    "clientpassword",
    "clientsecret",
    "csrfmiddlewaretoken",
    "csrftoken",
    "idtoken",
    "keypairid",
    "oauthtoken",
    "onetimepassword",
    "privatekey",
    "privatetoken",
    "refreshtoken",
    "samlart",
    "samlartifact",
    "samlrequest",
    "samlresponse",
    "relaystate",
    "secretkey",
    "securitytoken",
    "sessionkey",
    "sessiontoken",
    "ssotoken",
    "phpsessid",
    "jsessionid",
    "userpassword",
    "verificationtoken",
    "xapikey",
    "xamzcredential",
    "xamzsecuritytoken",
    "xamzsignature",
}
_CREDENTIAL_COMPACT = _REPORT_SECRET_COMPACT - {"samlrequest", "relaystate"}
_SENSITIVE_COMPACT_SUFFIXES = {
    "accesskeyid",
    "accesstoken",
    "apikey",
    "apitoken",
    "assertion",
    "authtoken",
    "credential",
    "csrftoken",
    "idtoken",
    "oauthtoken",
    "password",
    "privatekey",
    "privatetoken",
    "refreshtoken",
    "secret",
    "securitytoken",
    "sessionkey",
    "sessiontoken",
    "signature",
    "ssotoken",
    "verificationtoken",
    "xsrftoken",
}
_LOGOUT_TOKENS = {
    "disconnect",
    "endsession",
    "logout",
    "log-out",
    "log_out",
    "logoff",
    "log-off",
    "log_off",
    "signout",
    "sign-out",
    "sign_out",
    "signoff",
    "sign-off",
    "sign_off",
}
_LOGOUT_TOKEN_SEQUENCES = {
    ("end", "session"),
    ("log", "off"),
    ("log", "out"),
    ("sign", "off"),
    ("sign", "out"),
}
MAX_URL_LENGTH = 8192


def normalize_hostname(host: str) -> str:
    value = host.strip().rstrip(".")
    if not value:
        raise ValueError("empty host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid IDN hostname: {host!r}") from exc
    if len(ascii_host) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in ascii_host.split(".")
    ):
        raise ValueError(f"invalid hostname: {host!r}")
    return ascii_host


def normalize_url(url: str, *, redact_query: bool = False) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise ValueError("URL contains control characters")
    raw = url.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"URL is longer than {MAX_URL_LENGTH} characters")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("only http/https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing userinfo are not allowed")
    if not parts.hostname:
        raise ValueError("URL has no host")
    host = normalize_hostname(parts.hostname)
    display_host = f"[{host}]" if ":" in host else host
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"invalid URL port: {port}")
    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{display_host}:{port}"
    else:
        netloc = display_host
    path = parts.path or "/"
    query = redact_query_parameters(parts.query) if redact_query else parts.query
    return urlunsplit((scheme, netloc, path, query, ""))


def redact_query_parameters(query: str) -> str:
    if not query:
        return ""
    pairs = _query_pairs(query)
    redacted = [
        (
            key,
            "REDACTED"
            if _is_sensitive_query_key(key)
            or _embedded_sensitive_query_keys(value, credential_only=False)
            else value,
        )
        for key, value in pairs
    ]
    return urlencode(redacted, doseq=True)


def credential_query_keys(url: str) -> list[str]:
    normalized = normalize_url(url, redact_query=False)
    keys: list[str] = []
    for key, value in _query_pairs(urlsplit(normalized).query):
        if _is_sensitive_query_key(key, credential_only=True):
            keys.append(key)
        keys.extend(_embedded_sensitive_query_keys(value, credential_only=True))
    return list(dict.fromkeys(keys))


def host_for_uri(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def is_logout_url(url: str) -> bool:
    normalized = normalize_url(url, redact_query=False)
    parts = urlsplit(normalized)
    if _contains_logout_token(parts.path):
        return True
    return any(
        _contains_logout_token(key) or _contains_logout_token(value)
        for key, value in _query_pairs(parts.query)
    )


def _is_sensitive_query_key(key: str, *, credential_only: bool = False) -> bool:
    key = _decode_repeatedly(key, plus=True)
    # Convert camelCase/PascalCase and bracket/dot/dash namespaces to tokens.
    compact = re.sub(r"[^A-Za-z0-9]+", "", key).lower()
    compact_values = _CREDENTIAL_COMPACT if credential_only else _REPORT_SECRET_COMPACT
    if compact in compact_values:
        return True
    if any(compact.endswith(suffix) for suffix in _SENSITIVE_COMPACT_SUFFIXES):
        return True
    separated = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", key)
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", separated)
    tokens = [token for token in re.split(r"[^A-Za-z0-9]+", separated.lower()) if token]
    token_set = set(tokens)
    sensitive_tokens = _CREDENTIAL_TOKENS if credential_only else _REPORT_SECRET_TOKENS
    if token_set & sensitive_tokens:
        return True
    joined = "_".join(tokens)
    compounds = {
        "api_key",
        "access_key",
        "access_key_id",
        "auth_code",
        "client_assertion",
        "one_time_password",
        "private_token",
        "saml_request",
        "saml_response",
        "saml_artifact",
        "relay_state",
        "key_pair_id",
    }
    if not credential_only:
        compounds |= {"redirect_uri", "return_url", "saml_request", "relay_state", "policy"}
    padded_joined = f"_{joined}_"
    return any(f"_{compound}_" in padded_joined for compound in compounds)


def _query_pairs(query: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for component in re.split(r"[&;]", query):
        if not component:
            continue
        raw_key, separator, raw_value = component.partition("=")
        key = unquote_plus(raw_key)
        value = unquote_plus(raw_value) if separator else ""
        pairs.append((key, value))
    return pairs


def _embedded_sensitive_query_keys(
    value: str,
    *,
    credential_only: bool,
) -> list[str]:
    """Find credential keys inside encoded callback/next URL values."""
    decoded = value
    found: list[str] = []
    for _ in range(4):
        for match in re.finditer(r"(?:^|[?&;])([^?&;=]{1,200})=", decoded):
            key = match.group(1)
            if _is_sensitive_query_key(key, credential_only=credential_only):
                found.append(key)
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return list(dict.fromkeys(found))


def _decode_repeatedly(value: str, *, plus: bool = False) -> str:
    decoder = unquote_plus if plus else unquote
    decoded = value
    for _ in range(3):
        next_value = decoder(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _contains_logout_token(value: str) -> bool:
    decoded = _decode_repeatedly(value).strip().lower().replace("\\", "/")
    for raw_segment in decoded.split("/"):
        segment = raw_segment.split(";", 1)[0].strip()
        if not segment:
            continue
        tokens = re.findall(r"[a-z0-9]+", segment)
        if set(tokens) & _LOGOUT_TOKENS:
            return True
        for sequence in _LOGOUT_TOKEN_SEQUENCES:
            length = len(sequence)
            if any(
                tuple(tokens[index : index + length]) == sequence
                for index in range(len(tokens))
            ):
                return True
    return False
