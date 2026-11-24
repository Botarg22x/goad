from __future__ import annotations

import base64
import http.client
import http.cookiejar
import ipaddress
import re
import ssl
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request

from .base import AuthAdapter
from ..defaults import DEFAULT_USER_AGENT
from ..auth_signals import json_auth_signal, json_object
from ..models import AuthJob, Credential, Outcome, OutcomeStatus
from ..template_profile import apply_defaults, html_signals, profile_from_metadata, profile_outcome, profile_unconfirmed, render_raw_request, page_request_fields


_IDENTIFIER_NAME = re.compile(r"(?:user|login|email|account|identifier)", re.I)
_FAILURE_TEXT = re.compile(
    r"(?:invalid|incorrect|wrong)[^.!?\n]{0,80}(?:username|email|password|credentials)|"
    r"(?:username|email|password|credentials)[^.!?\n]{0,80}"
    r"(?:invalid|incorrect|wrong|do not match|does not match|rejected)|"
    r"(?:authentication|login|sign[- ]?in) failed|"
    r"(?:unable to|couldn.?t) (?:log|sign) (?:you )?in|"
    r"(?:неверн\w*|неправильн\w*|ошибочн\w*)[^.!?\n]{0,100}"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)|"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)"
    r"[^.!?\n]{0,100}(?:неверн\w*|неправильн\w*|ошибочн\w*)",
    re.IGNORECASE,
)
_LOGOUT_LABEL = re.compile(r"^\s*(?:sign\s*out|log\s*out|logout|выйти|выход)\s*$", re.I)
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_REDIRECT_LIMIT = 4
_CHALLENGE_MARKERS = re.compile(
    r"(?:<title[^>]*>\s*(?:just a moment|attention required|"
    r"verify (?:that )?you are human|checking your browser|captcha|security check)|"
    r"cf-chl-|challenge-platform|captcha[_ -]?required|cloudflare ray id|"
    r"enable javascript and cookies to continue)",
    re.IGNORECASE,
)
_CSRF_ERROR = re.compile(
    r"(?:csrf|xsrf|authenticity)[^\n]{0,60}(?:invalid|expired|missing|mismatch|failed)|"
    r"(?:invalid|expired|missing|mismatch|failed)[^\n]{0,60}(?:csrf|xsrf|authenticity)",
    re.I,
)
_OTP_FIELD_NAME = re.compile(r"^(?:otp|totp|verification_code|email_code|one_time_code)$", re.I)


class ProxyTransportError(RuntimeError):
    """A bounded request could not be completed through the configured proxy."""


class _PreflightOutcome(Exception):
    def __init__(self, outcome: Outcome) -> None:
        self.outcome = outcome


@dataclass(frozen=True, slots=True)
class TargetScope:
    domain: str
    include_subdomains: bool = False

    @classmethod
    def from_domain(
        cls,
        domain: str | None,
        *,
        include_subdomains: bool = False,
    ) -> "TargetScope | None":
        if domain is None:
            return None
        value = domain.strip().lower().rstrip(".")
        if not value or any(character in value for character in ("/", "\\", "@")):
            raise ValueError("--scope-domain must be one hostname without a scheme or path")
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            try:
                normalized = value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("--scope-domain is not a valid hostname") from exc
            labels = normalized.split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
                for label in labels
            ):
                raise ValueError("--scope-domain is not a valid hostname")
        return cls(normalized, include_subdomains)

    def allows(self, hostname: str) -> bool:
        value = hostname.lower().rstrip(".")
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        return value == self.domain or (
            self.include_subdomains and value.endswith("." + self.domain)
        )


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    # A mapping cannot retain multiple Set-Cookie headers from one response.
    set_cookie_headers: tuple[str, ...] = field(default=(), repr=False)


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse: ...


class ProxyHttpClient:
    """Bounded scoped HTTP(S) client with optional generic HTTP proxy."""

    def __init__(
        self,
        proxy_url: str | None = None,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 512 * 1024,
        user_agent: str = DEFAULT_USER_AGENT,
        target_scope: TargetScope | None = None,
        ca_cert: Path | None = None,
    ) -> None:
        self._proxy_host: str | None = None
        self._proxy_port: int | None = None
        if proxy_url:
            parts = urlsplit(proxy_url)
            if parts.scheme.casefold() != "http":
                raise ValueError("--proxy must use http://")
            if not parts.hostname:
                raise ValueError("--proxy must contain a hostname")
            if parts.username or parts.password or parts.path not in {"", "/"}:
                raise ValueError("--proxy must not contain credentials or a path")
            if parts.query or parts.fragment:
                raise ValueError("--proxy must not contain a query or fragment")
            try:
                port = parts.port or 80
            except ValueError as exc:
                raise ValueError("--proxy contains an invalid port") from exc
            if not 1 <= port <= 65535:
                raise ValueError("--proxy port must be between 1 and 65535")
            self._proxy_host = parts.hostname
            self._proxy_port = port
        if not 0 < timeout_seconds <= 60:
            raise ValueError("HTTP timeout must be greater than 0 and at most 60 seconds")
        user_agent = user_agent.strip()
        if not user_agent or len(user_agent) > 512:
            raise ValueError("--user-agent must contain between 1 and 512 characters")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in user_agent):
            raise ValueError("--user-agent must not contain control characters")
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._user_agent = user_agent
        self._target_scope = target_scope
        if ca_cert is not None:
            certificate = ca_cert.expanduser().resolve()
            if not certificate.is_file():
                raise ValueError(f"--ca-cert file not found: {certificate}")
            self._ssl_context = ssl.create_default_context(cafile=str(certificate))
        else:
            self._ssl_context = (
                ssl._create_unverified_context() if proxy_url
                else ssl.create_default_context()
            )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        parts = validate_target_url(url, self._target_scope)
        absolute_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path or "/", parts.query, "")
        )
        request_headers = {
            "Host": parts.netloc,
            "Connection": "close",
            "User-Agent": self._user_agent,
        }
        if headers:
            request_headers.update(headers)
        if self._proxy_host is None:
            if parts.scheme.casefold() == "https":
                connection = http.client.HTTPSConnection(
                    parts.hostname,
                    parts.port or 443,
                    timeout=self._timeout_seconds,
                    context=self._ssl_context,
                )
            else:
                connection = http.client.HTTPConnection(
                    parts.hostname,
                    parts.port or 80,
                    timeout=self._timeout_seconds,
                )
            request_target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        elif parts.scheme.casefold() == "https":
            connection = http.client.HTTPSConnection(
                self._proxy_host,
                self._proxy_port,
                timeout=self._timeout_seconds,
                context=self._ssl_context,
            )
            connection.set_tunnel(
                parts.hostname,
                parts.port or 443,
                headers={"Host": parts.netloc},
            )
            request_target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        else:
            connection = http.client.HTTPConnection(
                self._proxy_host,
                self._proxy_port,
                timeout=self._timeout_seconds,
            )
            request_target = absolute_url
        try:
            connection.request(
                method.upper(),
                request_target,
                body=body,
                headers=request_headers,
            )
            response = connection.getresponse()
            raw_body = response.read(self._max_response_bytes + 1)
            if len(raw_body) > self._max_response_bytes:
                raw_body = raw_body[: self._max_response_bytes]
            raw_headers = response.getheaders()
            response_headers = {key.casefold(): value for key, value in raw_headers}
            return HttpResponse(
                status=response.status,
                headers=response_headers,
                body=raw_body.decode("utf-8", errors="replace"),
                set_cookie_headers=tuple(
                    value for key, value in raw_headers if key.casefold() == "set-cookie"
                ),
            )
        except (OSError, http.client.HTTPException) as exc:
            raise ProxyTransportError(
                f"proxy request failed: {type(exc).__name__}: {exc}"
            ) from exc
        finally:
            connection.close()


class HttpBasicAdapter(AuthAdapter):
    def __init__(self, client: HttpClient, target_scope: TargetScope | None = None) -> None:
        self._client = client
        self._target_scope = target_scope

    @property
    def auth_types(self) -> Collection[str]:
        return ("http_basic",)

    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        try:
            validate_live_job(job, self._target_scope)
            if ":" in credential.username:
                return Outcome(
                    OutcomeStatus.UNSUPPORTED,
                    detail="HTTP Basic usernames containing ':' are unsupported",
                    evidence={"attempted": False, "reason": "preflight"},
                )
            token = base64.b64encode(
                f"{credential.username}:{credential.password}".encode("utf-8")
            ).decode("ascii")
            response = self._client.request(
                "GET",
                job.endpoint,
                headers={"Authorization": f"Basic {token}"},
            )
            return _basic_outcome(response)
        except ProxyTransportError as exc:
            return Outcome(OutcomeStatus.NETWORK_ERROR, detail=str(exc))
        except ValueError as exc:
            return Outcome(
                OutcomeStatus.UNSUPPORTED,
                detail=str(exc),
                evidence={"attempted": False, "reason": "preflight"},
            )


class PasswordFormAdapter(AuthAdapter):
    def __init__(self, client: HttpClient, target_scope: TargetScope | None = None) -> None:
        self._client = client
        self._target_scope = target_scope

    @property
    def auth_types(self) -> Collection[str]:
        return ("password_form",)

    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        submitted = False
        try:
            validate_live_job(job, self._target_scope)
            profile = profile_from_metadata(job.metadata)
            action, identifier_name, password_name, has_hidden_fields = _form_submission(job)
            # CSRF and other hidden values belong to the current cookie session.
            # Refresh the form for every candidate; never reuse values from the
            # discovery report or a previous authentication attempt.
            cookies = http.cookiejar.CookieJar()
            fields: list[tuple[str, str]] = []
            if has_hidden_fields or profile is not None:
                fields = _fresh_form_fields(
                    self._client, cookies, job, action, identifier_name,
                    password_name, self._target_scope,
                )
            if profile is not None:
                fields = apply_defaults(profile, fields)
            fields.extend(((identifier_name, credential.username), (password_name, credential.password)))
            encoded = urlencode(fields).encode("utf-8")
            post_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": job.endpoint,
            }
            if profile is not None and "raw" in profile["request"]:
                template_headers, encoded = render_raw_request(
                    profile, action=action, page_url=job.endpoint, fields=fields,
                    username_field=identifier_name, password_field=password_name,
                    login=credential.username, password=credential.password,
                )
                post_headers.update(template_headers)
            post_headers["Content-Length"] = str(len(encoded))
            cookie_request = Request(action)
            cookies.add_cookie_header(cookie_request)
            if cookie_header := cookie_request.get_header("Cookie"):
                post_headers["Cookie"] = cookie_header
            submitted = True
            response = self._client.request(
                "POST",
                action,
                headers=post_headers,
                body=encoded,
            )
            post_status = response.status
            # Each candidate gets its own session: a successful attempt must
            # never make the next password appear authenticated.
            _retain_cookies(cookies, action, response)
            current_url = action
            redirect_count = 0
            while response.status in {301, 302, 303, 307, 308}:
                common = _common_outcome(response)
                if common is not None:
                    return common
                headers = _response_headers(response)
                location = headers.get("location")
                if not location:
                    break
                if redirect_count == 0 and response.status not in {302, 303}:
                    return Outcome(
                        OutcomeStatus.AMBIGUOUS,
                        detail="Редирект не подтверждает вход; повтор POST не выполнялся",
                        evidence={"reason": "credential_redirect", "http_status": response.status},
                    )
                if redirect_count >= _REDIRECT_LIMIT:
                    return Outcome(
                        OutcomeStatus.AMBIGUOUS,
                        detail="Достигнут предел переходов; вход не подтверждён",
                        evidence={"reason": "redirect_limit", "http_status": response.status},
                    )
                destination = urljoin(current_url, location)
                try:
                    destination_parts = validate_target_url(destination, self._target_scope)
                    allowed = _origin(destination_parts) == _origin(urlsplit(action))
                except ValueError:
                    allowed = False
                if not allowed:
                    return Outcome(
                        OutcomeStatus.UNSUPPORTED,
                        detail="Переход за пределы origin остановлен; вход не подтверждён",
                        evidence={"reason": "scope", "attempted": True, "http_status": response.status},
                    )
                if credential.password and (
                    any(
                        value == credential.password
                        for _, value in parse_qsl(destination_parts.query, keep_blank_values=True)
                    )
                    or credential.password in unquote(destination_parts.path).split("/")
                ):
                    return Outcome(
                        OutcomeStatus.UNSUPPORTED,
                        detail="Пароль в URL перехода не передавался; вход не подтверждён",
                        evidence={"reason": "credential_url", "attempted": True},
                    )
                cookie_request = Request(destination)
                cookies.add_cookie_header(cookie_request)
                cookie_header = cookie_request.get_header("Cookie")
                response = self._client.request(
                    "GET", destination,
                    headers={"Cookie": cookie_header} if cookie_header else {},
                )
                _retain_cookies(cookies, destination, response)
                current_url = destination
                redirect_count += 1
            return _form_outcome(response, action, page_url=job.endpoint, final_url=current_url,
                                 profile=profile, post_status=post_status)
        except _PreflightOutcome as exc:
            return exc.outcome
        except ProxyTransportError as exc:
            return Outcome(
                OutcomeStatus.NETWORK_ERROR, detail=str(exc),
                evidence={"attempted": submitted},
            )
        except ValueError as exc:
            return Outcome(
                OutcomeStatus.UNSUPPORTED,
                detail=str(exc),
                evidence={
                    "attempted": submitted,
                    "reason": "response_configuration" if submitted else "preflight",
                },
            )


def validate_live_job(job: AuthJob, target_scope: TargetScope | None = None) -> None:
    endpoint = validate_target_url(job.endpoint, target_scope)
    if job.auth_type == "password_form":
        action = job.form_action or str(job.metadata.get("form_action") or "")
        if not action:
            raise ValueError("password form has no form_action metadata")
        action_parts = validate_target_url(action, target_scope)
        if _origin(endpoint) != _origin(action_parts):
            raise ValueError("cross-origin form actions are not allowed in live mode")


def validate_target_url(url: str, target_scope: TargetScope | None = None):
    parts = urlsplit(url)
    if parts.scheme.casefold() not in {"http", "https"}:
        raise ValueError("live HTTP adapters support only http:// and https:// URLs")
    if not parts.hostname:
        raise ValueError("target URL has no hostname")
    if target_scope is None:
        if not _is_loopback_host(parts.hostname):
            raise ValueError(
                "external live targets require --scope-domain"
            )
        if parts.scheme.casefold() != "http":
            raise ValueError("loopback mode without --scope-domain supports only http://")
    elif not target_scope.allows(parts.hostname):
        raise ValueError(
            f"target host {parts.hostname!r} is outside scope {target_scope.domain!r}"
        )
    if parts.username or parts.password:
        raise ValueError("target URL must not contain credentials")
    try:
        port = parts.port or 80
    except ValueError as exc:
        raise ValueError("target URL contains an invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")
    return parts


def validate_loopback_http_url(url: str):
    """Backward-compatible strict validator used by older integrations."""
    return validate_target_url(url)


def _form_submission(job: AuthJob) -> tuple[str, str, str, bool]:
    from ..form_fields import template_credential_fields

    profile = profile_from_metadata(job.metadata)
    if profile is not None and profile["request"]["action"] in {"page", "fixed"}:
        username, password = template_credential_fields(job.metadata)
        action = job.form_action or job.endpoint
        return action, username, password, True

    method = str(job.metadata.get("form_method") or "POST").upper()
    if method != "POST":
        raise ValueError(
            "Форма входа не объявляет POST; HTTP-проверка не отправляет пароль "
            "через GET. Для JavaScript-формы используйте браузерный режим."
        )
    action = job.form_action or str(job.metadata.get("form_action") or "")
    fields = job.metadata.get("fields")
    if not isinstance(fields, list):
        raise ValueError("password form metadata does not contain fields")

    # A template hint must reference real, usable fields in this very report.
    # The observed action/method and fresh CSRF handling remain authoritative.
    identifier_name, password_name = template_credential_fields(job.metadata)
    has_hidden_fields = False
    for raw_field in fields:
        if not isinstance(raw_field, Mapping):
            continue
        name = str(raw_field.get("name") or "")
        field_type = str(raw_field.get("type") or "").casefold()
        autocomplete = str(raw_field.get("autocomplete") or "").casefold()
        disabled = bool(raw_field.get("disabled"))
        hidden = bool(raw_field.get("hidden")) or field_type == "hidden"
        if disabled:
            continue
        if hidden and name:
            has_hidden_fields = True
            continue
        if not name:
            continue
        if not password_name and (
            field_type == "password" or autocomplete == "current-password"
        ):
            password_name = name
            continue
        if not identifier_name and (
            autocomplete in {"username", "email"} or _IDENTIFIER_NAME.search(name)
        ):
            identifier_name = name

    if not identifier_name or not password_name:
        raise ValueError("could not identify username and password field names")
    return action, identifier_name, password_name, has_hidden_fields


@dataclass(slots=True)
class _SessionForm:
    action: str
    method: str
    inputs: list[tuple[str, str, str]] = field(default_factory=list)


class _SessionFormParser(HTMLParser):
    def __init__(self, body: str) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_SessionForm] = []
        self.current: _SessionForm | None = None
        self.feed(body)
        self.close()

    def handle_starttag(self, tag, attrs) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        if tag == "form":
            self.current = _SessionForm(
                values.get("action", ""), values.get("method", "get").upper()
            )
            self.forms.append(self.current)
        elif tag in {"input", "button"} and self.current is not None:
            name = values.get("name", "")
            if name and "disabled" not in values:
                self.current.inputs.append((
                    name,
                    values.get("type", "submit" if tag == "button" else "text").casefold(),
                    values.get("value", ""),
                ))

    def handle_endtag(self, tag) -> None:
        if tag == "form":
            self.current = None


def _fresh_form_fields(
    client: HttpClient,
    cookies: http.cookiejar.CookieJar,
    job: AuthJob,
    action: str,
    identifier_name: str,
    password_name: str,
    scope: TargetScope | None,
) -> list[tuple[str, str]]:
    profile = profile_from_metadata(job.metadata)
    page_url = job.endpoint
    for _ in range(_REDIRECT_LIMIT + 1):
        request = Request(page_url)
        cookies.add_cookie_header(request)
        cookie_header = request.get_header("Cookie")
        response = client.request(
            "GET", page_url,
            headers={"Cookie": cookie_header} if cookie_header else {},
        )
        _retain_cookies(cookies, page_url, response)
        common = _common_outcome(response)
        if common is not None:
            raise _PreflightOutcome(Outcome(
                common.status,
                detail=f"Страница входа недоступна до отправки пароля: {common.detail}",
                retry_after_seconds=common.retry_after_seconds,
                evidence={**common.evidence, "attempted": False},
            ))
        if response.status in {301, 302, 303, 307, 308}:
            location = _response_headers(response).get("location", "")
            if not location:
                raise ValueError("Страница входа вернула редирект без Location")
            destination = urljoin(page_url, location)
            if _origin(validate_target_url(destination, scope)) != _origin(urlsplit(action)):
                raise ValueError("Страница входа перенаправила запрос за пределы origin")
            page_url = destination
            continue
        if response.status != 200:
            if response.status == 403:
                raise _PreflightOutcome(Outcome(
                    OutcomeStatus.UNSUPPORTED,
                    detail="HTTP 403: доступ к странице входа запрещён; пароль не отправлялся",
                    evidence={"reason": "http_403", "attempted": False, "http_status": 403},
                ))
            raise ValueError(f"Страница входа вернула HTTP {response.status}; пароль не отправлялся")
        protection = profile_outcome(profile, html_signals(response.body), page_url, status=response.status, submitted=False)
        if protection is not None:
            raise _PreflightOutcome(protection)
        if profile is not None and profile["request"]["action"] in {"page", "fixed"}:
            # No form/method/type/visibility inference: raw defines the request.
            # A changed page must still pass the same product/login fingerprint.
            if page_url != job.endpoint:
                raise ValueError("Страница сменила URL; обновите отчёт перед проверкой шаблона")
            required = {str(item.get("name")) for item in job.metadata.get("fields", [])
                        if isinstance(item, Mapping) and item.get("name") in profile["request"]["csrf_fields"]}
            return page_request_fields(profile, response.body, page_url, response.status, required)
        parser = _SessionFormParser(response.body)
        matches = [
            form for form in parser.forms
            if form.method == "POST"
            and urljoin(page_url, form.action or page_url) == action
            and {identifier_name, password_name} <= {name for name, _, _ in form.inputs}
        ]
        if len(matches) != 1:
            raise ValueError(
                "Не удалось однозначно найти исходную форму входа; пароль не отправлялся. "
                "Если форму создаёт JavaScript, попробуйте --auto-browser"
            )
        form = matches[0]
        if profile is not None:
            usernames = [kind for name, kind, _ in form.inputs if name == identifier_name]
            passwords = [kind for name, kind, _ in form.inputs if name == password_name]
            if len(usernames) != 1 or usernames[0] not in {"text", "email", "tel"} or passwords != ["password"]:
                raise ValueError("Поля текущей формы не соответствуют шаблону; пароль не отправлялся")
        csrf_name = re.compile(r"csrf|xsrf|authenticity|verificationtoken|anti.?forgery", re.I)
        declared_csrf = set(profile["request"]["csrf_fields"]) if profile else set()
        expected_csrf = {
            str(field.get("name")) for field in job.metadata.get("fields", [])
            if isinstance(field, Mapping)
            and field.get("name")
            and (field.get("type") == "hidden" or field.get("hidden") is True)
            and (csrf_name.search(str(field.get("name"))) or field.get("name") in declared_csrf)
            and not field.get("disabled")
        }
        actual_names = {name for name, _, _ in form.inputs}
        if not expected_csrf <= actual_names:
            raise ValueError(
                "Не удалось обновить CSRF-поля формы; пароль не отправлялся. "
                "Если токен создаёт JavaScript, попробуйте --auto-browser"
            )
        for name, field_type, value in form.inputs:
            if name in declared_csrf and sum(key == name for key, _, _ in form.inputs) != 1:
                raise ValueError("Неоднозначное CSRF-поле; пароль не отправлялся")
            if (csrf_name.search(name) or name in declared_csrf) and not value:
                raise ValueError(
                    "CSRF-токен пустой; пароль не отправлялся. "
                    "Если токен создаёт JavaScript, попробуйте --auto-browser"
                )
        fixed_fields = [
            (name, value) for name, field_type, value in form.inputs
            if name not in {identifier_name, password_name}
            and field_type in {"hidden", "text", "email", "search", "tel", "url", "number"}
        ]
        submit = next(
            ((name, value) for name, field_type, value in form.inputs if field_type == "submit"),
            None,
        )
        if submit is not None:
            fixed_fields.append(submit)
        return fixed_fields
    raise ValueError("Превышен предел редиректов страницы входа; пароль не отправлялся")


def _basic_outcome(response: HttpResponse) -> Outcome:
    common = _common_outcome(response)
    if common is not None:
        return common
    if 200 <= response.status < 300:
        return Outcome(OutcomeStatus.SUCCESS, detail=f"HTTP {response.status}")
    if response.status in {401, 403}:
        if response.status == 403:
            return Outcome(
                OutcomeStatus.UNSUPPORTED,
                detail=(
                    "HTTP 403: доступ запрещён; нельзя однозначно "
                    "отличить блокировку от отклонённой авторизации; "
                    "дальнейшие попытки остановлены"
                ),
                evidence={"reason": "http_403", "http_status": 403, "attempted": True},
            )
        return Outcome(OutcomeStatus.FAILURE, detail="HTTP 401")
    return Outcome(OutcomeStatus.AMBIGUOUS, detail=f"HTTP {response.status}")


def _form_outcome(
    response: HttpResponse, action: str, *, page_url: str, final_url: str,
    profile: dict | None = None, post_status: int | None = None,
) -> Outcome:
    common = _common_outcome(response)
    if common is not None:
        return common
    if profile is not None:
        decision = profile_outcome(profile, html_signals(response.body), final_url,
                                   status=response.status, post_status=post_status, submitted=True)
        if decision is not None:
            return decision
        if response.status == 403:
            return Outcome(OutcomeStatus.UNSUPPORTED, "HTTP 403: доступ запрещён", evidence={"reason": "http_403", "attempted": True, "http_status": 403})
        return profile_unconfirmed(profile, status=response.status, post_status=post_status)
    document = _LoginDocument(response.body)
    parsed_json = json_object(response.body)
    is_json_body = "json" in _response_headers(response).get("content-type", "").casefold() or bool(parsed_json)
    json_signal = json_auth_signal(parsed_json, _FAILURE_TEXT) if is_json_body else None
    if _CSRF_ERROR.search(document.text) or (is_json_body and _CSRF_ERROR.search(response.body)):
        return Outcome(
            OutcomeStatus.UNSUPPORTED,
            detail="Сайт отклонил session/CSRF-токен; результат входа не установлен",
            evidence={"reason": "csrf", "http_status": response.status},
        )
    if (document.otp_field and not document.password_field) or any(parsed_json.get(key) is True for key in (
        "mfa_required", "otp_required", "requires_otp", "two_factor_required",
    )):
        return Outcome(
            OutcomeStatus.MFA_REQUIRED,
            detail="После пароля требуется OTP/код подтверждения",
            evidence={"reason": "otp", "http_status": response.status},
        )
    # A number of login endpoints deliberately answer a rejected credential
    # with HTTP 403.  An explicit login-error message is stronger evidence
    # than the status code alone; generic 403 pages remain UNSUPPORTED so the
    # automatic browser fallback can inspect them.
    if json_signal == "failure" or (not is_json_body and _FAILURE_TEXT.search(document.text)):
        return Outcome(
            OutcomeStatus.FAILURE,
            detail="Сайт сообщил об ошибке авторизации",
            evidence={"reason": "login_error", "http_status": response.status},
        )
    if response.status in {401, 403}:
        if response.status == 403:
            return Outcome(
                OutcomeStatus.UNSUPPORTED,
                detail=(
                    "HTTP 403: доступ запрещён; нельзя однозначно "
                    "отличить блокировку от отклонённой авторизации; "
                    "дальнейшие попытки остановлены"
                ),
                evidence={"reason": "http_403", "http_status": 403, "attempted": True},
            )
        return Outcome(OutcomeStatus.FAILURE, detail="HTTP 401")
    if (
        200 <= response.status < 300
        and not document.password_field
        and (json_signal == "success" or (not is_json_body and document.has_logout_control(action)))
    ):
        return Outcome(
            OutcomeStatus.SUCCESS,
            detail="Получен явный признак успешного входа",
            evidence={"reason": "authenticated_marker", "http_status": response.status},
        )
    if json_signal == "error":
        return Outcome(
            OutcomeStatus.AMBIGUOUS,
            detail="Сайт вернул ошибку, но не подтвердил отказ в учётных данных",
            evidence={"reason": "site_error_unclassified", "http_status": response.status},
        )
    if (
        200 <= response.status < 300
        and not is_json_body
        and document.password_field
        and _same_page(final_url, page_url)
    ):
        return Outcome(
            OutcomeStatus.FAILURE,
            detail="После ответа осталась та же парольная форма входа",
            evidence={"reason": "password_form_remains", "http_status": response.status},
        )
    return Outcome(
        OutcomeStatus.AMBIGUOUS,
        detail=f"HTTP {response.status}: запрос отправлен, но результат входа не подтверждён",
        evidence={"reason": "unconfirmed", "http_status": response.status},
    )


def _same_page(first: str, second: str) -> bool:
    try:
        left, right = urlsplit(first), urlsplit(second)
        return _origin(left) == _origin(right) and (left.path or "/") == (right.path or "/")
    except ValueError:
        return False


@dataclass(slots=True)
class _VisibleElement:
    tag: str
    attrs: dict[str, str]
    hidden: bool
    text: list[str] = field(default_factory=list)


class _LoginDocument(HTMLParser):
    """Inspect rendered text and controls without treating source code as UI.

    This static parser cannot evaluate external CSS.  When the response has no
    explicit evidence, classification deliberately remains ambiguous.
    """

    def __init__(self, body: str) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[_VisibleElement] = []
        self._controls: list[_VisibleElement] = []
        self._text: list[str] = []
        self.password_field = False
        self.otp_field = False
        self.feed(body)
        self.close()
        self.text = " ".join(" ".join(self._text).split())

    def handle_starttag(self, tag, attrs) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        hidden = (
            bool(self._stack and self._stack[-1].hidden)
            or tag in {"head", "title", "script", "style", "template", "noscript"}
            or "hidden" in values
            or values.get("aria-hidden", "").casefold() == "true"
            or bool(re.search(
                r"display\s*:\s*none|visibility\s*:\s*hidden",
                values.get("style", ""), re.I,
            ))
        )
        element = _VisibleElement(tag, values, hidden)
        if not hidden and tag in {"a", "button"}:
            self._controls.append(element)
        if (
            not hidden and tag == "input" and "disabled" not in values
            and (
                values.get("type", "").casefold() == "password"
                or values.get("autocomplete", "").casefold() == "current-password"
            )
        ):
            self.password_field = True
        if (
            not hidden and tag == "input" and "disabled" not in values
            and (
                values.get("autocomplete", "").casefold() == "one-time-code"
                or _OTP_FIELD_NAME.fullmatch(values.get("name", ""))
            )
        ):
            self.otp_field = True
        if tag not in _VOID_TAGS:
            self._stack.append(element)

    def handle_startendtag(self, tag, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag) -> None:
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index].tag == tag:
                del self._stack[index:]
                break

    def handle_data(self, data) -> None:
        if self._stack and self._stack[-1].hidden:
            return
        self._text.append(data)
        for element in self._stack:
            if element.tag in {"a", "button"}:
                element.text.append(data)

    def has_logout_control(self, base_url: str) -> bool:
        for element in self._controls:
            if (
                "disabled" in element.attrs
                or element.attrs.get("aria-disabled", "").strip().casefold() == "true"
            ):
                continue
            label = " ".join("".join(element.text).split())
            if element.tag == "button" and _LOGOUT_LABEL.fullmatch(label):
                return True
            href = element.attrs.get("href", "").strip()
            if element.tag == "a" and href and not href.startswith("#"):
                try:
                    destination = urlsplit(urljoin(base_url, href))
                    if (
                        destination.scheme.casefold() in {"http", "https"}
                        and not destination.username and not destination.password
                        and _origin(destination) == _origin(urlsplit(base_url))
                        and (
                            _LOGOUT_LABEL.fullmatch(label)
                            or re.search(r"/(?:logout|signout|sign-out)(?:/|$)", destination.path, re.I)
                        )
                    ):
                        return True
                except ValueError:
                    continue
        return False


class _CookieResponse:
    def __init__(self, response: HttpResponse) -> None:
        self._headers = Message()
        headers = response.set_cookie_headers
        if not headers:
            single_header = _response_headers(response).get("set-cookie")
            headers = (single_header,) if single_header else ()
        for value in headers:
            self._headers.add_header("Set-Cookie", value)

    def info(self) -> Message:
        return self._headers


def _retain_cookies(cookies: http.cookiejar.CookieJar, url: str, response: HttpResponse) -> None:
    cookies.extract_cookies(_CookieResponse(response), Request(url))


def _response_headers(response: HttpResponse) -> dict[str, str]:
    return {str(key).casefold(): str(value) for key, value in response.headers.items()}


def _common_outcome(response: HttpResponse) -> Outcome | None:
    headers = _response_headers(response)
    if (
        headers.get("cf-mitigated", "").casefold() == "challenge"
        or _CHALLENGE_MARKERS.search(response.body[:100_000])
    ):
        return Outcome(
            OutcomeStatus.UNSUPPORTED,
            detail=(
                f"HTTP {response.status}: получена CAPTCHA/"
                "защитная страница; проверка остановлена"
            ),
            evidence={
                "reason": "challenge",
                "http_status": response.status,
                "attempted": True,
            },
        )
    if response.status == 407:
        return Outcome(OutcomeStatus.ERROR, detail="HTTP 407 proxy authentication required")
    if response.status == 423:
        return Outcome(OutcomeStatus.LOCKED_OUT, detail="HTTP 423")
    if response.status == 429:
        retry_after = _retry_after(response.headers.get("retry-after"))
        return Outcome(
            OutcomeStatus.RATE_LIMITED,
            detail="HTTP 429",
            retry_after_seconds=retry_after,
        )
    if 500 <= response.status <= 599:
        return Outcome(OutcomeStatus.NETWORK_ERROR, detail=f"HTTP {response.status}")
    return None


def _retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _origin(parts) -> tuple[str, str, int]:
    return (
        parts.scheme.casefold(),
        (parts.hostname or "").casefold(),
        parts.port or (443 if parts.scheme.casefold() == "https" else 80),
    )


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
