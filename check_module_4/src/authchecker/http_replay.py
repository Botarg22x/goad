"""Replay a captured login request with a fresh, private HTTP cookie session.

Templates, CSRF values and cookie jars live only in memory.  Redirect handling
is explicit: a credential POST is never automatically repeated by urllib.
"""

from __future__ import annotations

import copy
import http.client
import http.cookiejar
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

from .adapters.http import TargetScope, validate_target_url
from .auth_signals import json_auth_signal, json_object as _json_object
from .browser import BrowserCheckCancelled, BrowserCheckConfig, BrowserCheckResult
from .models import Credential, Outcome, OutcomeStatus
from .template_profile import apply_defaults, html_signals, profile_from_json, profile_outcome, profile_unconfirmed, render_raw_request

if TYPE_CHECKING:
    from .browser import BrowserRequestSnapshot


_MAX_BODY = 2 * 1024 * 1024
_CSRF = re.compile(r"csrf|xsrf|authenticity|verificationtoken|anti.?forgery", re.I)
_IDENTIFIER = re.compile(r"user(?:name)?|login|email|account|identifier", re.I)
_PASSWORD = re.compile(r"password|passwd|secret|(?:^|[_\[.-])pwd", re.I)
_CHALLENGE = re.compile(r"just a moment|attention required|verify (?:that )?you are human|проверка браузера", re.I)
_OTP = re.compile(r"two[- ]factor|verification code|one[- ]time (?:code|password)|код подтверждения|одноразов\w* код", re.I)
_OTP_PATH = re.compile(r"(?:send|resend|request|issue)[-_]?(?:email[-_]?)?(?:otp|code|magic)|(?:otp|code|magic)[-_]?(?:send|resend|request)", re.I)
_CSRF_ERROR = re.compile(r"(?:csrf|xsrf|authenticity)[^\n]{0,60}(?:invalid|expired|missing|mismatch|failed)|(?:invalid|expired|missing|mismatch|failed)[^\n]{0,60}(?:csrf|xsrf|authenticity)", re.I)
_FAILURE = re.compile(
    r"invalid (?:username|email|password|credentials)|incorrect (?:username|email|password)|"
    r"(?:username|email|password|credentials)[^\n]{0,80}(?:invalid|incorrect|wrong|do not match|does not match)|"
    r"(?:invalid|incorrect|wrong)[^\n]{0,80}(?:username|email|password|credentials)|"
    r"couldn.?t (?:log|sign) (?:you )?in|unable to (?:log|sign) in|"
    r"(?:login|sign[- ]?in|authentication) failed|wrong password|"
    r"(?:неверн\w*|неправильн\w*|ошибочн\w*)[^.!?\n]{0,100}"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)|"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)"
    r"[^.!?\n]{0,100}(?:неверн\w*|неправильн\w*|ошибочн\w*)",
    re.I,
)
_LOGOUT = re.compile(r"^\s*(?:sign\s*out|log\s*out|logout|выйти|выход)\s*$", re.I)
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_HOP_HEADERS = {"host", "cookie", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-connection", "accept-encoding"}


@dataclass(frozen=True, slots=True)
class _TokenBinding:
    location: tuple[Any, ...] | str = field(repr=False)
    source_kind: str
    source_name: str = field(repr=False)
    required: bool = True


@dataclass(frozen=True, slots=True)
class HttpReplayTemplate:
    """A request recipe with credential placeholders, never a reusable result."""

    url: str = field(repr=False)
    page_url: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body_type: str
    body: Any = field(repr=False)
    username_path: tuple[Any, ...] = field(repr=False)
    password_path: tuple[Any, ...] = field(repr=False)
    cookies: tuple[dict[str, Any], ...] = field(repr=False)
    tokens: tuple[_TokenBinding, ...] = field(repr=False)
    fields: tuple[str, ...] = field(repr=False)
    captured_authenticated: bool = False

    @classmethod
    def from_capture(cls, snapshot: BrowserRequestSnapshot, credential: Credential) -> HttpReplayTemplate:
        if snapshot.method.upper() != "POST":
            raise ValueError("HTTP replay поддерживает только POST-запрос авторизации")
        if _origin(snapshot.url) != _origin(snapshot.page_url):
            raise ValueError("HTTP replay не поддерживает отправку данных на другой origin")
        if not credential.username or not credential.password:
            raise ValueError("Для HTTP replay нужны непустые логин и пароль")
        if _has_password_query(snapshot.url, credential) or _has_password_query(snapshot.page_url, credential):
            raise ValueError("HTTP replay не поддерживает пароль в URL")
        if len(snapshot.body.encode("utf-8")) > _MAX_BODY:
            raise ValueError("Запрос авторизации превышает допустимый размер")
        if any(key.casefold() in {"authorization", "proxy-authorization"} for key in snapshot.headers):
            raise ValueError("HTTP replay не поддерживает захваченный Authorization-заголовок")
        headers = {str(key): str(value) for key, value in snapshot.headers.items() if key.casefold() not in _HOP_HEADERS}
        content_type = next((value for key, value in headers.items() if key.casefold() == "content-type"), "").split(";", 1)[0].strip().casefold()
        if content_type == "application/x-www-form-urlencoded":
            pairs = parse_qsl(snapshot.body, keep_blank_values=True, max_num_fields=10000)
            body_type = "form"
            body: Any = [[name, value] for name, value in pairs]
            leaves = [((index, 1), name, value) for index, (name, value) in enumerate(pairs)]
        elif content_type == "application/json" or content_type.endswith("+json"):
            try:
                body = json.loads(snapshot.body, object_pairs_hook=_unique_object)
            except (ValueError, RecursionError) as exc:
                raise ValueError("Не удалось однозначно разобрать JSON-запрос авторизации") from exc
            if not isinstance(body, (dict, list)):
                raise ValueError("JSON-запрос авторизации должен содержать объект или массив")
            body_type = "json"
            leaves = list(_json_leaves(body))
        else:
            raise ValueError("HTTP replay поддерживает application/x-www-form-urlencoded и JSON")
        username_path = _credential_path(leaves, snapshot.username_field, credential.username, _IDENTIFIER)
        password_path = _credential_path(leaves, snapshot.password_field, credential.password, _PASSWORD)
        if username_path == password_path:
            raise ValueError("Не удалось различить поля логина и пароля в запросе")
        if any(path not in {username_path, password_path} and value == credential.password for path, _, value in leaves):
            raise ValueError("Пароль встречается в нескольких полях захваченного запроса")
        doc = _Document(snapshot.page_html)
        doc.select_login_form(snapshot.page_url, snapshot.url, snapshot.username_field, snapshot.password_field)
        sources = [("hidden", name, value) for name, value in doc.hidden.items()]
        sources += [("meta", name, value) for name, value in doc.meta.items() if _CSRF.search(name)]
        sources += [("cookie", str(cookie.get("name", "")), unquote(str(cookie.get("value", "")))) for cookie in snapshot.cookies if _CSRF.search(str(cookie.get("name", "")))]
        tokens: list[_TokenBinding] = []
        for path, name, value in leaves:
            if path in {username_path, password_path}:
                _set_path(body, path, "")
                continue
            if name in doc.hidden:
                tokens.append(_TokenBinding(path, "hidden", name, bool(_CSRF.search(name))))
            elif _CSRF.search(name):
                kind, source_name = _token_source(name, value, sources)
                tokens.append(_TokenBinding(path, kind, source_name))
        for name, value in headers.items():
            if _CSRF.search(name):
                kind, source_name = _token_source(name, value, sources)
                tokens.append(_TokenBinding(name, kind, source_name))
        fields = (snapshot.username_field or _path_name(body_type, body, username_path), snapshot.password_field or _path_name(body_type, body, password_path))
        return cls(
            snapshot.url, snapshot.page_url, tuple(headers.items()), body_type,
            body, username_path, password_path,
            tuple(dict(cookie) for cookie in snapshot.cookies), tuple(tokens), fields,
            doc.positive(None),
        )


def run_http_replay(
    template: HttpReplayTemplate,
    credential: Credential,
    *,
    config: BrowserCheckConfig,
    target_scope: TargetScope | None = None,
    timeout_seconds: float = 10,
    on_progress: Callable[[str], None] | None = None,
    before_submit: Callable[[Callable[[float], None]], None] | None = None,
) -> BrowserCheckResult:
    """Refresh login tokens, then release at most one credential POST."""
    attempted = 0
    final_url = template.page_url
    last_status: int | None = None
    post_status: int | None = None
    blocked_info: dict[str, str] = {}

    def result(status: OutcomeStatus, detail: str, reason: str, retry_after: float | None = None) -> BrowserCheckResult:
        evidence: dict[str, Any] = {"reason": reason}
        if last_status is not None:
            evidence["http_status"] = last_status
        if post_status is not None:
            evidence["post_status"] = post_status
        evidence.update(blocked_info)
        return BrowserCheckResult(Outcome(status, detail, retry_after, evidence), attempted, _safe_url(final_url), template.fields)

    try:
        profile = profile_from_json(config.verification_json)
        if not 0 < timeout_seconds <= 60:
            return result(OutcomeStatus.UNSUPPORTED, "HTTP timeout должен быть от 0 до 60 секунд", "configuration")
        for value in (template.url, template.page_url):
            validate_target_url(value, target_scope)
        if _origin(template.url) != _origin(template.page_url):
            return result(OutcomeStatus.UNSUPPORTED, "Страница и POST находятся на разных origin", "scope")
        if _OTP_PATH.search(urlsplit(template.url).path):
            raise _ReplayStop("otp", "Шаг отправки OTP/письма остановлен", blocked_url=template.url, method="POST", request_type="http_request")
        if _has_password_query(template.url, credential) or _has_password_query(template.page_url, credential):
            return result(OutcomeStatus.UNSUPPORTED, "Пароль в URL не передаётся", "credential_url")
        success_selector = _Selector.parse(config.success_selector)
        failure_selector = _Selector.parse(config.failure_selector)
        if template.captured_authenticated:
            return result(OutcomeStatus.AMBIGUOUS, "Признак входа уже присутствовал до отправки формы", "preexisting_success")
        jar = http.cookiejar.CookieJar() if profile is not None else _cookie_jar(template.cookies, template.url)
        proxy = _proxy(config.proxy)
        if config.ca_cert:
            context = ssl.create_default_context(
                cafile=str(config.ca_cert.expanduser().resolve())
            )
        elif proxy:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            _ExplicitProxy({"http": proxy, "https": proxy} if proxy else {}),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(jar), _NoRedirect(),
        )
        user_agent = config.user_agent.strip()
        if not user_agent or len(user_agent) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in user_agent):
            return result(OutcomeStatus.UNSUPPORTED, "Некорректный User-Agent", "configuration")
        if on_progress:
            on_progress("[HTTP] Обновляю страницу входа и CSRF в отдельной сессии")
        refreshed = _follow_get(opener, template.page_url, target_scope, timeout_seconds, user_agent, credential)
        final_url, last_status = refreshed.url, refreshed.status
        doc = _Document(refreshed.body)
        doc.select_login_form(refreshed.url, template.url, *template.fields)
        special = _special_response(refreshed, doc, attempted=0)
        if special:
            return result(*special)
        if profile is not None:
            decision = profile_outcome(profile, html_signals(refreshed.body), refreshed.url, status=refreshed.status, submitted=False)
            if decision is not None:
                return result(decision.status, decision.detail, str(decision.evidence.get("reason", "")))
        if _origin(refreshed.url) != _origin(template.url):
            return result(OutcomeStatus.UNSUPPORTED, "Страница входа перешла на другой origin", "scope")
        if doc.positive(success_selector) or _json_auth_signal(_json_object(refreshed.body)) == "success":
            return result(OutcomeStatus.AMBIGUOUS, "Страница уже выглядит авторизованной до отправки формы", "preexisting_success")
        if refreshed.status >= 400:
            if refreshed.status == 403:
                return result(
                    OutcomeStatus.UNSUPPORTED,
                    "HTTP 403: доступ к странице входа запрещён; пароль не отправлялся",
                    "http_403",
                )
            return result(OutcomeStatus.UNSUPPORTED, "Не удалось обновить страницу входа", "http_error")
        if not doc.password_form:
            # The browser captured a rendered password form, but an ordinary
            # GET only returned the application's HTML shell. HTTP replay
            # could submit the captured request, yet could not inspect the
            # JavaScript-rendered outcome after a redirect. Switch transport
            # before spending an authentication attempt.
            return result(
                OutcomeStatus.UNSUPPORTED,
                "Форма входа создаётся JavaScript; для проверки результата нужен браузер, пароль не отправлялся",
                "browser_required",
            )
        body = copy.deepcopy(template.body)
        if profile is not None:
            if template.body_type != "form":
                return result(OutcomeStatus.UNSUPPORTED, "Шаблон ожидает form-запрос; нужен исходный браузерный сценарий", "browser_required")
            # The captured body may contain a stale Bitrix sessid which is not
            # covered by the generic csrf-name regexp. Bind it to this GET.
            for name in profile["request"]["csrf_fields"]:
                captured = [pair for pair in body if pair[0] == name]
                if captured or name in doc.hidden:
                    fresh = doc.hidden.get(name)
                    if not fresh:
                        return result(OutcomeStatus.UNSUPPORTED, "Не удалось обновить CSRF-поле шаблона", "csrf")
                    if not captured:
                        body.append([name, fresh])
                    for pair in captured:
                        pair[1] = fresh
            for name, value in doc.hidden.items():
                if name in template.fields:
                    continue
                pairs = [pair for pair in body if pair[0] == name]
                for pair in pairs:
                    pair[1] = value
                if not pairs:
                    body.append([name, value])
            # Append only: credential/token binding indexes must stay stable.
            body = [list(pair) for pair in apply_defaults(profile, [tuple(pair) for pair in body])]
        headers = {key: value for key, value in template.headers}
        for binding in template.tokens:
            fresh_value = _fresh_token(binding, doc, jar)
            if fresh_value is None:
                if binding.required:
                    return result(OutcomeStatus.UNSUPPORTED, "Не удалось обновить session/CSRF-токен; пароль не отправлялся", "csrf")
                continue
            if isinstance(binding.location, str):
                headers[binding.location] = fresh_value
            else:
                _set_path(body, binding.location, fresh_value)
        _set_path(body, template.username_path, credential.username)
        _set_path(body, template.password_path, credential.password)
        encoded = (urlencode([tuple(pair) for pair in body]) if template.body_type == "form" else json.dumps(body, ensure_ascii=False, separators=(",", ":"))).encode("utf-8")
        if profile is not None and "raw" in profile["request"]:
            template_headers, encoded = render_raw_request(
                profile, action=template.url, page_url=refreshed.url,
                fields=[tuple(pair) for pair in body], username_field=template.fields[0],
                password_field=template.fields[1], login=credential.username, password=credential.password,
            )
            template_names = {name.casefold() for name in template_headers}
            headers = {key: value for key, value in headers.items() if key.casefold() not in template_names}
            headers.update(template_headers)
        headers = {key: value for key, value in headers.items() if key.casefold() not in _HOP_HEADERS and key.casefold() != "user-agent"}
        headers.update({"User-Agent": user_agent, "Accept-Encoding": "identity"})
        if before_submit:
            before_submit(time.sleep)
        if on_progress:
            on_progress("[HTTP] Отправляю одну попытку авторизации")
        attempted = 1
        posted = _request(opener, template.url, timeout_seconds, headers=headers, body=encoded)
        post_status = posted.status
        final_url, last_status = posted.url, posted.status
        doc = _Document(posted.body)
        special = _special_response(posted, doc, attempted=1)
        if special:
            return result(*special)
        if posted.status in {307, 308}:
            destination = urljoin(posted.url, posted.headers.get("location", posted.url))
            raise _ReplayStop("credential_redirect", "Повтор POST через редирект остановлен", blocked_url=destination, method="POST", request_type="http_redirect")
        if 300 <= posted.status < 400:
            if posted.status not in {302, 303} or not posted.headers.get("location"):
                return result(OutcomeStatus.AMBIGUOUS, "Редирект не подтверждает вход", "unconfirmed")
            destination = urljoin(posted.url, posted.headers["location"])
            _check_get_destination(destination, target_scope, template.url, credential)
            posted = _follow_get(opener, destination, target_scope, timeout_seconds, user_agent, credential, redirect_budget=4)
            final_url, last_status = posted.url, posted.status
            doc = _Document(posted.body)
            special = _special_response(posted, doc, attempted=1)
            if special:
                return result(*special)
        if profile is not None:
            decision = profile_outcome(profile, html_signals(posted.body), posted.url,
                                       status=posted.status, post_status=post_status, submitted=True)
            if decision is not None:
                return result(decision.status, decision.detail, str(decision.evidence.get("reason", "")))
            if posted.status == 403:
                return result(OutcomeStatus.UNSUPPORTED, "HTTP 403: доступ запрещён", "http_403")
            unmatched = profile_unconfirmed(profile, status=posted.status, post_status=post_status)
            return result(unmatched.status, unmatched.detail, str(unmatched.evidence["reason"]))
        json_body = _json_object(posted.body)
        is_json_body = _is_json(posted) or bool(json_body)
        if _CSRF_ERROR.search(doc.text) or _CSRF_ERROR.search(posted.body if is_json_body else ""):
            return result(OutcomeStatus.UNSUPPORTED, "Сайт отклонил session/CSRF-токен", "csrf")
        json_signal = _json_auth_signal(json_body) if is_json_body else None
        if ((not is_json_body and (doc.matches(failure_selector) or _FAILURE.search(doc.text)))
                or json_signal == "failure" or posted.status == 401):
            return result(OutcomeStatus.FAILURE, "Сайт сообщил об ошибке авторизации", "login_error")
        if posted.status >= 400:
            if posted.status == 403:
                return result(
                    OutcomeStatus.UNSUPPORTED,
                    "HTTP 403: доступ запрещён; нельзя однозначно отличить блокировку от отклонённой авторизации",
                    "http_403",
                )
            return result(OutcomeStatus.UNSUPPORTED, "Сайт отклонил запрос авторизации", "http_error")
        html_success = not is_json_body and doc.positive(success_selector)
        if 200 <= posted.status < 300 and not doc.password_form and json_signal != "error" and (json_signal == "success" or html_success):
            return result(OutcomeStatus.SUCCESS, "Получен явный признак успешного входа", "authenticated_marker")
        if json_signal == "error":
            return result(
                OutcomeStatus.AMBIGUOUS,
                "Сайт вернул ошибку, но не подтвердил отказ в учётных данных",
                "site_error_unclassified",
            )
        if (
            200 <= posted.status < 300
            and not is_json_body
            and doc.password_form
            and not doc.positive(success_selector)
            and _same_page(posted.url, template.page_url)
        ):
            return result(
                OutcomeStatus.FAILURE,
                "После ответа осталась та же парольная форма входа",
                "password_form_remains",
            )
        return result(OutcomeStatus.AMBIGUOUS, "Запрос отправлен, но однозначный результат не обнаружен", "unconfirmed")
    except BrowserCheckCancelled:
        return result(OutcomeStatus.SKIPPED, "Проверка прервана пользователем", "interrupted")
    except _ReplayStop as exc:
        blocked_info.update(exc.evidence)
        return result(OutcomeStatus.UNSUPPORTED, exc.detail, exc.reason)
    except (urllib.error.URLError, OSError, ssl.SSLError, TimeoutError, http.client.HTTPException):
        return result(OutcomeStatus.NETWORK_ERROR, "Не удалось получить HTTP-ответ через выбранное соединение", "network_error")
    except (ValueError, TypeError, RecursionError):
        return result(OutcomeStatus.UNSUPPORTED, "Запрос или настройки HTTP replay не поддерживаются", "configuration")


@dataclass(frozen=True, slots=True)
class _Response:
    url: str = field(repr=False)
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: str = field(repr=False)


class _ReplayStop(Exception):
    def __init__(self, reason: str, detail: str, *, blocked_url: str | None = None, method: str = "", request_type: str = "") -> None:
        self.reason, self.detail = reason, detail
        self.evidence: dict[str, str] = {}
        if blocked_url:
            self.evidence["blocked_origin"] = _safe_origin(blocked_url)
        if method:
            self.evidence["method"] = method
        if request_type:
            self.evidence["request_type"] = request_type


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ExplicitProxy(urllib.request.ProxyHandler):
    def proxy_open(self, request, proxy, request_type):
        # An explicitly chosen proxy applies to loopback and NO_PROXY hosts as
        # well.  ProxyHandler's default implementation consults proxy_bypass.
        parts = urlsplit(proxy)
        request.set_proxy(parts.netloc, parts.scheme)
        return None


def _request(opener, url: str, timeout: float, *, headers: Mapping[str, str], body: bytes | None = None) -> _Response:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST" if body is not None else "GET")
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(_MAX_BODY + 1)
        if len(raw) > _MAX_BODY:
            raise _ReplayStop("response_limit", "HTTP-ответ превышает допустимый размер")
        encoding = response.headers.get("Content-Encoding", "").casefold()
        if encoding in {"gzip", "deflate"}:
            try:
                raw = zlib.decompressobj(31 if encoding == "gzip" else 15).decompress(raw, _MAX_BODY + 1)
            except zlib.error as exc:
                raise _ReplayStop("response_encoding", "Не удалось прочитать сжатый HTTP-ответ") from exc
            if len(raw) > _MAX_BODY:
                raise _ReplayStop("response_limit", "HTTP-ответ превышает допустимый размер")
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return _Response(response.geturl(), response.code, {key.casefold(): value for key, value in response.headers.items()}, text)


def _follow_get(opener, url: str, scope: TargetScope | None, timeout: float, user_agent: str, credential: Credential, *, redirect_budget: int = 5) -> _Response:
    initial = url
    for step in range(redirect_budget + 1):
        _check_get_destination(url, scope, initial, credential)
        if _OTP_PATH.search(urlsplit(url).path):
            raise _ReplayStop("otp", "Шаг отправки OTP/письма остановлен", blocked_url=url, method="GET", request_type="http_request")
        response = _request(opener, url, timeout, headers={"User-Agent": user_agent, "Accept-Encoding": "identity"})
        if not 300 <= response.status < 400 or not response.headers.get("location"):
            return response
        if step == redirect_budget:
            raise _ReplayStop("redirect_limit", "Превышен лимит редиректов")
        url = urljoin(url, response.headers["location"])
    raise AssertionError("unreachable")


def _check_get_destination(url: str, scope: TargetScope | None, initial: str, credential: Credential) -> None:
    try:
        validate_target_url(url, scope)
    except ValueError as exc:
        raise _ReplayStop("scope", "Редирект за пределы разрешённой области остановлен", blocked_url=url, method="GET", request_type="http_redirect") from exc
    if scope is None and _origin(url) != _origin(initial):
        raise _ReplayStop("scope", "Редирект на другой origin остановлен", blocked_url=url, method="GET", request_type="http_redirect")
    if _has_password_query(url, credential):
        raise _ReplayStop("credential_url", "Передача пароля через URL остановлена", blocked_url=url, method="GET", request_type="http_redirect")


def _credential_path(leaves, dom_name: str, value: str, pattern) -> tuple[Any, ...]:
    exact = [path for path, name, item in leaves if dom_name and name == dom_name and item == value]
    if not exact:
        exact = [path for path, name, item in leaves if pattern.search(name) and item == value]
    if len(exact) != 1:
        raise ValueError("Не удалось однозначно сопоставить credential-поле с захваченным запросом")
    return exact[0]


def _json_leaves(value: Any, path: tuple[Any, ...] = ()):
    if isinstance(value, dict):
        for name, child in value.items():
            if isinstance(child, str):
                yield (*path, name), name, child
            elif isinstance(child, (dict, list)):
                yield from _json_leaves(child, (*path, name))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                yield from _json_leaves(child, (*path, index))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous JSON keys")
        result[key] = value
    return result


def _set_path(body: Any, path: tuple[Any, ...], value: str) -> None:
    for segment in path[:-1]:
        body = body[segment]
    body[path[-1]] = value


def _path_name(body_type: str, body: Any, path: tuple[Any, ...]) -> str:
    return str(body[path[0]][0] if body_type == "form" else path[-1])


def _token_source(name: str, value: str, sources) -> tuple[str, str]:
    matches = [(kind, source_name) for kind, source_name, old in sources if old and unquote(value) == unquote(old)]
    if matches:
        return matches[0]
    if name:
        direct = [(kind, source_name) for kind, source_name, _ in sources if source_name.casefold() == name.casefold()]
        if direct:
            return direct[0]
    return "auto", name


def _fresh_token(binding: _TokenBinding, doc, jar) -> str | None:
    if binding.source_kind == "hidden":
        return doc.hidden.get(binding.source_name)
    if binding.source_kind == "meta":
        return doc.meta.get(binding.source_name.casefold())
    cookies = {cookie.name.casefold(): unquote(cookie.value) for cookie in jar if cookie.value}
    if binding.source_kind == "cookie":
        return cookies.get(binding.source_name.casefold())
    source = binding.source_name.casefold()
    for name, value in (*doc.hidden.items(), *doc.meta.items(), *cookies.items()):
        if name.casefold() == source:
            return value
    if "xsrf" in source:
        for name in ("xsrf-token", "xsrf_token"):
            if name in cookies:
                return cookies[name]
    candidates = [value for name, value in (*doc.meta.items(), *doc.hidden.items(), *cookies.items()) if _CSRF.search(name) and value]
    return candidates[0] if len(set(candidates)) == 1 else None


def _cookie_jar(cookies, url: str) -> http.cookiejar.CookieJar:
    jar = http.cookiejar.CookieJar()
    hostname = (urlsplit(url).hostname or "").casefold()
    for data in cookies:
        domain = str(data.get("domain") or hostname).casefold()
        bare = domain.lstrip(".")
        if not bare or not (hostname == bare or hostname.endswith("." + bare)):
            continue
        name, value = data.get("name"), data.get("value")
        if not isinstance(name, str) or not isinstance(value, str) or any(char in name + value for char in "\r\n\x00"):
            continue
        expires = data.get("expires", -1)
        expiry = int(expires) if isinstance(expires, (int, float)) and expires > 0 else None
        jar.set_cookie(http.cookiejar.Cookie(
            0, name, value, None, False, domain, domain.startswith("."), domain.startswith("."),
            str(data.get("path") or "/"), True, bool(data.get("secure")), expiry, expiry is None,
            None, None, {"HttpOnly": None} if data.get("httpOnly") else {}, False,
        ))
    return jar


def _special_response(response: _Response, doc, *, attempted: int):
    parsed = _json_object(response.body)
    if (response.headers.get("cf-mitigated", "").casefold() == "challenge" or _CHALLENGE.search(doc.title)
            or parsed.get("challenge_required") is True or parsed.get("captcha_required") is True):
        return OutcomeStatus.UNSUPPORTED, "Получена CAPTCHA/защитная страница; HTTP replay остановлен", "challenge"
    if response.status == 429:
        try:
            retry_after = max(0.0, float(response.headers.get("retry-after", "")))
            if not math.isfinite(retry_after):
                retry_after = None
        except ValueError:
            retry_after = None
        return OutcomeStatus.RATE_LIMITED, "Сайт ограничил число запросов (HTTP 429)", "rate_limit", retry_after
    if response.status == 423:
        return OutcomeStatus.LOCKED_OUT, "Сайт сообщил о блокировке (HTTP 423)", "locked_out"
    otp = doc.otp or any(parsed.get(key) is True for key in ("mfa_required", "otp_required", "requires_otp", "two_factor_required"))
    if otp:
        return (OutcomeStatus.MFA_REQUIRED if attempted else OutcomeStatus.UNSUPPORTED), "Требуется OTP/код подтверждения; продолжение остановлено", "otp"
    if _CSRF_ERROR.search(doc.text) or (_is_json(response) and _CSRF_ERROR.search(response.body)):
        return OutcomeStatus.UNSUPPORTED, "Сайт отклонил session/CSRF-токен", "csrf"
    return None


def _json_auth_signal(value: dict) -> str | None:
    return json_auth_signal(value, _FAILURE)


def _is_json(response: _Response) -> bool:
    return "json" in response.headers.get("content-type", "").casefold()


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme.casefold(), (parts.hostname or "").casefold(), parts.port or (443 if parts.scheme.casefold() == "https" else 80)


def _same_page(first: str, second: str) -> bool:
    try:
        left, right = urlsplit(first), urlsplit(second)
        return _origin(first) == _origin(second) and (left.path or "/") == (right.path or "/")
    except ValueError:
        return False


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, ""))


def _safe_origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
            return ""
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host += f":{parts.port}"
        return urlunsplit((parts.scheme, host, "", "", ""))
    except ValueError:
        return ""


def _has_password_query(url: str, credential: Credential) -> bool:
    return any(_PASSWORD.search(key) or value == credential.password for key, value in parse_qsl(urlsplit(url).query))


def _proxy(proxy: str | None) -> str | None:
    if not proxy:
        return None
    parts = urlsplit(proxy)
    if (parts.scheme.casefold() != "http" or not parts.hostname or parts.username or parts.password
            or parts.path not in {"", "/"} or parts.query or parts.fragment or not 0 < (parts.port or 80) <= 65535):
        raise ValueError("unsupported proxy")
    return proxy


@dataclass(slots=True)
class _Form:
    attrs: dict[str, str] = field(repr=False)
    hidden: dict[str, str] = field(default_factory=dict, repr=False)
    names: set[str] = field(default_factory=set, repr=False)
    has_password: bool = False


@dataclass(slots=True)
class _Element:
    tag: str
    attrs: dict[str, str] = field(repr=False)
    hidden: bool = False
    text: str = field(default="", repr=False)
    form: _Form | None = field(default=None, repr=False)


class _Document(HTMLParser):
    def __init__(self, body: str) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[_Element] = []
        self.stack: list[_Element] = []
        self.hidden: dict[str, str] = {}
        self.meta: dict[str, str] = {}
        self.forms: list[_Form] = []
        self.title = ""
        self.text = ""
        self.password_form = False
        self.otp = False
        self.feed(body)
        self.close()
        self.otp = self.otp or (not self.password_form and bool(_OTP.search(self.text)))

    def handle_starttag(self, tag, attrs) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        hidden = bool(self.stack and self.stack[-1].hidden) or "hidden" in values or bool(re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", values.get("style", ""), re.I))
        element = _Element(tag, values, hidden)
        if tag == "form":
            element.form = _Form(values)
            self.forms.append(element.form)
        self.elements.append(element)
        if tag not in _VOID:
            self.stack.append(element)
        if tag == "meta" and values.get("name"):
            self.meta[values["name"].casefold()] = values.get("content", "")
        if tag == "input":
            name = values.get("name", "")
            active = next((entry.form for entry in reversed(self.stack) if entry.form is not None), None)
            if active is not None:
                if name:
                    active.names.add(name)
                if values.get("type", "").casefold() == "hidden" and name:
                    active.hidden[name] = values.get("value", "")
                if values.get("type", "").casefold() == "password":
                    active.has_password = True
            if not hidden and values.get("type", "").casefold() == "password":
                self.password_form = True
            if not hidden and (values.get("autocomplete") == "one-time-code" or name.casefold() in {"otp", "totp", "verification_code", "email_code"}):
                self.otp = True
        if tag == "form" and _OTP_PATH.search(values.get("action", "")):
            self.otp = True

    def handle_endtag(self, tag) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data) -> None:
        if any(element.tag == "title" for element in self.stack):
            self.title += data
        if self.stack and (self.stack[-1].hidden or self.stack[-1].tag in {"script", "style"}):
            return
        self.text += data + " "
        for element in self.stack:
            if element.tag in {"a", "button"}:
                element.text += data

    def matches(self, selector) -> bool:
        return selector is not None and any(not element.hidden and selector.matches(element) for element in self.elements)

    def select_login_form(self, page_url: str, action_url: str, username_field: str, password_field: str) -> None:
        scored = []
        for form in self.forms:
            action = urljoin(page_url, form.attrs.get("action", "") or page_url)
            same_action = action == action_url
            roles = bool(username_field and username_field in form.names) + bool(password_field and password_field in form.names)
            if not form.has_password and roles < 2:
                continue
            score = roles * 5 + 3 * same_action + int(form.has_password)
            scored.append((score, form))
        if scored:
            best = max(score for score, _ in scored)
            matches = [form for score, form in scored if score == best]
            if len(matches) == 1:
                self.hidden = matches[0].hidden.copy()

    def positive(self, selector) -> bool:
        if selector is not None:
            return self.matches(selector)
        return any(not element.hidden and element.tag in {"a", "button"} and (
            _LOGOUT.fullmatch(element.text) or any(marker in element.attrs.get("href", "").casefold() for marker in ("/logout", "/signout", "/sign-out"))
        ) for element in self.elements)


@dataclass(frozen=True, slots=True)
class _Selector:
    tag: str | None
    identifier: str | None
    classes: tuple[str, ...]
    attrs: tuple[tuple[str, str | None], ...]

    @classmethod
    def parse(cls, value: str | None):
        if value is None:
            return None
        rest = value.strip()
        tag = identifier = None
        classes: list[str] = []
        attrs: list[tuple[str, str | None]] = []
        match = re.match(r"(?:[a-zA-Z][\w:-]*|\*)", rest)
        if match:
            tag, rest = match.group().casefold(), rest[match.end():]
        while rest:
            match = re.match(r"([#.])([\w-]+)", rest)
            if match:
                if match[1] == "#":
                    if identifier is not None:
                        raise _ReplayStop("selector", "HTTP replay не поддерживает этот CSS-селектор")
                    identifier = match[2]
                else:
                    classes.append(match[2])
                rest = rest[match.end():]
                continue
            match = re.match(r'''\[\s*([\w:-]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+)))?\s*\]''', rest)
            if match:
                attrs.append((match[1].casefold(), next((item for item in match.groups()[1:] if item is not None), None)))
                rest = rest[match.end():]
                continue
            raise _ReplayStop("selector", "HTTP replay поддерживает только простые #id, .class, tag и [attr] селекторы")
        if tag is None and identifier is None and not classes and not attrs:
            raise _ReplayStop("selector", "Пустой селектор результата входа")
        return cls(tag, identifier, tuple(classes), tuple(attrs))

    def matches(self, element: _Element) -> bool:
        return (
            (self.tag in {None, "*", element.tag})
            and (self.identifier is None or element.attrs.get("id") == self.identifier)
            and all(value in element.attrs.get("class", "").split() for value in self.classes)
            and all(name in element.attrs and (value is None or element.attrs[name] == value) for name, value in self.attrs)
        )
