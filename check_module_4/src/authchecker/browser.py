"""One browser-backed login check in an ephemeral, scoped session."""

from __future__ import annotations

import json
import math
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlsplit, urlunsplit

from .adapters.http import TargetScope, validate_target_url
from .browser_tls import browser_tls_args
from .defaults import DEFAULT_USER_AGENT
from .models import Credential, Outcome, OutcomeStatus
from .template_profile import browser_signals, prepare_browser_form, profile_from_json, profile_outcome, profile_unconfirmed, render_raw_request


_IDENTIFIER = re.compile(r"user(?:name)?|login|email|account|identifier", re.I)
_LOGIN_LABEL = re.compile(r"^\s*(?:sign\s*in|log\s*in|login|войти|вход)\s*$", re.I)
_CONTINUE_LABEL = re.compile(
    r"^\s*(?:continue|next|proceed|sign\s*in|log\s*in|login|"
    r"продолжить|далее|войти|вход)\s*$",
    re.I,
)
_LOGOUT_LABEL = re.compile(r"^\s*(?:sign\s*out|log\s*out|logout|выйти|выход)\s*$", re.I)
_OTP_PATH = re.compile(
    r"(?:send|resend|request|issue)[-_]?(?:email[-_]?)?(?:otp|code|magic)|"
    r"(?:otp|code|magic)[-_]?(?:send|resend|request)", re.I,
)
_NON_LOGIN_PATH = re.compile(r"(?:^|/)(?:sign[-_]?ups?|register|registrations?|reset|forgot|change[-_]password)(?:[/_.-]|$)", re.I)
_REGISTRATION_TEXT = re.compile(r"sign\s*up|register|create (?:an? )?account|reset password|регистрац|создать аккаунт", re.I)
_AUTH_PATH = re.compile(r"(?:^|/)(?:log[-_]?in|sign[-_]?in|sessions?|authenticate)(?:[/_.-]|$)", re.I)
_FAILURE = re.compile(
    r"invalid (?:username|email|password|credentials)|incorrect (?:username|email|password)|"
    r"(?:username|email|password|credentials)[^\n]{0,80}(?:invalid|incorrect|wrong|do not match|does not match)|"
    r"(?:invalid|incorrect|wrong)[^\n]{0,80}(?:username|email|password|credentials)|"
    r"couldn.?t (?:log|sign) (?:you )?in|unable to (?:log|sign) in|"
    r"(?:login|sign[- ]?in|authentication) failed|wrong password|"
    r"(?:неверн\w*|неправильн\w*|ошибочн\w*)[^.!?\n]{0,100}"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)|"
    r"(?:логин|парол\w*|имя\s+пользовател\w*|уч[её]тн\w*\s+данн\w*)"
    r"[^.!?\n]{0,100}(?:неверн\w*|неправильн\w*|ошибочн\w*)", re.I,
)
_CHALLENGE_TITLE = re.compile(
    r"just a moment|attention required|verify (?:that )?you are human|"
    r"captcha|security check|проверка (?:браузера|безопасности)",
    re.I,
)
_CAPTCHA_SELECTOR = (
    "iframe[src*='recaptcha' i], iframe[src*='hcaptcha' i], "
    "iframe[src*='challenges.cloudflare.com' i], .g-recaptcha, .h-captcha, "
    "[data-hcaptcha-widget-id]"
)
_MFA_TEXT = re.compile(r"two[- ]factor|verification code|one[- ]time (?:code|password)|код подтверждения|одноразов\w* код", re.I)
_OTP_INTENT = re.compile(
    r"send (?:me )?(?:a )?(?:code|link)|email (?:me )?(?:a )?(?:code|link)|"
    r"magic link|one[- ]time (?:code|link)|получить код|отправить код|"
    r"код на почт|ссылк\w* на почт",
    re.I,
)
_COOKIE_TEXT = re.compile(r"cookies?|cookie-файл|файл\w* cookie|куки", re.I)
_COOKIE_REJECT_LABEL = re.compile(
    r"^\s*(?:reject(?:\s+all)?(?:\s+cookies)?|only\s+necessary(?:\s+cookies)?|"
    r"necessary\s+only|decline(?:\s+all)?|отклонить(?:\s+все)?|только\s+необходимые)\s*$", re.I,
)
_SITE_ERROR_TEXT = re.compile(
    r"(?:unknown|unexpected|internal|server)\s+error|something went wrong|"
    r"an error (?:has )?occurred|произошла\s+(?:неизвестн\w*\s+)?ошибк\w*|"
    r"(?:неизвестн\w*|непредвиденн\w*|внутренн\w*)\s+ошибк\w*",
    re.I,
)
_SITE_ERROR_CLOSE = re.compile(r"^\s*(?:close|dismiss|закрыть|ok|ок|понятно)\s*$", re.I)


class BrowserCheckCancelled(RuntimeError):
    """A batch stopped before a paused authentication request was released."""


@dataclass(frozen=True, slots=True)
class BrowserCheckConfig:
    headless: bool = False
    timeout_seconds: float = 60.0
    proxy: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    ca_cert: Path | None = None
    success_selector: str | None = None
    failure_selector: str | None = None
    stop_on_challenge: bool = False
    username_field_hint: str = ""
    password_field_hint: str = ""
    verification_json: str = ""
    required_csrf_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BrowserCheckResult:
    outcome: Outcome
    attempted_count: int = 0
    final_url: str = ""
    fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BrowserRequestSnapshot:
    """An intercepted request held in memory; never include it in diagnostics."""

    method: str = field(repr=False)
    url: str = field(repr=False)
    headers: dict[str, str] = field(repr=False)
    body: str = field(repr=False)
    cookies: tuple[dict[str, Any], ...] = field(repr=False)
    page_html: str = field(repr=False)
    page_url: str = field(repr=False)
    username_field: str = field(repr=False)
    password_field: str = field(repr=False)


@dataclass(slots=True)
class _State:
    armed: bool = False
    attempted: int = 0
    request: Any = None
    response_status: int | None = None
    response_finished: bool = False
    request_failed: bool = False
    resource_error: str = ""
    document_status: int | None = None
    challenge: bool = False
    blocked_reason: str = ""
    submission_action: str = ""
    password_name: str = ""
    username_name: str = ""
    filling: bool = False
    capturing: bool = False
    captured: bool = False
    blocked_origin: str = ""
    blocked_method: str = ""
    blocked_request_type: str = ""
    identifier_advancing: bool = False
    identifier_submitted: bool = False
    identifier_action: str = ""


@dataclass(slots=True)
class _LoginForm:
    identifier: Any | None
    password: Any
    submit: Any = None
    action: str = ""
    fields: tuple[str, ...] = field(default_factory=tuple)


@dataclass(slots=True)
class _IdentifierStep:
    identifier: Any
    submit: Any
    action: str
    field_name: str


@dataclass(frozen=True, slots=True)
class _PositiveMarker:
    description: str
    explicit: bool = False


def run_browser_check(
    url: str,
    credential: Credential,
    *,
    config: BrowserCheckConfig,
    target_scope: TargetScope | None = None,
    on_progress: Callable[[str], None] | None = None,
    before_submit: Callable[[Callable[[float], None]], None] | None = None,
    on_capture: Callable[[BrowserRequestSnapshot], None] | None = None,
) -> BrowserCheckResult:
    """Load, discover and submit once without discarding browser session state.

    Browser resources may load from other origins. Credential submissions stay
    on the exact initial origin. One clearly identified login-to-password step
    may submit only the identifier; OTP, magic-link and identifier-in-URL steps
    are never submitted.
    A redirect alone cannot establish success.  No page bodies, request bodies,
    cookies or storage state are persisted by this function.

    ``before_submit`` runs immediately before the permitted credential POST is
    released to the network, so isolated checks can share a submission rate.
    Its waiter keeps this browser's event loop running while it is delayed.

    ``on_capture`` receives the first credential request without sending it.
    A successful capture returns SKIPPED/request_captured with zero attempts.
    """
    validate_target_url(url, target_scope)
    profile = profile_from_json(config.verification_json)
    if not math.isfinite(config.timeout_seconds) or not 1 <= config.timeout_seconds <= 300:
        raise ValueError("--browser-timeout должен быть от 1 до 300 секунд")
    if not credential.username or not credential.password:
        raise ValueError("--browser требует один непустой логин и пароль")
    user_agent = config.user_agent.strip()
    if not user_agent or len(user_agent) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in user_agent):
        raise ValueError("некорректный User-Agent")
    proxy = _proxy_url(config.proxy)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ValueError("Для --browser установите Playwright: pip install -e 'check_module_4[browser]'") from exc

    state = _State()
    fields: tuple[str, ...] = ()
    page: Any = None
    capture_page_html = ""

    def progress(message: str) -> None:
        if on_progress is not None:
            on_progress(message)

    def result(status: OutcomeStatus, detail: str, reason: str = "") -> BrowserCheckResult:
        # DOM queries also dispatch network events.  A deliberate block may
        # have arrived after the loop's first guard; it wins over a provisional
        # result (including requestfailed caused by our own Fetch.failRequest).
        if state.blocked_reason and reason != state.blocked_reason:
            return _blocked_result(state.blocked_reason, result)
        evidence: dict[str, object] = {}
        if reason:
            evidence["reason"] = reason
        status_code = state.response_status if state.attempted else state.document_status
        if status_code is not None:
            evidence["http_status"] = status_code
        if state.attempted and state.response_status is not None:
            evidence["post_status"] = state.response_status
        for name in ("blocked_origin", "blocked_method", "blocked_request_type"):
            value = getattr(state, name)
            if value:
                evidence[name] = value
        final_url = _safe_url(page.url) if page is not None and not page.is_closed() else _safe_url(url)
        return BrowserCheckResult(Outcome(status, detail, evidence=evidence), state.attempted, final_url, fields)

    try:
        launch_args = browser_tls_args(
            url, ca_cert=config.ca_cert, proxy=proxy,
            timeout_seconds=min(config.timeout_seconds, 30),
        )
    except ValueError as exc:
        return result(OutcomeStatus.NETWORK_ERROR, str(exc), "tls")
    if proxy:
        launch_args.append("--proxy-bypass-list=<-loopback>")
    else:
        launch_args.append("--no-proxy-server")
    options: dict[str, Any] = {"headless": config.headless, "args": launch_args}
    executable = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if executable:
        options["executable_path"] = executable
    if proxy:
        options["proxy"] = {"server": proxy}

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**options, timeout=config.timeout_seconds * 1000)
            try:
                context = browser.new_context(
                    user_agent=user_agent,
                    ignore_https_errors=bool(proxy and config.ca_cert is None),
                    service_workers="block", viewport={"width": 1280, "height": 800},
                )
                page = context.new_page()
                page.set_default_timeout(min(config.timeout_seconds, 10) * 1000)
                if profile is not None and profile["request"]["action"] in {"page", "fixed"}:
                    if on_capture is not None:
                        return result(OutcomeStatus.UNSUPPORTED, "Запрос уже задан шаблоном; перехват формы не требуется", "template_capture")
                    from .browser_page_template import check_page_template
                    return check_page_template(context, page, url, credential, profile, config=config,
                                               target_scope=target_scope, on_progress=on_progress,
                                               before_submit=before_submit)

                def in_scope(candidate: str) -> bool:
                    try:
                        validate_target_url(candidate, target_scope)
                        return target_scope is not None or _origin(candidate) == _origin(url)
                    except ValueError:
                        return False

                def has_secret_query(candidate: str) -> bool:
                    return any(
                        re.search(r"password|passwd|(?:^|[_\[.-])pwd", key, re.I)
                        or (state.password_name and key == state.password_name)
                        or value == credential.password
                        for key, value in parse_qsl(urlsplit(candidate).query)
                    )

                def has_identifier_query(candidate: str) -> bool:
                    return any(value == credential.username for _, value in parse_qsl(urlsplit(candidate).query))

                def block(reason: str, candidate: str, method: str, resource_type: str) -> None:
                    state.blocked_reason = reason
                    state.blocked_origin = _safe_origin(candidate)
                    state.blocked_method = method.upper()
                    state.blocked_request_type = resource_type

                def route_request(route: Any) -> None:
                    request = route.request
                    try:
                        owner_page = request.frame.page
                    except PlaywrightError:
                        block("popup", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if owner_page != page:
                        block("popup", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    parts = urlsplit(request.url)
                    if _OTP_PATH.search(parts.path) and request.resource_type not in {"script", "stylesheet", "image", "font"}:
                        block("otp", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if has_secret_query(request.url):
                        block("credential_url", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if state.identifier_advancing and has_identifier_query(request.url):
                        block("identifier_url", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if request.is_navigation_request() and request.frame == page.main_frame and not in_scope(request.url):
                        block("scope", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if request.method in {"GET", "HEAD"}:
                        route.continue_()
                        return
                    raw_body = request.post_data or ""
                    body = unquote_plus(raw_body)
                    has_credentials = _body_contains_credentials(raw_body, credential)
                    has_identifier = _body_contains_identifier(raw_body, credential.username)
                    has_password = _body_contains_password(raw_body, credential.password)
                    if state.identifier_advancing:
                        rejected = [
                            reason
                            for reason, condition in (
                                ("already_submitted", state.identifier_submitted),
                                ("method", request.method != "POST"),
                                ("origin", _origin(request.url) != _origin(url)),
                                (
                                    "action",
                                    not (
                                        request.is_navigation_request()
                                        or _same_page(request.url, state.identifier_action)
                                        or _AUTH_PATH.search(parts.path)
                                    ),
                                ),
                                ("identifier_missing", not has_identifier),
                                ("password_present", has_password),
                            )
                            if condition
                        ]
                        if rejected:
                            progress(
                                "Первый шаг логин → пароль отклонён: "
                                + ", ".join(rejected)
                            )
                            route.abort()
                            return
                        state.identifier_submitted = True
                        state.identifier_advancing = False
                        route.continue_()
                        return
                    if _origin(request.url) != _origin(url) and has_credentials:
                        block("scope", request.url, request.method, request.resource_type)
                        route.abort()
                        return
                    if state.capturing or state.captured:
                        route.abort()
                        return
                    # Let ordinary browser initialization use its background
                    # APIs, including page-provided challenge resources. Once
                    # armed, unrelated writes are aborted without turning an
                    # analytics/consent request into a fatal login failure.
                    if not state.armed:
                        if (not state.filling and request.method == "POST"
                                and not request.is_navigation_request()
                                and not has_credentials
                                and not _AUTH_PATH.search(parts.path)):
                            route.continue_()
                        else:
                            route.abort()
                        return
                    if _origin(request.url) != _origin(url):
                        route.abort()
                        return
                    if request.method != "POST" or state.attempted:
                        route.abort()
                        return
                    if request.url != state.submission_action and credential.password not in body:
                        # Analytics and unrelated background writes must not use
                        # up the form's only authentication request.
                        route.abort()
                        return
                    rendered_headers = None
                    rendered_body = None
                    if profile is not None and "raw" in profile["request"]:
                        try:
                            captured_headers = dict(request.all_headers())
                            content_type = captured_headers.get("content-type", "").split(";", 1)[0].strip().lower()
                            if content_type != "application/x-www-form-urlencoded" or request.url != state.submission_action:
                                raise ValueError("template transport mismatch")
                            pairs = parse_qsl(raw_body, keep_blank_values=True, strict_parsing=True,
                                              encoding="utf-8", errors="strict", max_num_fields=10000)
                            for name, value in ((state.username_name, credential.username), (state.password_name, credential.password)):
                                if [item for key, item in pairs if key == name] != [value]:
                                    raise ValueError("template credential mismatch")
                            for name in config.required_csrf_fields:
                                tokens = [item for key, item in pairs if key == name]
                                if len(tokens) != 1 or not tokens[0]:
                                    raise ValueError("template CSRF missing")
                            template_headers, rendered_body = render_raw_request(
                                profile, action=request.url, page_url=page.url, fields=pairs,
                                username_field=state.username_name, password_field=state.password_name,
                                login=credential.username, password=credential.password,
                            )
                            rendered_headers = {**captured_headers, **{k.lower(): v for k, v in template_headers.items()}}
                            # Chromium owns these headers and the live cookie jar.
                            rendered_headers = {k: v for k, v in rendered_headers.items() if k not in {"host", "cookie", "content-length"}}
                        except (ValueError, UnicodeError):
                            block("template_request", request.url, request.method, request.resource_type)
                            state.armed = False
                            route.abort()
                            return
                    if on_capture is not None:
                        state.capturing = True
                        try:
                            snapshot = BrowserRequestSnapshot(
                                method=request.method,
                                url=request.url,
                                headers=rendered_headers if rendered_headers is not None else dict(request.all_headers()),
                                body=rendered_body.decode("utf-8") if rendered_body is not None else request.post_data or "",
                                cookies=tuple(dict(cookie) for cookie in context.cookies()),
                                # Querying the DOM during a paused native form
                                # navigation deadlocks Chromium's frame. Keep
                                # the pre-submit DOM and fetch cookies/headers
                                # at interception time, when they are current.
                                page_html=capture_page_html,
                                page_url=page.url,
                                username_field=state.username_name,
                                password_field=state.password_name,
                            )
                            on_capture(snapshot)
                            state.captured = True
                        except Exception:
                            # Callback validation/driver exceptions must not
                            # escape a Playwright event listener or expose raw
                            # request, HTML, cookies or exception messages.
                            state.blocked_reason = "capture_error"
                        finally:
                            state.capturing = False
                            state.armed = False
                            route.abort()
                        return
                    state.attempted = 1
                    state.request = request
                    if before_submit is not None:
                        try:
                            before_submit(lambda seconds: page.wait_for_timeout(seconds * 1000))
                        except BrowserCheckCancelled:
                            state.blocked_reason = "interrupted"
                    if state.blocked_reason:
                        # The rate wait pumps browser events.  A prohibited
                        # navigation or OTP action may have arrived meanwhile.
                        state.attempted = 0
                        state.armed = False
                        route.abort()
                        return
                    if rendered_body is not None:
                        route.continue_(headers=rendered_headers, post_data=rendered_body)
                    else:
                        route.continue_()

                def response_received(response: Any) -> None:
                    request = response.request
                    if request.is_navigation_request() and request.frame == page.main_frame:
                        state.document_status = response.status
                        state.challenge = response.headers.get("cf-mitigated", "").casefold() == "challenge"
                    if state.request is request or (state.request is not None and request == state.request):
                        state.response_status = response.status
                        if response.headers.get("cf-mitigated", "").casefold() == "challenge":
                            state.challenge = True

                def request_finished(request: Any) -> None:
                    if state.request is request or (state.request is not None and request == state.request):
                        state.response_finished = True

                def request_failed(request: Any) -> None:
                    if not state.blocked_reason and (state.request is request or (state.request is not None and request == state.request)):
                        state.request_failed = True
                    failure = request.failure or ""
                    if "ERR_CERT" in failure:
                        state.resource_error = "resource_tls"
                    elif "ERR_PROXY" in failure or "ERR_TUNNEL" in failure:
                        state.resource_error = "proxy"

                context.route("**/*", route_request)
                page.on("response", response_received)
                page.on("requestfinished", request_finished)
                page.on("requestfailed", request_failed)

                # Playwright routing sees only the first URL of a redirect
                # chain.  Intercept response headers in Chromium itself before
                # it can replay a credential POST on a 307/308 redirect.
                cdp = context.new_cdp_session(page)
                main_frame_id = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]

                def response_paused(event: dict[str, Any]) -> None:
                    request = event["request"]
                    status = event.get("responseStatusCode", 0)
                    headers = {header["name"].casefold(): header["value"] for header in event.get("responseHeaders", [])}
                    location = headers.get("location")
                    reason = ""
                    if 300 <= status < 400 and location:
                        destination = urljoin(request["url"], location)
                        credential_response = (
                            state.request is not None
                            and request["url"] == state.request.url
                            and request["method"] == state.request.method
                        )
                        if request["method"] == "POST" and status in {307, 308} and state.attempted and credential_response:
                            reason = "credential_redirect"
                        elif has_secret_query(destination):
                            reason = "credential_url"
                        elif event.get("frameId") == main_frame_id and event.get("resourceType") == "Document" and not in_scope(destination):
                            reason = "scope"
                    if reason:
                        block(reason, destination, request["method"], event.get("resourceType", "").lower())
                        cdp.send("Fetch.failRequest", {"requestId": event["requestId"], "errorReason": "BlockedByClient"})
                    else:
                        cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})

                cdp.on("Fetch.requestPaused", response_paused)
                cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})
                for selector in (config.success_selector, config.failure_selector):
                    if selector is not None:
                        try:
                            page.locator(selector).count()
                        except PlaywrightError as exc:
                            raise ValueError("Некорректный CSS-селектор результата входа") from exc
                progress("Открываю страницу; ожидаю форму входа")
                page.goto(url, wait_until="domcontentloaded", timeout=config.timeout_seconds * 1000)
                deadline = time.monotonic() + config.timeout_seconds
                form: _LoginForm | None = None
                identifier_started = False
                challenge_announced = False
                consent_announced = False
                consent_rejected: set[str] = set()
                site_error_dismissed = False

                def cookie_consent_ready(until: float) -> bool:
                    nonlocal consent_announced
                    while time.monotonic() < until:
                        disposition = _cookie_consent(page, consent_rejected)
                        if disposition == "none":
                            return True
                        if disposition == "blocked":
                            if config.headless:
                                return False
                            if not consent_announced:
                                progress("Cookie-диалог закрывает форму; отклоните необязательные cookies в открытом окне")
                                consent_announced = True
                        page.wait_for_timeout(150)
                    return False

                while time.monotonic() < deadline:
                    if state.blocked_reason:
                        return _blocked_result(state.blocked_reason, result)
                    if profile is not None:
                        decision = profile_outcome(profile, browser_signals(page), page.url, status=state.document_status or 200, submitted=False)
                        if decision is not None:
                            return result(decision.status, decision.detail, str(decision.evidence.get("reason", "")))
                    if _challenge_page(page, state):
                        if config.headless or config.stop_on_challenge:
                            return result(OutcomeStatus.UNSUPPORTED, "Получена CAPTCHA/защитная страница (challenge); форма входа недоступна", "challenge")
                        if not challenge_announced:
                            progress("Защитная страница: ожидаю появления формы в открытом окне")
                            challenge_announced = True
                        page.wait_for_timeout(200)
                        continue
                    if not cookie_consent_ready(deadline):
                        return result(OutcomeStatus.UNSUPPORTED, "Cookie-диалог закрывает форму; выберите только необходимые cookies и повторите проверку", "cookie_consent")
                    error_dialog = _site_error_dialog(page)
                    if error_dialog is not None:
                        if site_error_dismissed or not _dismiss_site_error_dialog(error_dialog):
                            return result(
                                OutcomeStatus.UNSUPPORTED,
                                "Сайт показал окно с ошибкой; форма входа недоступна, пароль не отправлялся",
                                "site_error",
                            )
                        site_error_dismissed = True
                        progress("Сайт показал окно с ошибкой; закрыл его один раз и повторно проверяю форму")
                        page.wait_for_timeout(150)
                        continue
                    if _otp_page(page):
                        return result(OutcomeStatus.MFA_REQUIRED, "Требуется OTP/код подтверждения; отправка остановлена", "otp")
                    if _email_otp_form(page):
                        return result(OutcomeStatus.UNSUPPORTED, "Обнаружен шаг email/OTP без пароля; письмо или код не отправлялись", "otp")
                    if state.document_status is not None and state.document_status >= 400:
                        status = OutcomeStatus.RATE_LIMITED if state.document_status == 429 else OutcomeStatus.UNSUPPORTED
                        if state.document_status == 403:
                            return result(
                                status,
                                "HTTP 403: доступ к странице входа запрещён; пароль не отправлялся",
                                "http_403",
                            )
                        return result(status, f"Страница входа вернула HTTP {state.document_status}", "http_error")
                    form = _find_login_form(
                        page,
                        allow_missing_identifier=identifier_started,
                        fallback_identifier_name=state.username_name,
                        username_field_hint=config.username_field_hint,
                        password_field_hint=config.password_field_hint,
                    )
                    if form is not None:
                        state.identifier_advancing = False
                        break
                    if not identifier_started:
                        identifier_step = _find_identifier_step(page)
                        if identifier_step is not None:
                            if _origin(identifier_step.action) != _origin(url):
                                block("scope", identifier_step.action, "POST", "document")
                                return result(OutcomeStatus.UNSUPPORTED, "Первый шаг отправляет логин на другой origin", "scope")
                            identifier_started = True
                            state.identifier_action = identifier_step.action
                            state.username_name = identifier_step.field_name
                            progress("Найден безопасный шаг логин → пароль; отправляю только логин")
                            identifier_step.identifier.fill(credential.username)
                            state.identifier_advancing = True
                            try:
                                identifier_step.submit.click(
                                    timeout=min(config.timeout_seconds, 10) * 1000,
                                    no_wait_after=True,
                                )
                            except PlaywrightError:
                                if state.blocked_reason:
                                    return _blocked_result(state.blocked_reason, result)
                                return result(
                                    OutcomeStatus.UNSUPPORTED,
                                    "Не удалось безопасно выполнить первый шаг логин → пароль",
                                    "identifier_step",
                                )
                            continue
                    page.wait_for_timeout(150)
                if form is None:
                    if _challenge_page(page, state):
                        return result(OutcomeStatus.UNSUPPORTED, "CAPTCHA/защитная проверка не завершена; пароль не отправлялся", "challenge")
                    if state.resource_error == "resource_tls":
                        return result(OutcomeStatus.NETWORK_ERROR, "Chromium отклонил сертификат ресурса страницы; форма не загрузилась полностью", "resource_tls")
                    if state.resource_error == "proxy":
                        return result(OutcomeStatus.NETWORK_ERROR, "Браузер не смог загрузить ресурсы страницы через прокси", "proxy")
                    return result(OutcomeStatus.UNSUPPORTED, "Не найдена видимая форма с логином и паролем; первый шаг без пароля не отправлялся", "no_password_form")
                fields = form.fields
                if profile is not None:
                    if (form.password.get_attribute("name") != config.password_field_hint
                            or form.identifier is None
                            or form.identifier.get_attribute("name") != config.username_field_hint):
                        return result(OutcomeStatus.UNSUPPORTED, "Форма больше не соответствует полям шаблона", "template_fields")
                    try:
                        prepare_browser_form(form.password, profile, config.required_csrf_fields)
                    except ValueError as exc:
                        return result(OutcomeStatus.UNSUPPORTED, str(exc), "template_fields")
                target = form.password.evaluate("e => e.form ? e.form.target : ''")
                if form.submit is not None:
                    target = form.submit.get_attribute("formtarget") or target
                if target and target.casefold() not in {"_self", "_parent", "_top"}:
                    return result(OutcomeStatus.UNSUPPORTED, "Вход через отдельное окно пока не поддерживается", "popup")
                if form.action and _origin(form.action) != _origin(url):
                    block("scope", form.action, "POST", "document")
                    return result(OutcomeStatus.UNSUPPORTED, "Форма отправляет данные на другой origin; проверка остановлена", "scope")
                initial_marker = _positive_marker(page, config.success_selector)
                if initial_marker is not None:
                    if initial_marker.explicit:
                        return result(
                            OutcomeStatus.AMBIGUOUS,
                            f"До отправки уже совпал {initial_marker.description}; результат нельзя проверить",
                            "preexisting_success",
                        )
                    progress(
                        f"До отправки видна {initial_marker.description}, но форма входа доступна; "
                        "не считаю это подтверждением сессии"
                    )
                state.submission_action = form.action or page.url
                state.password_name = form.password.get_attribute("name") or ""
                if form.identifier is not None:
                    state.username_name = form.identifier.get_attribute("name") or state.username_name
                if not cookie_consent_ready(deadline):
                    return result(OutcomeStatus.UNSUPPORTED, "Cookie-диалог закрывает форму; отправка остановлена", "cookie_consent")
                if _site_error_dialog(page) is not None:
                    return result(OutcomeStatus.UNSUPPORTED, "Сайт показал окно с ошибкой; пароль не отправлялся", "site_error")
                state.filling = True
                progress("Найдены поля: " + ", ".join(fields))
                if form.identifier is not None:
                    form.identifier.fill(credential.username)
                form.password.fill(credential.password)
                if state.blocked_reason:
                    return _blocked_result(state.blocked_reason, result)
                if not cookie_consent_ready(deadline):
                    return result(OutcomeStatus.UNSUPPORTED, "Cookie-диалог закрывает форму; отправка остановлена", "cookie_consent")
                if _site_error_dialog(page) is not None:
                    return result(OutcomeStatus.UNSUPPORTED, "Сайт показал окно с ошибкой; пароль не отправлялся", "site_error")
                if profile is not None:
                    decision = profile_outcome(profile, browser_signals(page), page.url, status=state.document_status or 200, submitted=False)
                    if decision is not None:
                        return result(decision.status, decision.detail, str(decision.evidence.get("reason", "")))
                if on_capture is not None:
                    capture_page_html = page.content()
                state.armed = True
                progress("Получаю запрос формы без отправки" if on_capture is not None else "Отправляю форму один раз")
                try:
                    if form.submit is not None:
                        form.submit.click(timeout=min(config.timeout_seconds, 10) * 1000, no_wait_after=True)
                    else:
                        form.password.press("Enter", timeout=min(config.timeout_seconds, 10) * 1000)
                except PlaywrightError:
                    if state.blocked_reason:
                        return _blocked_result(state.blocked_reason, result)
                    if state.captured:
                        return result(OutcomeStatus.SKIPPED, "Запрос авторизации получен без отправки", "request_captured")
                    if not state.attempted:
                        if _site_error_dialog(page) is not None:
                            return result(OutcomeStatus.UNSUPPORTED, "Окно с ошибкой сайта помешало нажать кнопку входа; пароль не отправлялся", "site_error")
                        return result(OutcomeStatus.UNSUPPORTED, "Браузер не смог отправить выбранную форму", "submission")
                deadline = time.monotonic() + config.timeout_seconds
                while time.monotonic() < deadline:
                    if state.blocked_reason:
                        return _blocked_result(state.blocked_reason, result)
                    if state.captured:
                        return result(OutcomeStatus.SKIPPED, "Запрос авторизации получен без отправки", "request_captured")
                    if not in_scope(page.url):
                        return result(OutcomeStatus.UNSUPPORTED, "Итоговая страница вышла за разрешённую область", "scope")
                    if _challenge_page(page, state):
                        return result(OutcomeStatus.UNSUPPORTED, "Сайт запросил CAPTCHA/защитную проверку после отправки формы", "challenge")
                    if _otp_page(page):
                        return result(OutcomeStatus.MFA_REQUIRED, "После пароля требуется OTP/код; дальнейшие шаги не выполнялись", "otp")
                    if state.request_failed:
                        return result(OutcomeStatus.NETWORK_ERROR, "Не удалось получить ответ на запрос авторизации", "request_failed")
                    if state.response_status == 429:
                        return result(OutcomeStatus.RATE_LIMITED, "Сайт ограничил число запросов (HTTP 429)", "rate_limit")
                    if state.response_finished:
                        if profile is not None:
                            decision = profile_outcome(profile, browser_signals(page), page.url,
                                                       status=state.document_status or state.response_status or 200,
                                                       post_status=state.response_status, submitted=True)
                            if decision is not None:
                                return result(decision.status, decision.detail, str(decision.evidence.get("reason", "")))
                            if state.response_status == 403:
                                return result(OutcomeStatus.UNSUPPORTED, "HTTP 403: доступ запрещён", "http_403")
                            page.wait_for_timeout(150)
                            continue
                        if _visible(page, config.failure_selector) or _failure_text(page):
                            return result(OutcomeStatus.FAILURE, "Страница сообщила об ошибке входа", "login_error")
                        if state.response_status == 401:
                            return result(OutcomeStatus.FAILURE, "Сайт отклонил авторизацию (HTTP 401)", "login_error")
                        if state.response_status == 403:
                            return result(
                                OutcomeStatus.UNSUPPORTED,
                                "HTTP 403: доступ запрещён; нельзя однозначно отличить блокировку от отклонённой авторизации",
                                "http_403",
                            )
                        success_marker = _positive_marker(page, config.success_selector)
                        if success_marker is not None:
                            if config.success_selector or not _visible_passwords(page):
                                progress(f"Признак успешного входа: {success_marker.description}")
                                return result(OutcomeStatus.SUCCESS, "В браузере появился подтверждённый признак входа", "authenticated_marker")
                        if _visible_passwords(page) and _same_page(page.url, url):
                            return result(
                                OutcomeStatus.FAILURE,
                                "После ответа осталась та же парольная форма входа",
                                "password_form_remains",
                            )
                    page.wait_for_timeout(150)
                if not state.attempted:
                    return result(OutcomeStatus.UNSUPPORTED, "Форма не отправила разрешённый POST-запрос; пароль в URL не передаётся", "no_submission")
                if profile is not None and state.response_finished:
                    unmatched = profile_unconfirmed(
                        profile, status=state.document_status or state.response_status or 200,
                        post_status=state.response_status,
                    )
                    return result(unmatched.status, unmatched.detail, str(unmatched.evidence["reason"]))
                return result(OutcomeStatus.AMBIGUOUS, "Запрос отправлен, но однозначный признак успеха или ошибки не появился", "unconfirmed")
            finally:
                browser.close()
    except PlaywrightError as exc:
        if state.blocked_reason:
            return _blocked_result(state.blocked_reason, result)
        challenge = state.challenge
        if page is not None and not page.is_closed():
            try:
                challenge = _challenge_page(page, state)
            except PlaywrightError:
                pass
        if challenge:
            return result(
                OutcomeStatus.UNSUPPORTED,
                "Обнаружена CAPTCHA/защитная страница; проверки этого хоста остановлены",
                "challenge",
            )
        if state.document_status == 403:
            return result(
                OutcomeStatus.UNSUPPORTED,
                "HTTP 403: доступ к странице входа запрещён; пароль не отправлялся",
                "http_403",
            )
        message = str(exc)
        if state.resource_error == "resource_tls" or "ERR_CERT" in message or "certificate" in message.casefold():
            detail = "Chromium отклонил HTTPS-сертификат; проверьте CA для браузера и прокси"
        elif state.resource_error == "proxy" or "ERR_PROXY" in message or "ERR_TUNNEL" in message:
            detail = "Браузер не смог загрузить страницу через выбранный прокси"
        elif "X server" in message or "DISPLAY" in message:
            detail = "Для видимого браузера нужна графическая сессия; используйте --headless для запуска без окна"
        elif "Executable doesn't exist" in message:
            detail = "Chromium не установлен: выполните python -m playwright install chromium"
        else:
            detail = "Браузер не смог загрузить страницу или дождаться её состояния"
        return result(OutcomeStatus.NETWORK_ERROR, detail, "browser_error")
    except KeyboardInterrupt:
        return result(OutcomeStatus.SKIPPED, "Браузерная проверка прервана пользователем", "interrupted")


def _blocked_result(reason: str, result: Callable[..., BrowserCheckResult]) -> BrowserCheckResult:
    detail = {
        "otp": "Обнаружен запрос отправки OTP/письма; этот шаг остановлен",
        "scope": "Переход или отправка данных за пределы разрешённого origin остановлены",
        "credential_url": "Форма пытается отправить пароль в URL; запрос остановлен",
        "identifier_url": "Первый шаг пытается отправить логин в URL; запрос остановлен",
        "credential_redirect": "Сайт потребовал повторить POST через редирект; повторная отправка остановлена",
        "popup": "Вход через отдельное окно пока не поддерживается; отправка остановлена",
        "interrupted": "Браузерная проверка прервана пользователем",
        "capture_error": "Не удалось безопасно подготовить запрос авторизации; пароль не отправлялся",
        "template_request": "Запрос браузера не соответствует HTTP-шаблону формы; пароль не отправлялся",
    }.get(reason, "Браузерная проверка остановлена")
    return result(OutcomeStatus.SKIPPED if reason == "interrupted" else OutcomeStatus.UNSUPPORTED, detail, reason)


def _cookie_consent(page: Any, rejected: set[str]) -> str:
    """Reject clearly identified optional cookies, never choose Accept all."""

    for selector in ("#onetrust-reject-all-handler", "#CybotCookiebotDialogBodyButtonDecline"):
        candidate = page.locator(selector)
        if selector not in rejected and candidate.count() and candidate.first.is_visible() and candidate.first.is_enabled():
            rejected.add(selector)
            try:
                candidate.first.click(timeout=1000, no_wait_after=True)
            except Exception:
                return "blocked"
            return "dismissed"
    dialogs = page.locator(
        "[role='dialog'], [aria-modal='true'], #onetrust-banner-sdk, #CybotCookiebotDialog, "
        "[id*='cookie-consent' i], [class*='cookie-consent' i]"
    )
    blocking = False
    for index in range(min(dialogs.count(), 20)):
        dialog = dialogs.nth(index)
        if not dialog.is_visible() or not _COOKIE_TEXT.search(dialog.inner_text(timeout=1000)[:8000]):
            continue
        reject = dialog.get_by_role("button", name=_COOKIE_REJECT_LABEL)
        for button_index in range(min(reject.count(), 10)):
            button = reject.nth(button_index)
            label = "cookie:" + button.inner_text(timeout=1000).strip().casefold()
            if label not in rejected and button.is_visible() and button.is_enabled():
                rejected.add(label)
                try:
                    button.click(timeout=1000, no_wait_after=True)
                except Exception:
                    return "blocked"
                return "dismissed"
        blocking = blocking or bool(dialog.evaluate("""element => {
            const rect = element.getBoundingClientRect();
            const style = getComputedStyle(element);
            return element.getAttribute('aria-modal') === 'true'
                || element.getAttribute('role') === 'dialog'
                || ((style.position === 'fixed' || style.position === 'sticky')
                    && rect.width * rect.height > innerWidth * innerHeight * 0.15);
        }"""))
    return "blocked" if blocking else "none"


def _site_error_dialog(page: Any) -> Any | None:
    """Find a visible application error overlay, not a browser/JS alert."""

    dialogs = page.locator(
        "[role='alertdialog'], [role='dialog'], [aria-modal='true'], "
        "mat-dialog-container, [class*='modal' i]"
    )
    for index in range(min(dialogs.count(), 20)):
        dialog = dialogs.nth(index)
        try:
            if dialog.is_visible() and _SITE_ERROR_TEXT.search(dialog.inner_text(timeout=1000)[:4000]):
                return dialog
        except Exception:
            continue
    return None


def _dismiss_site_error_dialog(dialog: Any) -> bool:
    """Close one informational error overlay without confirming other actions."""

    try:
        buttons = dialog.get_by_role("button", name=_SITE_ERROR_CLOSE)
        candidates = [
            buttons.nth(index)
            for index in range(min(buttons.count(), 10))
            if buttons.nth(index).is_visible() and buttons.nth(index).is_enabled()
        ]
        if len(candidates) != 1:
            return False
        candidates[0].click(timeout=1000, no_wait_after=True)
    except Exception:
        return False
    return True


def _find_login_form(
    page: Any,
    *,
    allow_missing_identifier: bool = False,
    fallback_identifier_name: str = "",
    username_field_hint: str = "",
    password_field_hint: str = "",
) -> _LoginForm | None:
    passwords = page.locator("input[type='password']")
    ordered_passwords = [passwords.nth(index) for index in range(min(passwords.count(), 20))]
    if password_field_hint:
        ordered_passwords.sort(key=lambda field: field.get_attribute("name") != password_field_hint)
    for password in ordered_passwords:
        if not password.is_visible() or not password.is_enabled():
            continue
        ancestor = password.locator("xpath=ancestor::form[1]")
        container = ancestor if ancestor.count() else page.locator("body")
        if len(_visible_passwords(container)) != 1:
            continue
        action = password.evaluate("e => e.form ? e.form.action : ''")
        if action and _NON_LOGIN_PATH.search(urlsplit(action).path):
            continue
        form_text = container.inner_text(timeout=1000)[:4000]
        if _REGISTRATION_TEXT.search(form_text) and not re.search(r"sign\s*in|log\s*in|войти", form_text, re.I):
            continue
        if (password.get_attribute("autocomplete") or "").casefold() == "new-password" and not re.search(r"sign\s*in|log\s*in|войти", form_text, re.I):
            continue
        candidates: list[tuple[int, Any]] = []
        inputs = container.locator("input")
        for field_index in range(min(inputs.count(), 100)):
            candidate = inputs.nth(field_index)
            kind = (candidate.get_attribute("type") or "text").casefold()
            if kind not in {"text", "email", "tel"} or not candidate.is_visible() or not candidate.is_enabled():
                continue
            name = candidate.get_attribute("name") or candidate.get_attribute("id") or ""
            autocomplete = (candidate.get_attribute("autocomplete") or "").casefold()
            score = 4 * (autocomplete in {"username", "email"}) + 3 * bool(_IDENTIFIER.search(name)) + (kind == "email")
            if username_field_hint and password_field_hint and password.get_attribute("name") == password_field_hint and candidate.get_attribute("name") == username_field_hint:
                score += 10
            candidates.append((score, candidate))
        identifier = None
        if candidates:
            candidates.sort(key=lambda item: item[0], reverse=True)
            if candidates[0][0] == 0 and len(candidates) != 1:
                continue
            identifier = candidates[0][1]
        elif not allow_missing_identifier:
            continue
        submit = None
        buttons = container.locator("button[type='submit'], button:not([type]), input[type='submit']")
        for button_index in range(min(buttons.count(), 20)):
            button = buttons.nth(button_index)
            if button.is_visible() and button.is_enabled():
                submit = button
                break
        if submit is None:
            for role in ("button",):
                buttons = container.get_by_role(role, name=_LOGIN_LABEL)
                if buttons.count() == 1 and buttons.first.is_visible() and buttons.first.is_enabled():
                    submit = buttons.first
                    break
        identifier_name = (
            identifier.get_attribute("name") or identifier.get_attribute("id") or "<без name>"
            if identifier is not None
            else fallback_identifier_name or "<логин из первого шага>"
        )
        fields = (
            identifier_name[:200],
            (password.get_attribute("name") or password.get_attribute("id") or "<без name>")[:200],
        )
        return _LoginForm(identifier, password, submit, action, fields)
    return None


def _find_identifier_step(page: Any) -> _IdentifierStep | None:
    if _visible_passwords(page):
        return None
    forms = page.locator("form")
    for index in range(min(forms.count(), 20)):
        form = forms.nth(index)
        method = (form.get_attribute("method") or "get").casefold()
        action = form.evaluate("e => e.action || location.href")
        path = urlsplit(action).path
        text = form.inner_text(timeout=1000)[:4000]
        if method != "post" or _OTP_PATH.search(path) or _NON_LOGIN_PATH.search(path) or _OTP_INTENT.search(text):
            continue
        candidates: list[tuple[int, Any, str]] = []
        inputs = form.locator("input")
        for field_index in range(min(inputs.count(), 50)):
            candidate = inputs.nth(field_index)
            kind = (candidate.get_attribute("type") or "text").casefold()
            if kind not in {"text", "email", "tel"} or not candidate.is_visible() or not candidate.is_enabled():
                continue
            name = candidate.get_attribute("name") or candidate.get_attribute("id") or ""
            autocomplete = (candidate.get_attribute("autocomplete") or "").casefold()
            score = 4 * (autocomplete in {"username", "email"}) + 3 * bool(_IDENTIFIER.search(name)) + (kind == "email")
            if score:
                candidates.append((score, candidate, name))
        if len(candidates) != 1:
            continue
        buttons = form.locator("button[type='submit'], button:not([type]), input[type='submit']")
        submit = None
        for button_index in range(min(buttons.count(), 20)):
            button = buttons.nth(button_index)
            if not button.is_visible() or not button.is_enabled():
                continue
            label = (button.inner_text(timeout=1000) or button.get_attribute("value") or "").strip()
            if _OTP_INTENT.search(label):
                submit = None
                break
            if _CONTINUE_LABEL.fullmatch(label) or _AUTH_PATH.search(path):
                submit = button
                break
        if submit is not None:
            _, identifier, field_name = candidates[0]
            return _IdentifierStep(identifier, submit, action, field_name)
    return None


def _visible_passwords(container: Any) -> list[Any]:
    passwords = container.locator("input[type='password']")
    return [passwords.nth(i) for i in range(min(passwords.count(), 20)) if passwords.nth(i).is_visible()]


def _visible(page: Any, selector: str | None) -> bool:
    if selector is None:
        return False
    matches = page.locator(selector)
    return any(matches.nth(i).is_visible() for i in range(min(matches.count(), 20)))


def _positive_marker(page: Any, selector: str | None) -> _PositiveMarker | None:
    if selector is not None:
        return _PositiveMarker("заданный --success-selector", explicit=True) if _visible(page, selector) else None
    for role in ("link", "button"):
        markers = page.get_by_role(role, name=_LOGOUT_LABEL)
        if any(markers.nth(i).is_visible() for i in range(min(markers.count(), 20))):
            return _PositiveMarker("ссылка «Выход/Logout»" if role == "link" else "кнопка «Выход/Logout»")
    if _visible(page, "a[href*='/logout'], a[href*='/signout'], a[href*='/sign-out']"):
        return _PositiveMarker("ссылка на выход из аккаунта")
    return None


def _otp_page(page: Any) -> bool:
    if _visible(page, "input[autocomplete='one-time-code'], input[name='otp' i], input[name='totp' i], input[name='verification_code' i], input[name='email_code' i]"):
        return True
    text = _body_text(page)
    return not _visible_passwords(page) and bool(_MFA_TEXT.search(text)) and bool(re.search(r"enter|provide|введите", text, re.I))


def _email_otp_form(page: Any) -> bool:
    if _visible_passwords(page):
        return False
    forms = page.locator("form")
    return any(
        _OTP_PATH.search(forms.nth(i).get_attribute("action") or "")
        or _OTP_INTENT.search(forms.nth(i).inner_text(timeout=1000)[:4000])
        for i in range(min(forms.count(), 30))
    )


def _challenge_page(page: Any, state: _State) -> bool:
    return (
        state.challenge
        or bool(_CHALLENGE_TITLE.search(page.title()))
        or _visible(page, _CAPTCHA_SELECTOR)
    )


def _failure_text(page: Any) -> bool:
    return bool(_FAILURE.search(_body_text(page)))


def _body_text(page: Any) -> str:
    body = page.locator("body")
    return body.inner_text(timeout=1000)[:32000] if body.count() else ""


def _body_contains_credentials(body: str, credential: Credential) -> bool:
    """Avoid treating a short username as an arbitrary analytics substring."""

    decoded = unquote_plus(body)
    if credential.password in body or credential.password in decoded:
        return True
    if body == credential.username or decoded == credential.username:
        return True
    if any(value == credential.username for _, value in parse_qsl(body, keep_blank_values=True)):
        return True
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        payload = None

    def includes_identifier(value: Any) -> bool:
        if isinstance(value, str):
            return value == credential.username or value == credential.password
        if isinstance(value, dict):
            return any(includes_identifier(item) for item in value.values())
        if isinstance(value, list):
            return any(includes_identifier(item) for item in value)
        return False

    if includes_identifier(payload):
        return True
    # Multipart values are separated by CR/LF, rather than URL encoded.
    return any(line == credential.username for line in body.splitlines())


def _body_contains_identifier(body: str, username: str) -> bool:
    decoded = unquote_plus(body)
    if body == username or decoded == username:
        return True
    if any(value == username for _, value in parse_qsl(body, keep_blank_values=True)):
        return True
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        payload = None

    def includes(value: Any) -> bool:
        if isinstance(value, str):
            return value == username
        if isinstance(value, dict):
            return any(includes(item) for item in value.values())
        if isinstance(value, list):
            return any(includes(item) for item in value)
        return False

    return includes(payload) or any(line == username for line in body.splitlines())


def _body_contains_password(body: str, password: str) -> bool:
    decoded = unquote_plus(body)
    if password in body or password in decoded:
        return True
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False

    def includes(value: Any) -> bool:
        if isinstance(value, str):
            return value == password
        if isinstance(value, dict):
            return any(includes(item) for item in value.values())
        if isinstance(value, list):
            return any(includes(item) for item in value)
        return False

    return includes(payload)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return (parts.scheme.casefold(), (parts.hostname or "").casefold(), parts.port or (443 if parts.scheme.casefold() == "https" else 80))


def _same_page(first: str, second: str) -> bool:
    try:
        left, right = urlsplit(first), urlsplit(second)
        return (
            _origin(first) == _origin(second)
            and (left.path or "/") == (right.path or "/")
        )
    except ValueError:
        return False


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


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
        return urlunsplit((parts.scheme.casefold(), host, "", "", ""))
    except ValueError:
        return ""


def _proxy_url(proxy: str | None) -> str | None:
    if not proxy:
        return None
    parts = urlsplit(proxy)
    if (parts.scheme.casefold() != "http" or not parts.hostname or parts.username or parts.password
            or parts.path not in {"", "/"} or parts.query or parts.fragment):
        raise ValueError("--proxy должен иметь вид http://HOST:PORT")
    try:
        port = parts.port or 80
    except ValueError as exc:
        raise ValueError("Некорректный порт --proxy") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Некорректный порт --proxy")
    return proxy
