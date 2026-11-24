"""Render only when needed, then send a declared request using fresh cookies.

This path deliberately does not locate/click HTML form controls. It uses the
same bounded HTTP adapter and result rules as the non-browser template path.
"""
from __future__ import annotations

from http.cookies import SimpleCookie
import time

from .adapters.http import HttpResponse, PasswordFormAdapter, ProxyHttpClient, _common_outcome
from .models import Outcome, OutcomeStatus
from .template_profile import html_signals, page_request_fields, page_template_job, profile_outcome


def check_page_template(context, page, url, credential, profile, *, config, target_scope,
                        on_progress=None, before_submit=None):
    from .browser import BrowserCheckResult, BrowserCheckCancelled, _origin, _OTP_PATH

    def result(outcome, attempted=0):
        return BrowserCheckResult(outcome, attempted, url,
                                  (config.username_field_hint, config.password_field_hint))

    def route_request(route):
        request = route.request
        if (request.method not in {"GET", "HEAD"} or _OTP_PATH.search(request.url)
                or (request.is_navigation_request() and _origin(request.url) != _origin(url))):
            route.abort()
        else:
            route.continue_()

    context.route("**/*", route_request)
    if on_progress:
        on_progress("Отрисовываю страницу шаблона; поля и POST уже заданы в YAML")
    response = page.goto(url, wait_until="domcontentloaded", timeout=config.timeout_seconds * 1000)
    status = response.status if response else 0
    headers = dict(response.headers) if response else {}
    deadline = time.monotonic() + config.timeout_seconds
    while True:
        if page.url != url:
            return result(Outcome(OutcomeStatus.UNSUPPORTED, "Страница сменила URL; обновите отчёт", evidence={"reason": "scope"}))
        body = page.content()
        decision = _common_outcome(HttpResponse(status, headers, body))
        decision = decision or profile_outcome(profile, html_signals(body), url, status=status, submitted=False)
        if decision is not None:
            return result(decision)
        try:
            page_request_fields(profile, body, url, status, set(config.required_csrf_fields))
            break
        except ValueError as exc:
            if time.monotonic() >= deadline:
                return result(Outcome(OutcomeStatus.UNSUPPORTED, str(exc), evidence={"reason": "template_page"}))
            page.wait_for_timeout(150)

    # Browser cookies stay in memory and are scoped to the checked URL.
    cookie_headers = []
    for cookie in context.cookies([url]):
        jar = SimpleCookie()
        jar[cookie["name"]] = cookie["value"]
        item = jar[cookie["name"]]
        item["path"] = cookie.get("path", "/")
        if cookie.get("secure"):
            item["secure"] = True
        cookie_headers.append(item.OutputString())
    prepared = HttpResponse(status, headers, body, tuple(cookie_headers))
    client = ProxyHttpClient(config.proxy, timeout_seconds=min(config.timeout_seconds, 60),
                             user_agent=config.user_agent, target_scope=target_scope, ca_cert=config.ca_cert)
    attempted = False

    class PreparedClient:
        first = True

        def request(self, method, target, *, headers=None, body=None):
            nonlocal attempted
            if self.first:
                self.first = False
                if method != "GET" or target != url:
                    raise ValueError("Неверный начальный запрос шаблона")
                return prepared
            if method == "POST":
                if before_submit:
                    before_submit(lambda seconds: page.wait_for_timeout(seconds * 1000))
                attempted = True
                if on_progress:
                    on_progress("Отправляю HTTP-запрос шаблона со свежей браузерной сессией")
            return client.request(method, target, headers=headers, body=body)

    job = page_template_job(url, profile, config.required_csrf_fields)
    try:
        outcome = PasswordFormAdapter(PreparedClient(), target_scope).attempt(job, credential)
    except BrowserCheckCancelled:
        return result(Outcome(OutcomeStatus.SKIPPED, "Проверка прервана", evidence={"reason": "interrupted"}), int(attempted))
    return result(outcome, int(attempted))
