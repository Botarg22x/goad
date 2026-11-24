from __future__ import annotations

import re

from .models import WebObservation


_CHALLENGE_TITLE = re.compile(
    r"(?:just a moment|attention required|verify (?:that )?you are human|"
    r"checking your browser|captcha|security check|"
    r"проверка (?:браузера|безопасности))",
    re.IGNORECASE,
)
_CHALLENGE_TEXT = re.compile(
    r"(?:cf-chl-|challenge-platform|captcha[_ -]?required|"
    r"verify (?:that )?you are human|checking (?:if|that) (?:the )?site connection|"
    r"enable javascript and cookies to continue|cloudflare ray id)",
    re.IGNORECASE,
)


def is_protection_challenge(observation: WebObservation) -> bool:
    """Return True only for strong CAPTCHA/anti-bot challenge indicators."""

    headers = {str(key).casefold(): str(value) for key, value in observation.headers.items()}
    if headers.get("cf-mitigated", "").casefold() == "challenge":
        return True
    if _CHALLENGE_TITLE.search(observation.title[:500]):
        return True
    return bool(_CHALLENGE_TEXT.search(observation.text[:20_000]))


def describe_http_access_problem(observation: WebObservation) -> str | None:
    """Describe responses that prevent a reliable login-page analysis."""

    status = observation.status_code
    if is_protection_challenge(observation):
        status_text = f"HTTP {status}: " if status is not None else ""
        return (
            f"{status_text}получена CAPTCHA/защитная страница (challenge); "
            "форма входа недоступна для анализа, данные авторизации не отправлялись"
        )
    headers = {str(key).casefold(): str(value) for key, value in observation.headers.items()}
    if status == 403 and not headers.get("www-authenticate"):
        return (
            "HTTP 403: сервер запретил доступ к странице; "
            "форма входа недоступна для анализа, данные авторизации не отправлялись"
        )
    if status is not None and 500 <= status <= 599:
        return (
            f"HTTP {status}: сервер вернул ошибку; "
            "анализ точки авторизации пропущен"
        )
    return None
