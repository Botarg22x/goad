"""Read and validate exact HTTP target URLs without resolving any hostname."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def load_target_urls(path: Path) -> tuple[str, ...]:
    """Return ordered unique targets, validating the entire UTF-8 file first.

    Error messages deliberately identify the line rather than echoing a URL:
    query strings can contain session tokens or other private values.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ValueError("Файл со ссылками не найден") from None
    except IsADirectoryError:
        raise ValueError("Вместо файла со ссылками указан каталог") from None
    except PermissionError:
        raise ValueError("Нет доступа для чтения файла со ссылками") from None
    except OSError:
        raise ValueError("Не удалось прочитать файл со ссылками") from None
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Файл со ссылками должен быть в кодировке UTF-8") from None

    targets: dict[str, None] = {}
    lines = content.split("\n")
    for line_number, line in enumerate(lines, 1):
        # Split only real LF separators: str.splitlines would turn embedded
        # Unicode/control characters into extra, apparently valid URL lines.
        if line.endswith("\r") and line_number < len(lines):
            line = line[:-1]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        value = line.strip(" ")
        try:
            normalized = _normalize_url(value)
        except ValueError as exc:
            raise ValueError(f"Некорректная ссылка в строке {line_number}: {exc}") from None
        targets.setdefault(normalized, None)
    if not targets:
        raise ValueError("Файл со ссылками пуст: укажите хотя бы один HTTP(S) URL")
    return tuple(targets)


def _normalize_url(value: str) -> str:
    if any(char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise ValueError("URL содержит пробельные или управляющие символы")
    if "\\" in value:
        raise ValueError("обратная косая черта в URL не допускается")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ValueError("некорректное имя хоста или формат URL") from None
    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("нужен полный URL с http:// или https://")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError("в URL нельзя указывать логин или пароль")
    hostname = parts.hostname
    if not hostname:
        raise ValueError("не указано имя хоста")

    bracketed = parts.netloc.startswith("[")
    if bracketed:
        suffix = parts.netloc[parts.netloc.find("]") + 1:]
        if suffix and not re.fullmatch(r":[0-9]+", suffix):
            raise ValueError("порт должен быть числом от 1 до 65535")
    elif "[" in parts.netloc or "]" in parts.netloc or parts.netloc.count(":") > 1:
        raise ValueError("IPv6-адрес нужно заключить в квадратные скобки")
    elif ":" in parts.netloc and not re.fullmatch(r"[0-9]+", parts.netloc.rsplit(":", 1)[1]):
        raise ValueError("порт должен быть числом от 1 до 65535")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("порт должен быть числом от 1 до 65535") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("порт должен быть числом от 1 до 65535")

    if "%" in hostname:
        raise ValueError("некорректное имя хоста")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if bracketed:
            raise ValueError("в квадратных скобках должен быть IPv6-адрес") from None
        # Alternative numeric IPv4 spellings have inconsistent browser/DNS
        # semantics.  Accept standard dotted decimal only, through ipaddress.
        if all(re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", label) for label in hostname.split(".")):
            raise ValueError("некорректный IPv4-адрес") from None
        try:
            host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("некорректное имя хоста") from None
        if host.endswith("."):
            host = host[:-1]
        if not host or len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("некорректное имя хоста")
        try:
            # ASCII punycode labels must also be valid IDNA, and a terminal
            # dot or Unicode DNS separator must not hide an invalid IPv4.
            host.encode("ascii").decode("idna")
            if all(re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", label) for label in host.split(".")):
                host = str(ipaddress.IPv4Address(host))
        except (UnicodeError, ValueError):
            raise ValueError("некорректное имя хоста") from None
    else:
        if bracketed != (address.version == 6):
            raise ValueError("IPv6-адрес нужно заключить в квадратные скобки")
        host = f"[{address.compressed}]" if address.version == 6 else str(address)

    if port is not None and port != (443 if scheme == "https" else 80):
        host += f":{port}"
    # The fragment is part of an exact target: SPAs can route #/login and
    # #/register to different forms even though HTTP sends the same document.
    return urlunsplit((scheme, host, parts.path, parts.query, parts.fragment))
