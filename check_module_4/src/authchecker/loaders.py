from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from .models import Credential


def load_passwords(
    path: str | Path, *, encoding: str = "utf-8"
) -> Iterator[str]:
    """Yield passwords without trimming anything except line terminators."""

    with Path(path).open("r", encoding=encoding, errors="strict", newline="") as stream:
        for line in stream:
            yield _remove_line_ending(line)


def load_logins(path: str | Path) -> Iterator[str]:
    """Yield UTF-8 logins, preserving all non-CR/LF characters."""

    with Path(path).open("r", encoding="utf-8", errors="strict", newline="") as stream:
        for line in stream:
            yield _remove_line_ending(line)


def iter_credentials(
    logins_path: str | Path | None,
    passwords_path: str | Path | None,
    *,
    password_encoding: str = "utf-8",
    login_values: Iterable[str] = (),
    password_values: Iterable[str] = (),
) -> Iterator[Credential]:
    """Stream the login/password Cartesian product without storing passwords."""

    inline_passwords = tuple(password_values)
    for username in _logins(logins_path, login_values):
        for password in _passwords(
            passwords_path,
            inline_passwords,
            encoding=password_encoding,
        ):
            yield Credential(username=username, password=password)


def count_candidates(
    logins_path: str | Path | None,
    passwords_path: str | Path | None,
    *,
    password_encoding: str = "utf-8",
    login_values: Iterable[str] = (),
    password_values: Iterable[str] = (),
) -> tuple[int, int]:
    """Validate and count both input streams without retaining their contents."""

    login_count = sum(1 for _ in _logins(logins_path, login_values))
    password_count = sum(
        1
        for _ in _passwords(
            passwords_path,
            password_values,
            encoding=password_encoding,
        )
    )
    return login_count, password_count


def _logins(
    path: str | Path | None,
    values: Iterable[str],
) -> Iterator[str]:
    if path is not None:
        yield from load_logins(path)
        return
    yield from values


def _passwords(
    path: str | Path | None,
    values: Iterable[str],
    *,
    encoding: str,
) -> Iterator[str]:
    if path is not None:
        yield from load_passwords(path, encoding=encoding)
        return
    yield from values


def _remove_line_ending(line: str) -> str:
    """Remove exactly one physical CRLF, LF or CR terminator."""

    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1]
    return line
