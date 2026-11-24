"""Encoding helpers for predictable CLI output, especially on Windows pipes."""

from __future__ import annotations

import codecs
from typing import Any


def configure_text_stream(
    stream: Any,
    *,
    encoding: str,
    errors: str,
) -> None:
    """Reconfigure a real text stream when the host wrapper supports it."""

    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding=encoding, errors=errors)
    except (OSError, ValueError):
        return


class EncodedStreamWriter:
    """Write encoded text directly to a stream's binary buffer without closing it."""

    def __init__(self, stream: Any, encoding: str):
        self._stream = stream
        self._buffer = getattr(stream, "buffer", None)
        self._encoder = (
            codecs.getincrementalencoder(encoding)(errors="strict")
            if self._buffer is not None
            else None
        )
        self._finished = False

    def write(self, value: str) -> int:
        if self._finished:
            raise ValueError("cannot write after stream finalization")
        if self._encoder is None:
            return self._stream.write(value)
        encoded = self._encoder.encode(value, final=False)
        if encoded:
            self._buffer.write(encoded)
        return len(value)

    def flush(self) -> None:
        if self._encoder is None:
            self._stream.flush()
        else:
            self._buffer.flush()

    def finish(self) -> None:
        if self._finished:
            return
        if self._encoder is None:
            self._stream.flush()
        else:
            remainder = self._encoder.encode("", final=True)
            if remainder:
                self._buffer.write(remainder)
            self._buffer.flush()
        self._finished = True
