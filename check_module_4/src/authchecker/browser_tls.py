"""Temporary, explicitly selected TLS key exceptions for native Chromium.

Chromium does not use Python's SSLContext or ``--ca-cert``.  Instead of
intercepting browser requests or changing a user's trust store, validate the
target with that CA first and allow the verified peer's public key and the
explicitly supplied CA keys for this browser process.  No HTTP request is sent
by this module; an HTTP proxy receives only CONNECT and the TLS handshake.

The Chromium SPKI switch ignores certificate errors for the matching key; it is
not equivalent to installing a root CA and does not enforce PKI constraints on
later uses of the same key.  The caller must use a disposable browser profile,
keep credential submissions within their exact origin, and never persist these
arguments.  Pins are not hostname restrictions: a proxy may reuse a leaf key
for multiple hosts.  CA pins help with asset hosts only when Chromium sees that
CA in their certificate chain.  A proxy which omits its root and issues distinct
leaf keys for other hosts can still cause certificate errors on those assets;
the target leaf pin covers the verified target even when the root is omitted.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import math
import shutil
import ssl
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def browser_tls_args(
    url: str,
    *,
    ca_cert: Path | None,
    proxy: str | None,
    timeout_seconds: float,
) -> list[str]:
    """Return Chromium arguments for an explicitly supplied target CA.

    With no CA, Chromium's normal TLS validation is untouched.  With an HTTPS
    target and CA, complete a hostname- and chain-verified TLS handshake before
    deriving a SHA-256 SubjectPublicKeyInfo pin with the local OpenSSL command.
    A verification or connection failure raises ValueError and never produces
    a certificate-error exception.  Plain HTTP needs no browser TLS arguments.

    Chromium requires ``--user-data-dir`` for the returned switch to take
    effect; Playwright supplies a temporary one during a normal launch.
    """

    if ca_cert is None:
        return []
    certificate = ca_cert.expanduser().resolve()
    if not certificate.is_file():
        raise ValueError(f"--ca-cert file not found: {certificate}")
    try:
        ssl_context = ssl.create_default_context(cafile=str(certificate))
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"invalid --ca-cert for browser TLS: {exc}") from exc

    parts = urlsplit(url)
    if (
        parts.scheme.casefold() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("browser TLS target must be an HTTP(S) URL without credentials")
    try:
        port = parts.port
        if port is None:
            port = 443 if parts.scheme.casefold() == "https" else 80
    except ValueError as exc:
        raise ValueError("browser TLS target contains an invalid port") from exc
    if not 0 < port <= 65535:
        raise ValueError("browser TLS target contains an invalid port")
    if parts.scheme.casefold() == "http":
        return []
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("browser TLS timeout must be a finite positive number")

    executable = shutil.which("openssl")
    if executable is None:
        raise ValueError("browser --ca-cert requires the openssl executable")
    connection = _tls_connection(
        parts.hostname,
        port,
        proxy=proxy,
        timeout_seconds=timeout_seconds,
        ssl_context=ssl_context,
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise ValueError("browser TLS preflight returned no TLS socket")
        peer_certificate = connection.sock.getpeercert(binary_form=True)
        if not peer_certificate:
            raise ValueError("browser TLS preflight returned no peer certificate")
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise ValueError(f"browser TLS preflight failed: {exc}") from exc
    finally:
        connection.close()

    # This SSLContext loaded only the explicitly supplied file, never the
    # platform's default CA bundle.  Do not pin every system-trusted CA key.
    certificates = dict.fromkeys([
        peer_certificate,
        *ssl_context.get_ca_certs(binary_form=True),
    ])
    pins = dict.fromkeys(
        _certificate_spki_pin(
            item,
            executable=executable,
            timeout_seconds=timeout_seconds,
        )
        for item in certificates
    )
    return [f"--ignore-certificate-errors-spki-list={','.join(pins)}"]


def _tls_connection(
    hostname: str,
    port: int,
    *,
    proxy: str | None,
    timeout_seconds: float,
    ssl_context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    if not proxy:
        return http.client.HTTPSConnection(
            hostname, port, timeout=timeout_seconds, context=ssl_context,
        )
    parts = urlsplit(proxy)
    if (
        parts.scheme.casefold() != "http"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("browser TLS --proxy must be http://HOST:PORT without credentials or a path")
    try:
        proxy_port = parts.port
        if proxy_port is None:
            proxy_port = 80
    except ValueError as exc:
        raise ValueError("browser TLS --proxy contains an invalid port") from exc
    if not 0 < proxy_port <= 65535:
        raise ValueError("browser TLS --proxy contains an invalid port")
    connection = http.client.HTTPSConnection(
        parts.hostname,
        proxy_port,
        timeout=timeout_seconds,
        context=ssl_context,
    )
    connection.set_tunnel(hostname, port)
    return connection


def _certificate_spki_pin(
    certificate: bytes,
    *,
    executable: str,
    timeout_seconds: float,
) -> str:
    # No shell or temporary certificate/private-key files: only the public peer
    # certificate and its public key pass through subprocess standard input.
    try:
        public_key = subprocess.run(
            [executable, "x509", "-inform", "DER", "-pubkey", "-noout"],
            input=certificate,
            capture_output=True,
            check=True,
            timeout=timeout_seconds,
        ).stdout
        spki = subprocess.run(
            [executable, "pkey", "-pubin", "-outform", "DER"],
            input=public_key,
            capture_output=True,
            check=True,
            timeout=timeout_seconds,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("could not derive a browser TLS public-key pin with openssl") from exc
    if not spki:
        raise ValueError("openssl returned an empty browser TLS public key")
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
