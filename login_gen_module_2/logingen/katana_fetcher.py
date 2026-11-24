"""Standalone Katana transport; the collector owns scope, depth and checkpoints."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import replace
from html import escape
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .models import AutoConfig
from .playwright_fetcher import (
    FetchResponse, PlaywrightFetchError, PlaywrightFetchTimeoutError,
    PlaywrightFetchTransport, PlaywrightUnavailableError,
)


class KatanaFetchTransport:
    def __init__(self, config: AutoConfig) -> None:
        self.config = config
        self.executable = shutil.which(config.katana_executable)
        if not self.executable:
            raise PlaywrightUnavailableError(
                "Katana не найдена. Установите katana или укажите --katana-executable PATH."
            )
        self.executable = str(Path(self.executable).resolve())
        self.fallback = None
        self.last_request = None

    def _wait(self):
        if self.last_request is not None:
            remaining = self.config.request_delay_seconds - (time.monotonic() - self.last_request)
            if remaining > 0:
                time.sleep(remaining)
        self.last_request = time.monotonic()

    def _http(self):
        if self.fallback is None:
            self.fallback = PlaywrightFetchTransport(replace(self.config, request_delay_seconds=0))
        return self.fallback

    def fetch_text(self, url, *, timeout_seconds=None, headers=None, _redirect_count=0):
        self._wait()
        if urlsplit(url).path == "/robots.txt":
            return self._http().fetch_text(url, timeout_seconds=timeout_seconds, headers=headers)
        timeout = timeout_seconds or self.config.timeout_seconds
        command = [self.executable, "-u", url, "-jsonl", "-silent", "-nc", "-duc",
                   "-d", "1", "-mdp", "1", "-c", "1", "-p", "1", "-rl", "1",
                   "-retry", "0", "-dr", "-ndef", "-timeout", str(timeout),
                   "-mrs", str(2 * 1024 * 1024), "-eof", "raw",
                   "-H", "User-Agent: " + self.config.user_agent]
        if self.config.proxy_url:
            command.extend(("-proxy", self.config.proxy_url))
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}}
        if self.config.ca_cert:
            environment["SSL_CERT_FILE"] = str(self.config.ca_cert)
        try:
            with tempfile.TemporaryDirectory(prefix="logingen-katana-") as working:
                process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                         errors="replace", timeout=timeout + 10, env=environment, cwd=working)
        except subprocess.TimeoutExpired as error:
            raise PlaywrightFetchTimeoutError(f"Katana: таймаут {url}") from error
        except OSError as error:
            raise PlaywrightFetchError(f"Katana: {error}") from error
        response = None
        links = []
        errors = []
        for line in process.stdout.splitlines():
            try:
                item = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(item, dict):
                continue
            request = item.get("request") or {}
            if not isinstance(request, dict):
                continue
            endpoint = request.get("endpoint") or request.get("url") or item.get("url")
            if isinstance(endpoint, str) and endpoint != url:
                links.append(endpoint)
            if item.get("error"):
                errors.append(str(item["error"]))
            current = item.get("response")
            if isinstance(current, dict) and endpoint == url:
                response = current
        if response is None:
            detail = "; ".join(errors) or process.stderr.strip() or "нет ответа страницы в JSONL"
            raise PlaywrightFetchError(f"Katana: {detail[:500]}")
        raw_headers = response.get("headers") or {}
        response_headers = {str(key).lower().replace("_", "-"): value
                            for key, value in raw_headers.items()}
        def header(name):
            value = response_headers.get(name, "")
            return value[0] if isinstance(value, list) and value else str(value)
        status = int(response.get("status_code") or 200)
        body = response.get("body") or ""
        content_type = header("content-type")
        if 300 <= status < 400 and header("location"):
            from .collector import is_allowed_url, normalize_url
            destination = normalize_url(urljoin(url, header("location")))
            allowed = self.config.allowed_domains or tuple(
                urlsplit(seed).hostname for seed in (self.config.url, *self.config.extra_urls) if seed)
            if not is_allowed_url(destination, allowed, exact_hosts=self.config.exact_hosts):
                raise PlaywrightFetchError(f"Katana: редирект за область обхода: {destination}")
            if _redirect_count >= 5:
                raise PlaywrightFetchError(f"Katana: превышен предел 5 редиректов: {url}")
            return self.fetch_text(destination, timeout_seconds=timeout, headers=headers,
                                   _redirect_count=_redirect_count + 1)
        if "html" in content_type or 300 <= status < 400:
            body += "".join(f'<a href="{escape(link, quote=True)}"></a>' for link in dict.fromkeys(links))
            content_type = "text/html"
        return FetchResponse(url, status, body, content_type)

    def fetch_bytes(self, url, **kwargs):
        self._wait()
        return self._http().fetch_bytes(url, **kwargs)

    def fetch_rendered_html(self, url):
        self._wait()
        return self._http().fetch_rendered_html(url)

    def fetch_rendered_html_with_manual_access(self, url):
        self._wait()
        return self._http().fetch_rendered_html_with_manual_access(url)

    def close(self):
        if self.fallback is not None:
            self.fallback.close()
