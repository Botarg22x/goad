from __future__ import annotations

from copy import deepcopy
from typing import Any


def valid_finding(
    *,
    finding_id: str = "auth-0123456789abcdef",
    auth_type: str = "password_form",
    endpoint: str = "https://example.test/login",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "web_login_page",
        "auth_type": auth_type,
        "endpoint": endpoint,
        "host": "example.test",
        "port": 443,
        "protocol": "https",
        "evidence": [
            {
                "rule_id": "html.form.identifier_password",
                "group": "form_structure",
                "source": "katana",
                "detail": "identifier and password fields",
            }
        ],
        "sources": ["katana"],
        "metadata": metadata
        or {
            "page_url": endpoint,
            "form_action": endpoint,
            "auth_fingerprint": "form-0123456789abcdef",
        },
        "id": finding_id,
        "discovered_at": "2026-10-01T10:00:01+00:00",
    }


def valid_service() -> dict[str, Any]:
    return {
        "host": "example.test",
        "port": 22,
        "transport": "tcp",
        "state": "open",
        "service": "ssh",
        "address": "192.0.2.10",
        "product": "OpenSSH",
        "version": "9",
        "extra_info": "",
        "tunnel": "",
        "detection_method": "probed",
        "service_confidence": 10,
        "source": "nmap",
    }


def valid_report(*, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    report = {
        "scope": ["example.test"],
        "findings": findings if findings is not None else [valid_finding()],
        "services": [valid_service()],
        "issues": [],
        "schema_version": "2.0",
        "detector_version": "3.0.0",
        "run_id": "12345678-1234-5678-9234-567812345678",
        "started_at": "2026-10-01T10:00:00+00:00",
        "finished_at": "2026-10-01T10:00:02+00:00",
        "partial": False,
        "config": {"source": "test"},
    }
    return deepcopy(report)

