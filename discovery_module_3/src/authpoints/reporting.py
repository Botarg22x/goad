from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import Report


def write_json_report(report: Report, output: Path) -> None:
    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"
    _write_text_atomic(payload, output)


def write_links_report(report: Report, output: Path) -> None:
    endpoints: list[str] = []
    for finding in report.findings:
        endpoints.append(finding.endpoint)
        discovered_on = finding.metadata.get("discovered_on")
        if isinstance(discovered_on, list):
            endpoints.extend(
                url for url in discovered_on if isinstance(url, str) and url
            )
    endpoints = list(dict.fromkeys(endpoints))
    payload = "".join(f"{endpoint}\n" for endpoint in endpoints)
    _write_text_atomic(payload, output)


def _write_text_atomic(payload: str, output: Path) -> None:
    destination = output.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
