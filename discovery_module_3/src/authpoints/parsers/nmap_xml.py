from __future__ import annotations

import re
import ipaddress
import xml.etree.ElementTree as ET

from ..models import ServiceObservation
from ..normalize import normalize_hostname


MAX_XML_BYTES = 64 * 1024 * 1024
_NMAP_DOCTYPE = re.compile(r"<!DOCTYPE\s+nmaprun\s*>", flags=re.IGNORECASE)


def parse_nmap_xml(data: bytes | str) -> list[ServiceObservation]:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_XML_BYTES:
        raise ValueError(f"Nmap XML is larger than {MAX_XML_BYTES} bytes")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Nmap XML must be UTF-8") from exc
    # Nmap emits the fixed, external-reference-free ``<!DOCTYPE nmaprun>``
    # declaration even when --no-stylesheet is used.  ElementTree does not
    # need it, so remove that one known-safe declaration while continuing to
    # reject custom DTDs and every entity declaration.
    if re.search(r"<!\s*ENTITY\b", decoded, flags=re.IGNORECASE):
        raise ValueError("DTD and entity declarations are not accepted in Nmap XML")
    decoded, doctype_count = _NMAP_DOCTYPE.subn("", decoded)
    if doctype_count > 1 or re.search(
        r"<!\s*DOCTYPE\b", decoded, flags=re.IGNORECASE
    ):
        raise ValueError("Only the standard Nmap DOCTYPE declaration is accepted")
    try:
        root = ET.fromstring(decoded)
    except ET.ParseError as exc:
        raise ValueError(f"invalid Nmap XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("not an Nmap XML document")

    observations: list[ServiceObservation] = []
    for host_node in root.findall("host"):
        host_state = host_node.find("status")
        if host_state is not None and host_state.get("state") == "down":
            continue
        addresses = {
            address.get("addrtype", ""): address.get("addr", "")
            for address in host_node.findall("address")
            if address.get("addr")
        }
        address = addresses.get("ipv4") or addresses.get("ipv6") or ""
        try:
            address = str(ipaddress.ip_address(address)) if address else ""
        except ValueError:
            address = ""
        hostname = next(
            (
                node.get("name", "")
                for node in host_node.findall("hostnames/hostname")
                if node.get("type") == "user" and node.get("name")
            ),
            "",
        )
        host = ""
        for candidate in (hostname, address):
            if not candidate:
                continue
            try:
                host = normalize_hostname(candidate)
                break
            except ValueError:
                continue
        if not host:
            continue
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state != "open":
                continue
            try:
                port = int(port_node.get("portid", ""))
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            service_node = port_node.find("service")
            attrs = service_node.attrib if service_node is not None else {}
            confidence: int | None = None
            try:
                if attrs.get("conf"):
                    confidence = int(attrs["conf"])
            except ValueError:
                confidence = None
            observations.append(
                ServiceObservation(
                    host=host,
                    address=address,
                    port=port,
                    transport=port_node.get("protocol", "tcp"),
                    state=state,
                    service=attrs.get("name", "unknown").lower(),
                    product=attrs.get("product", ""),
                    version=attrs.get("version", ""),
                    extra_info=attrs.get("extrainfo", ""),
                    tunnel=attrs.get("tunnel", "").lower(),
                    detection_method=attrs.get("method", ""),
                    service_confidence=confidence,
                )
            )
    return observations
