from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import normalize_hostname, normalize_url


MAX_NETWORK_ADDRESSES = 4096


@dataclass(slots=True)
class Scope:
    hosts: set[str] = field(default_factory=set)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    include_subdomains: bool = False

    @classmethod
    def from_inputs(
        cls,
        targets: list[str],
        urls: list[str],
        *,
        include_subdomains: bool = False,
        allow_large_networks: bool = False,
    ) -> "Scope":
        scope = cls(include_subdomains=include_subdomains)
        for target in targets:
            scope.add_target(target, allow_large_networks=allow_large_networks)
        for url in urls:
            normalized = normalize_url(url, redact_query=False)
            host = urlsplit(normalized).hostname
            if host:
                scope.hosts.add(normalize_hostname(host))
        return scope

    def add_target(self, target: str, *, allow_large_networks: bool = False) -> None:
        value = target.strip()
        if not value or value.startswith("-"):
            raise ValueError(f"invalid target: {target!r}")
        # Nmap accepts octet ranges such as 192.168.0-255.1-254.  The
        # ipaddress module does not, so treating them as hostnames would bypass
        # the network-size guard.  Require an auditable CIDR instead.
        if "-" in value and re.fullmatch(r"[0-9.-]+", value):
            raise ValueError("Nmap octet ranges are unsupported; use CIDR")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            self.hosts.add(str(address))
            return
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            if "/" in value or "://" in value:
                raise ValueError(f"invalid target: {target!r}") from None
            self.hosts.add(normalize_hostname(value))
            return
        total_addresses = sum(item.num_addresses for item in self.networks)
        if (
            total_addresses + network.num_addresses > MAX_NETWORK_ADDRESSES
            and not allow_large_networks
        ):
            raise ValueError(
                f"network scope contains more than {MAX_NETWORK_ADDRESSES} addresses; "
                "use --allow-large-networks explicitly"
            )
        self.networks.append(network)

    def allows_host(self, host: str) -> bool:
        normalized = normalize_hostname(host)
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            if normalized in self.hosts:
                return True
            return self.include_subdomains and any(
                normalized.endswith("." + allowed)
                for allowed in self.hosts
                if not _is_ip(allowed)
            )
        return normalized in self.hosts or any(address in network for network in self.networks)

    def allows_url(self, url: str) -> bool:
        try:
            normalized = normalize_url(url, redact_query=False)
        except ValueError:
            return False
        host = urlsplit(normalized).hostname
        return bool(host and self.allows_host(host))

    def describe(self) -> list[str]:
        entries = sorted(self.hosts)
        entries.extend(str(network) for network in sorted(self.networks, key=str))
        return entries


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
