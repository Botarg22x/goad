from __future__ import annotations

from .base import AuthAdapter
from .unsupported import UnsupportedAdapter


class AdapterRegistry:
    def __init__(self) -> None:
        self._by_auth_type: dict[str, AuthAdapter] = {}
        self._unsupported = UnsupportedAdapter()

    def register(self, adapter: AuthAdapter, *, replace: bool = False) -> None:
        auth_types = tuple(adapter.auth_types)
        if not auth_types:
            raise ValueError("an adapter must declare at least one auth_type")
        if any(not isinstance(item, str) or not item for item in auth_types):
            raise ValueError("adapter auth_types must be non-empty strings")
        collisions = sorted(item for item in auth_types if item in self._by_auth_type)
        if collisions and not replace:
            raise ValueError(f"adapter already registered for: {', '.join(collisions)}")
        for auth_type in auth_types:
            self._by_auth_type[auth_type] = adapter

    def resolve(self, auth_type: str) -> AuthAdapter:
        return self._by_auth_type.get(auth_type, self._unsupported)

    def registered_types(self) -> frozenset[str]:
        return frozenset(self._by_auth_type)

