from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Collection

from ..models import AuthJob, Credential, Outcome


class AuthAdapter(ABC):
    """Interface for a future protocol-specific authentication adapter."""

    @property
    @abstractmethod
    def auth_types(self) -> Collection[str]:
        raise NotImplementedError

    @abstractmethod
    def attempt(self, job: AuthJob, credential: Credential) -> Outcome:
        """Perform one bounded attempt and return a normalized outcome."""

        raise NotImplementedError

