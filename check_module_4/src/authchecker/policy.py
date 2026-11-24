from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttemptPolicy:
    """Single-mode safety policy applied to all adapters."""

    rate_per_second: float = 1.0
    max_total_attempts: int | None = None
    max_attempts_per_account: int = 3
    stop_on_success: bool = True
    stop_on_mfa: bool = True
    stop_on_lockout: bool = True
    stop_on_rate_limit: bool = True

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be greater than zero")
        if self.max_total_attempts is not None and self.max_total_attempts < 0:
            raise ValueError("max_total_attempts cannot be negative")

