"""Abstract provider adapter contract.

Every VPN provider must implement this interface.  The benchmark engine,
selector, and watch loop are all provider-agnostic - they only call methods
defined here.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProviderStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    """Lightweight measurement taken against a live tunnel."""

    provider_id: str
    median_rtt_ms: float
    jitter_ms: float
    loss_pct: float
    throughput_mbps: float
    score: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __str__(self) -> str:
        if not self.ok:
            return f"{self.provider_id}: ERROR - {self.error}"
        return (
            f"{self.provider_id}: rtt={self.median_rtt_ms:.1f}ms "
            f"jitter={self.jitter_ms:.1f}ms loss={self.loss_pct:.1f}% "
            f"dl={self.throughput_mbps:.2f}Mbps score={self.score:.2f}"
        )


@dataclass
class DoctorResult:
    """Outcome of a pre-flight dependency check for one provider."""

    provider_id: str
    ok: bool
    issues: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)


class ProviderAdapter(abc.ABC):
    """Common contract for all VPN provider adapters."""

    @property
    @abc.abstractmethod
    def provider_id(self) -> str:
        """Stable identifier used in config, logs, and output (e.g. 'warp-masque')."""

    @abc.abstractmethod
    def prepare(self) -> None:
        """One-time set-up: install configs, set protocol mode, etc.

        Must be idempotent.  Raises RuntimeError if prerequisites are absent.
        """

    @abc.abstractmethod
    def connect(self) -> None:
        """Bring the tunnel up.  Raises RuntimeError on failure."""

    @abc.abstractmethod
    def disconnect(self) -> None:
        """Tear the tunnel down.  Must not raise if already disconnected."""

    @abc.abstractmethod
    def status(self) -> ProviderStatus:
        """Return the current tunnel state without making any changes."""

    @abc.abstractmethod
    def probe(self) -> ProbeResult:
        """Measure tunnel quality while connected.

        Implementations should:
        - Ping a set of stable public targets (several to avoid single-host bias).
        - Measure median RTT and jitter (std-dev of RTT samples).
        - Estimate packet loss.
        - Run a short HTTP(S) download throughput test.
        - Return a ProbeResult; set error and return a degraded result on failure
          rather than raising.
        """

    def doctor(self) -> DoctorResult:
        """Check whether this provider's dependencies are satisfied.

        Default implementation returns ok=True.  Override to add checks.
        """
        return DoctorResult(provider_id=self.provider_id, ok=True)
