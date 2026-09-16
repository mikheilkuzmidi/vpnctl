"""The unprotected connection, measured as a baseline.

Every other adapter answers "how good is this tunnel". None of them answered
the question a selector actually has to settle first: is any tunnel better than
no tunnel at all? Without a control row, a benchmark table ranks three VPNs
against each other and silently assumes the winner beats the plain connection.

This adapter is that control. It brings nothing up and tears nothing down, so
it needs no root and cannot fail to connect; it runs the same probe every other
provider runs, against the path traffic already takes.
"""

from __future__ import annotations

from vpnctl.probe import ProbeResult, run_probe
from vpnctl.providers.base import DoctorResult, ProviderAdapter, ProviderStatus

PROVIDER_ID = "direct"


class DirectAdapter(ProviderAdapter):
    """Measures the connection as it stands, with no tunnel in the path."""

    @property
    def provider_id(self) -> str:
        return PROVIDER_ID

    def prepare(self) -> None:
        """Nothing to install: the unprotected path is always already there."""

    def connect(self) -> None:
        """No-op. Being connected to nothing is the state this measures."""

    def disconnect(self) -> None:
        """No-op. There is no tunnel to tear down."""

    def status(self) -> ProviderStatus:
        # Reported as connected because the path it measures is always usable.
        # Calling it disconnected would make `status` read as a fault.
        return ProviderStatus.CONNECTED

    def probe(self) -> ProbeResult:
        return run_probe(self.provider_id)

    def doctor(self) -> DoctorResult:
        # No binaries, no config, no privileges. There is nothing to check.
        return DoctorResult(provider_id=self.provider_id, ok=True)
