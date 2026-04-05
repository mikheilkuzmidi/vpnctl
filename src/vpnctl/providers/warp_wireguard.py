"""Cloudflare WARP adapter — WireGuard mode.

Identical lifecycle to WarpMasqueAdapter but switches the protocol to
`wireguard` before connecting, so both WARP modes appear as independent
benchmark candidates.
"""

from __future__ import annotations

import shutil
import subprocess
import time

from vpnctl.providers.base import (
    DoctorResult,
    ProbeResult,
    ProviderAdapter,
    ProviderStatus,
)
from vpnctl.probe import run_probe
from vpnctl.split_tunnel import apply_warp_excludes, remove_warp_excludes

_WARP_CLI = "warp-cli"
_PROTO = "WireGuard"
_PROVIDER_ID = "warp-wireguard"

_CONNECT_TIMEOUT = 20
_POLL_INTERVAL = 0.5


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_WARP_CLI, *args],
        capture_output=True,
        text=True,
        check=check,
    )


class WarpWireguardAdapter(ProviderAdapter):
    def __init__(self, excludes: list[str] | None = None) -> None:
        self._excludes: list[str] = excludes or []

    @property
    def provider_id(self) -> str:
        return _PROVIDER_ID

    def prepare(self) -> None:
        if not shutil.which(_WARP_CLI):
            raise RuntimeError(
                "warp-cli not found. Install Cloudflare WARP: "
                "brew install --cask cloudflare-warp"
            )
        result = _run(["tunnel", "protocol", "set", _PROTO], check=False)
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to set WARP protocol to {_PROTO}: {result.stderr.strip()}"
            )

    def connect(self) -> None:
        self.prepare()
        _run(["connect"])
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            if self.status() == ProviderStatus.CONNECTED:
                apply_warp_excludes(self._excludes)
                return
            time.sleep(_POLL_INTERVAL)
        raise RuntimeError(
            f"{_PROVIDER_ID}: timed out waiting for connection "
            f"({_CONNECT_TIMEOUT}s)"
        )

    def disconnect(self) -> None:
        if not shutil.which(_WARP_CLI):
            return
        remove_warp_excludes(self._excludes)
        _run(["disconnect"], check=False)

    def status(self) -> ProviderStatus:
        if not shutil.which(_WARP_CLI):
            return ProviderStatus.UNKNOWN
        result = _run(["status"], check=False)
        out = result.stdout.lower()
        if "connected" in out and "disconnected" not in out:
            return ProviderStatus.CONNECTED
        if "connecting" in out:
            return ProviderStatus.CONNECTING
        if "disconnected" in out:
            return ProviderStatus.DISCONNECTED
        return ProviderStatus.UNKNOWN

    def probe(self) -> ProbeResult:
        return run_probe(_PROVIDER_ID)

    def doctor(self) -> DoctorResult:
        issues: list[str] = []
        hints: list[str] = []
        if not shutil.which(_WARP_CLI):
            issues.append("warp-cli not found")
            hints.append("brew install --cask cloudflare-warp")
        else:
            result = _run(["settings"], check=False)
            if result.returncode != 0:
                issues.append(
                    "warp-cli is present but returned an error — "
                    "is WARP registered? Run: warp-cli registration new"
                )
        return DoctorResult(
            provider_id=_PROVIDER_ID,
            ok=len(issues) == 0,
            issues=issues,
            hints=hints,
        )
