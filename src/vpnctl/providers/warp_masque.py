"""Cloudflare WARP adapter - MASQUE (HTTP/3) mode.

Uses the `warp-cli` command-line tool shipped with the Cloudflare WARP macOS
client.  Switches the protocol to MASQUE before connecting so the benchmark
comparison is apples-to-apples against the WireGuard mode adapter.
"""

from __future__ import annotations

from typing import Optional

import shutil
import subprocess
import time

from vpnctl.providers.base import (
    DoctorResult,
    ProgressFn,
    ProbeResult,
    ProviderAdapter,
    ProviderStatus,
)
from vpnctl.platform import IS_MACOS
from vpnctl.probe import run_probe
from vpnctl.split_tunnel import apply_warp_excludes, remove_warp_excludes

_WARP_CLI = "warp-cli"
_PROTO = "MASQUE"
_PROVIDER_ID = "warp-masque"

_CONNECT_TIMEOUT = 20
_POLL_INTERVAL = 0.5


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_WARP_CLI, *args],
        capture_output=True,
        text=True,
        check=check,
    )


class WarpMasqueAdapter(ProviderAdapter):
    """MASQUE is Cloudflare's own transport, so it needs their client."""

    @classmethod
    def supported(cls) -> bool:
        # warp-cli ships for macOS and Windows only. On Linux this provider
        # is not broken, it is inapplicable.
        return IS_MACOS
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

    def probe(self, on_progress: Optional[ProgressFn] = None) -> ProbeResult:
        return run_probe(_PROVIDER_ID, on_progress)

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
                    "warp-cli is present but returned an error - "
                    "is WARP registered? Run: warp-cli registration new"
                )
        return DoctorResult(
            provider_id=_PROVIDER_ID,
            ok=len(issues) == 0,
            issues=issues,
            hints=hints,
        )
