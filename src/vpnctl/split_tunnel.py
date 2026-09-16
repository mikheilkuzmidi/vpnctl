"""Split-tunnel helpers for macOS.

Two strategies are supported:

1. WARP native split tunnel  (warp-cli split-tunnel add/remove/list)
   Used by WarpMasqueAdapter and WarpWireguardAdapter.  The WARP daemon owns
   the routing, so we tell it which CIDRs to exclude instead of touching the
   OS routing table ourselves.

2. macOS route-based split tunnel  (route add / route delete)
   Used by WgCustomAdapter.  After wg-quick brings the tunnel up it installs a
   0/0 default route.  We immediately punch back static routes for the excluded
   CIDRs that point to the *original* gateway, which the OS prefers because they
   are more specific.

Both strategies use the same list of excluded CIDRs from [split_tunnel].excludes
in ~/.config/vpnctl/config.toml.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Optional


# ---------------------------------------------------------------------------
# Gateway detection
# ---------------------------------------------------------------------------

def get_default_gateway() -> Optional[str]:
    """Return the current IPv4 default gateway (before the VPN changes it).

    Uses ``route -n get default`` which is reliable on macOS.
    Returns None if it cannot be determined.
    """
    result = subprocess.run(
        ["route", "-n", "get", "default"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        m = re.search(r"gateway:\s+(\S+)", line)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# WARP native split tunnel
# ---------------------------------------------------------------------------

_WARP_CLI = "warp-cli"


def _warp_available() -> bool:
    return shutil.which(_WARP_CLI) is not None


def apply_warp_excludes(excludes: list[str]) -> None:
    """Register each CIDR as a WARP split-tunnel exclusion (traffic bypasses WARP).

    Idempotent - adding the same entry twice is harmless.
    Skips silently if warp-cli is not installed.
    """
    if not excludes or not _warp_available():
        return
    for cidr in excludes:
        subprocess.run(
            [_WARP_CLI, "split-tunnel", "add", cidr],
            capture_output=True,
            text=True,
            check=False,
        )


def remove_warp_excludes(excludes: list[str]) -> None:
    """Remove each CIDR from WARP's split-tunnel exclusion list.

    Skips silently if warp-cli is not installed or the entry is not present.
    """
    if not excludes or not _warp_available():
        return
    for cidr in excludes:
        subprocess.run(
            [_WARP_CLI, "split-tunnel", "remove", cidr],
            capture_output=True,
            text=True,
            check=False,
        )


def list_warp_excludes() -> list[str]:
    """Return CIDRs currently in WARP's split-tunnel exclusion list."""
    if not _warp_available():
        return []
    result = subprocess.run(
        [_WARP_CLI, "split-tunnel", "list"],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# macOS route-based split tunnel  (for WireGuard / non-WARP providers)
# ---------------------------------------------------------------------------

def add_macos_routes(excludes: list[str], gateway: str) -> None:
    """Add static host/network routes that bypass the VPN tunnel.

    For each CIDR in *excludes*, installs a route via *gateway* (the original
    default gateway captured before the VPN connected).  More-specific routes
    win over the VPN's 0/0 default route, so these destinations use the plain
    internet connection.

    Requires sudo (wg-quick already runs as root so the child process inherits
    the right permissions when called from WgCustomAdapter.connect()).
    """
    if not excludes or not gateway:
        return
    for cidr in excludes:
        subprocess.run(
            ["sudo", "route", "-q", "add", "-net", cidr, gateway],
            capture_output=True,
            text=True,
            check=False,
        )


def remove_macos_routes(excludes: list[str]) -> None:
    """Delete the static routes previously added by add_macos_routes().

    Safe to call even if the routes are already gone (e.g. interface teardown
    removed them automatically).
    """
    if not excludes:
        return
    for cidr in excludes:
        subprocess.run(
            ["sudo", "route", "-q", "delete", "-net", cidr],
            capture_output=True,
            text=True,
            check=False,
        )


# ---------------------------------------------------------------------------
# Torrent-only / "no-default-tunnel" helpers
# ---------------------------------------------------------------------------

def remove_vpn_default_route() -> None:
    """Delete the 0/0 default route that wg-quick added.

    Called immediately after wg-quick up in torrent-only mode so that normal
    traffic continues using the physical interface while the WireGuard
    interface remains available for apps that bind to it explicitly.
    """
    subprocess.run(
        ["sudo", "route", "-q", "delete", "default"],
        capture_output=True,
        text=True,
        check=False,
    )


def restore_default_route(gateway: str) -> None:
    """Re-install the original default gateway after removing the VPN route.

    *gateway* should be the value returned by get_default_gateway() called
    **before** wg-quick up changed the routing table.
    """
    if not gateway:
        return
    subprocess.run(
        ["sudo", "route", "-q", "add", "default", gateway],
        capture_output=True,
        text=True,
        check=False,
    )
