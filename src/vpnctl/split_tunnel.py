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

import ipaddress

import shutil
import subprocess
from typing import Optional

from vpnctl import platform


# ---------------------------------------------------------------------------
# Gateway detection
# ---------------------------------------------------------------------------

def get_default_gateway() -> Optional[str]:
    """The current IPv4 default gateway, before the VPN changes it.

    Kept as a name because several callers use it; the platform-specific part
    now lives in vpnctl.platform, which asks `route` on macOS and `ip` on
    Linux. `route` is net-tools, absent from most Linux systems, and has no
    `get` verb even when present.
    """
    return platform.default_gateway()


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
    """Add static routes that bypass the VPN tunnel.

    For each CIDR, installs a route via *gateway* (the original default
    gateway captured before the VPN connected). A longer prefix wins over the
    VPN's 0.0.0.0/0, so those destinations use the plain connection.

    Named for macOS because that is all it did originally. The syntax differs
    per platform and now lives in vpnctl.platform.
    """
    platform.add_host_routes(excludes, gateway)


def remove_macos_routes(excludes: list[str]) -> None:
    """Delete the routes add_macos_routes() installed.

    Safe to call when they are already gone, which is the normal case after
    an interface teardown removes them itself.
    """
    platform.remove_host_routes(excludes)


# ---------------------------------------------------------------------------
# Leak review
# ---------------------------------------------------------------------------

# Excluding these is ordinary and expected: they are the local network, and
# routing them through a tunnel would break printers, NAS boxes and the router
# itself. Excluding anything else means traffic to a public address leaving
# unprotected, which is a decision rather than housekeeping.
_PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT, which Tailscale uses
)


def public_excludes(excludes: list[str]) -> list[str]:
    """The excluded ranges that are public addresses, so leave the tunnel.

    Returned so a caller can say which ones they are rather than warning in
    general terms. A range that cannot be parsed is reported too: it is not
    doing anything useful as a route either way.
    """
    leaking: list[str] = []
    for entry in excludes:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            leaking.append(entry)
            continue
        if not any(network.subnet_of(private) for private in _PRIVATE_RANGES):
            leaking.append(entry)
    return leaking
