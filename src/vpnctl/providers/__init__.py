"""Provider adapters package."""

from vpnctl.providers.base import ProviderAdapter, ProviderStatus, ProbeResult
from vpnctl.providers.warp_masque import WarpMasqueAdapter
from vpnctl.providers.warp_wireguard import WarpWireguardAdapter
from vpnctl.providers.wg_custom import WgCustomAdapter

__all__ = [
    "ProviderAdapter",
    "ProviderStatus",
    "ProbeResult",
    "WarpMasqueAdapter",
    "WarpWireguardAdapter",
    "WgCustomAdapter",
]
