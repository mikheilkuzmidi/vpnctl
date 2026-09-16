"""Provider adapters package.

Only the contract is re-exported here, deliberately.

Importing the adapters in this module made the package import them whenever
anything imported anything from it, including vpnctl.probe importing
ProbeResult from .base. Every adapter imports run_probe from vpnctl.probe, so
`import vpnctl.probe` in a fresh interpreter walked probe -> providers ->
warp_masque -> probe and failed on a partially initialised module. It only
ever worked because something else usually imported an adapter first.

Adapters are imported by their own module path: see vpnctl.selector.
"""

from vpnctl.providers.base import (
    DoctorResult,
    ProbeResult,
    ProgressFn,
    ProviderAdapter,
    ProviderStatus,
)

__all__ = [
    "DoctorResult",
    "ProbeResult",
    "ProgressFn",
    "ProviderAdapter",
    "ProviderStatus",
]
