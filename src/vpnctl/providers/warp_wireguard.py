"""Cloudflare WARP over plain WireGuard.

This is the provider that makes vpnctl work out of the box. WARP's free tier
takes no account and no payment, and its device API hands out ordinary
WireGuard parameters, so the tunnel is brought up by the same wg-quick that
the self-hosted provider uses. Nothing has to be installed beyond
wireguard-tools, and in particular not the Cloudflare desktop client, which
on macOS is a cask that needs an admin password before it will even land on
disk.

That is why this adapter no longer drives warp-cli. The MASQUE provider still
does, because MASQUE is Cloudflare's own transport and has no standard client.

The lifecycle is entirely WgCustomAdapter's: the only thing added here is
where the parameters come from. prepare() registers once, caches the device,
and fills them in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from vpnctl import warp
from vpnctl.providers.base import DoctorResult
from vpnctl.providers.wg_custom import WgCustomAdapter
from vpnctl.transports import Transport

_PROVIDER_ID = "warp-wireguard"

# A stable alias rather than a utun name, because macOS assigns the real
# device dynamically and the name is what status() has to find again.
_INTERFACE = "warpwg"

# 1.1.1.1 is WARP's own resolver and sits inside the tunnel, so DNS does not
# leak to whatever the local network handed out.
_DNS = "1.1.1.1"


class WarpWireguardAdapter(WgCustomAdapter):
    """Free Cloudflare WARP, registered anonymously, run over wg-quick."""

    def __init__(
        self,
        excludes: list[str] | None = None,
        device_path: Optional[Path] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        super().__init__(
            endpoint="",
            public_key="",
            interface=_INTERFACE,
            key_file=None,
            address="",
            dns=_DNS,
            allowed_ips="0.0.0.0/0",
            excludes=excludes,
            provider_id=_PROVIDER_ID,
            mtu=warp.WARP_MTU,
            transport=transport,
        )
        # The parameters arrive from Cloudflare, not from the config file, so
        # the inherited config-file checks do not apply.
        self._self_configured = False
        self._device_path = device_path
        self._device: Optional[warp.WarpDevice] = None

    def _apply(self, device: warp.WarpDevice) -> None:
        self._device = device
        self._private_key = device.private_key
        self._public_key = device.peer_public_key
        self._endpoint = device.endpoint()
        self._address = device.interface_address()

    def _load_cached(self) -> Optional[warp.WarpDevice]:
        """Use an existing registration, without making one."""
        device = warp.load(self._device_path)
        if device is not None:
            self._apply(device)
        return device

    def prepare(self) -> None:
        """Register on first use, then check the tools are present.

        Order matters: registering before the wg-quick check would make a
        network call on a machine that cannot bring a tunnel up anyway. So
        the keypair generation inside register() doubles as the check that wg
        exists, and super().prepare() covers wg-quick.
        """
        if self._device is None:
            self._apply(warp.load_or_register(self._device_path))
        super().prepare()

    def disconnect(self) -> None:
        """Tear down using the cached device, and do not register to do it.

        disconnect has to work when nothing is connected, including before
        the first registration. Reaching for the network here would turn
        "there is nothing to tear down" into an API call.
        """
        if self._device is None:
            try:
                self._load_cached()
            except warp.WarpError:
                pass
        super().disconnect()

    def doctor(self) -> DoctorResult:
        """Report readiness without registering anything.

        A dependency check that silently created an account on a third party
        service would be a surprising thing for `vpnctl doctor` to do.
        """
        try:
            cached = self._load_cached()
        except warp.WarpError as exc:
            return DoctorResult(
                provider_id=_PROVIDER_ID,
                ok=False,
                issues=[str(exc)],
                hints=[f"rm {warp.device_path()}"],
            )

        result = super().doctor()
        if cached is None:
            result.hints.append(
                "No WARP device registered yet. One is created automatically, "
                "anonymously and for free, on the first connect."
            )
        else:
            result.hints.append(
                f"WARP device registered, tunnel address {cached.address_v4}."
            )

        # WARP hands out an address inside 172.16.0.0/12, which is also a
        # range people commonly exclude from the tunnel. Worth mentioning, but
        # not a fault: the tunnel's address is a /32 on the interface itself,
        # and a /32 beats a /12 via the gateway, so the more specific route
        # wins and the tunnel still works. Only flagged so that anyone
        # debugging routing knows the overlap is there.
        overlapping = [
            exclude for exclude in self._excludes if exclude.startswith("172.16.")
        ]
        if cached is not None and overlapping:
            result.hints.append(
                f"Split tunnel excludes {', '.join(overlapping)}, which overlaps "
                f"WARP's own address {cached.address_v4}. Harmless, because the "
                "interface holds it as a /32 and the longer prefix wins."
            )

        return result
