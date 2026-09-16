"""Riseup and Calyx: free VPNs from nonprofits, with no account.

Both run LEAP, which publishes everything a client needs over a plain HTTP
API and hands out client certificates to anyone who asks. Riseup's own
provider.json says so: allow_anonymous true, allow_free true,
allow_registration false. There is nothing to sign up for and nothing to pay.

Two things about this shape it.

The credentials are certificates, not a username. So a client fetches a
short-lived certificate, uses it, and throws it away. Nothing about the user
is involved at any point.

And the API is often the first thing a restrictive network blocks, because it
lives on a well known hostname. Measured on one university network, the API
and all 21 gateways were unreachable while ordinary HTTPS was fine. So the
bundle is cached: fetch it once from a network that works, and the tunnel can
be brought up later from one that does not.
"""

from __future__ import annotations

import json
import os
import ssl
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from vpnctl import validate

# Both are LEAP providers with the same API. The CA is fetched from the
# provider rather than shipped, and pinned into the cached bundle.
PROVIDERS = {
    "riseup": {
        "domain": "black.riseup.net",
        "provider_url": "https://api.black.riseup.net/provider.json",
        "ca_url": "https://black.riseup.net/ca.crt",
    },
    "calyx": {
        "domain": "calyx.net",
        "provider_url": "https://api.calyx.net/provider.json",
        "ca_url": "https://calyx.net/ca.crt",
    },
}

_TIMEOUT = 30.0

# The bundle is worth re-fetching occasionally: gateways move and the client
# certificate is not meant to be long lived.
_MAX_AGE_SECONDS = 7 * 24 * 60 * 60


class RiseupError(RuntimeError):
    """The provider's API could not be used."""


@dataclass
class Gateway:
    host: str
    ip_address: str
    location: str
    # (protocol, port) pairs this gateway accepts OpenVPN on.
    openvpn: list[tuple[str, int]] = field(default_factory=list)

    def endpoint_for(self, protocol: str, port: int) -> bool:
        return (protocol, port) in self.openvpn


@dataclass
class Bundle:
    """Everything needed to connect, cached so the API is not a dependency."""

    provider: str
    ca_pem: str
    client_pem: str
    gateways: list[Gateway]
    openvpn_options: dict[str, Any]
    fetched_at: float

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.fetched_at)

    @property
    def stale(self) -> bool:
        return self.age_seconds > _MAX_AGE_SECONDS

    def locations(self) -> list[str]:
        return sorted({gateway.location for gateway in self.gateways})

    def pick(
        self,
        *,
        location: str = "",
        protocol: str = "tcp",
        port: int = 1194,
    ) -> Gateway:
        """Choose a gateway supporting this protocol and port.

        TCP by default, because the networks worth having a free VPN on are
        the ones that treat UDP differently, and Riseup offers OpenVPN over
        TCP on 53, 80 and 1194.
        """
        candidates = [g for g in self.gateways if g.endpoint_for(protocol, port)]
        if location:
            narrowed = [
                g for g in candidates if g.location.lower() == location.lower()
            ]
            if not narrowed:
                raise RiseupError(
                    f"No {self.provider} gateway in {location!r} offers "
                    f"{protocol}/{port}. Available: {', '.join(self.locations())}"
                )
            candidates = narrowed
        if not candidates:
            raise RiseupError(
                f"No {self.provider} gateway offers OpenVPN over "
                f"{protocol}/{port}."
            )
        return candidates[0]


def _parse_gateways(eip: dict[str, Any]) -> list[Gateway]:
    """Turn the provider's gateway list into checked values.

    Everything here is validated at the boundary, because the address ends up
    in the `remote` line of an OpenVPN config that runs as root, and a value
    carrying a newline would start a directive of its own. The allow-list
    that screens the provider's options table never covered this line.

    A gateway that does not validate is dropped rather than repaired. There
    are twenty of them; losing one is better than trusting it.
    """
    gateways: list[Gateway] = []
    for raw in eip.get("gateways", []):
        if not isinstance(raw, dict):
            continue
        pairs: list[tuple[str, int]] = []
        capabilities = raw.get("capabilities")
        transports = (
            capabilities.get("transport", []) if isinstance(capabilities, dict) else []
        )
        for transport in transports:
            if not isinstance(transport, dict) or transport.get("type") != "openvpn":
                continue
            for protocol in transport.get("protocols", []):
                for port in transport.get("ports", []):
                    try:
                        pairs.append(
                            (
                                validate.one_of(
                                    str(protocol), {"tcp", "udp"}, "protocol"
                                ),
                                validate.port(port, "gateway port"),
                            )
                        )
                    except validate.InvalidValue:
                        continue

        try:
            gateways.append(
                Gateway(
                    host=validate.hostname(str(raw.get("host", "")), "gateway host"),
                    ip_address=validate.ip_address(
                        str(raw.get("ip_address", "")), "gateway address"
                    ),
                    # Only ever displayed, but a newline would break the
                    # display and it costs nothing to check.
                    location=validate._no_control_characters(
                        str(raw.get("location", "")), "gateway location"
                    ),
                    openvpn=pairs,
                )
            )
        except validate.InvalidValue:
            continue
    return gateways


def fetch(provider: str = "riseup") -> Bundle:
    """Fetch the CA, the gateway list and an anonymous client certificate."""
    if provider not in PROVIDERS:
        raise RiseupError(
            f"Unknown provider {provider!r}. Available: {', '.join(PROVIDERS)}"
        )
    spec = PROVIDERS[provider]

    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            # The CA first: everything else is verified against it, and it is
            # served from the provider's ordinary web host rather than the API.
            ca_pem = client.get(spec["ca_url"]).text
            if "BEGIN CERTIFICATE" not in ca_pem:
                raise RiseupError(
                    f"{spec['ca_url']} did not return a certificate."
                )

            info = client.get(spec["provider_url"]).json()
    except httpx.HTTPError as exc:
        raise RiseupError(
            f"Could not reach {provider}: {exc}.\n"
            "Networks that block VPNs usually block this API too. Fetch the "
            "bundle from a network that works and it will be cached for later."
        ) from exc

    service = info.get("service", {})
    if not service.get("allow_anonymous", False):
        raise RiseupError(
            f"{provider} no longer allows anonymous use, so vpnctl cannot "
            "connect to it without an account."
        )

    api_uri = str(info.get("api_uri") or "").rstrip("/")
    api_version = str(info.get("api_version") or "3")
    if not api_uri:
        raise RiseupError(f"{provider}'s provider.json has no api_uri.")

    # The API is served under the provider's own CA, so it is verified
    # against the certificate fetched above rather than the system store.
    #
    # Built in memory rather than written out. This used to go to a
    # predictable path in the shared temp directory at 0644, which made the
    # trust anchor for the very connection that fetches the gateway list and
    # the client certificate writable by any local user.
    context = ssl.create_default_context(cadata=ca_pem)
    try:
        with httpx.Client(timeout=_TIMEOUT, verify=context) as client:
            eip = client.get(f"{api_uri}/{api_version}/config/eip-service.json").json()
            client_pem = client.post(f"{api_uri}/{api_version}/cert").text
    except httpx.HTTPError as exc:
        raise RiseupError(f"Could not fetch {provider}'s configuration: {exc}") from exc
    except ssl.SSLError as exc:
        raise RiseupError(
            f"{provider}'s CA did not load: {exc}"
        ) from exc

    if "BEGIN" not in client_pem:
        raise RiseupError(
            f"{provider} did not return a client certificate. It may have "
            "changed how anonymous access works."
        )

    gateways = _parse_gateways(eip)
    if not gateways:
        raise RiseupError(f"{provider} returned no usable gateways.")

    return Bundle(
        provider=provider,
        ca_pem=ca_pem,
        client_pem=client_pem,
        gateways=gateways,
        openvpn_options=dict(eip.get("openvpn_configuration") or {}),
        fetched_at=time.time(),
    )


def bundle_path(provider: str = "riseup", config_dir: Optional[Path] = None) -> Path:
    base = config_dir or (Path.home() / ".config" / "vpnctl")
    return base / f"{provider}-bundle.json"


def save(bundle: Bundle, path: Optional[Path] = None) -> Path:
    """Write the bundle at 0600: it contains a private key."""
    target = path or bundle_path(bundle.provider)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(bundle)
    payload["gateways"] = [
        {**asdict(g), "openvpn": [list(pair) for pair in g.openvpn]}
        for g in bundle.gateways
    ]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2)
    return target


def load(provider: str = "riseup", path: Optional[Path] = None) -> Optional[Bundle]:
    target = path or bundle_path(provider)
    if not target.exists():
        return None

    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        raise RiseupError(
            f"{target} holds a private key but is readable by others "
            f"({oct(mode)}). Run: chmod 600 {target}"
        )

    try:
        raw = json.loads(target.read_text())
        if not isinstance(raw, dict):
            raise TypeError(f"expected an object, got {type(raw).__name__}")
        gateways = [
            Gateway(
                host=g["host"],
                ip_address=g["ip_address"],
                location=g["location"],
                openvpn=[(p[0], int(p[1])) for p in g.get("openvpn", [])],
            )
            for g in raw.get("gateways", [])
        ]
        return Bundle(
            provider=raw["provider"],
            ca_pem=raw["ca_pem"],
            client_pem=raw["client_pem"],
            gateways=gateways,
            openvpn_options=raw.get("openvpn_options", {}),
            fetched_at=float(raw.get("fetched_at", 0.0)),
        )
    except (
        json.JSONDecodeError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise RiseupError(
            f"{target} is not a usable bundle ({exc}). Delete it and vpnctl "
            "will fetch a new one."
        ) from exc


def load_or_fetch(
    provider: str = "riseup",
    path: Optional[Path] = None,
    *,
    refresh: bool = False,
) -> Bundle:
    """The cached bundle, fetching one when absent, stale or asked for.

    A stale cache still beats no cache: if the refresh cannot be done because
    the network blocks the API, the old bundle is returned rather than
    failing, because an old gateway list usually still works.
    """
    existing = load(provider, path)
    if existing is not None and not refresh and not existing.stale:
        return existing

    try:
        fresh = fetch(provider)
    except RiseupError:
        if existing is not None:
            return existing
        raise

    save(fresh, path)
    return fresh
