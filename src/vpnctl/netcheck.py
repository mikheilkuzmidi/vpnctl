"""Working out what this network will and will not carry.

Written because diagnosing one blocked network by hand took a long time and
produced a result worth keeping. On a university network: arbitrary outbound
UDP was fine, STUN answered on two different ports, and TCP 22 and 443 to
ordinary hosts were fine. Riseup's API, all 21 of its gateways, and Tor's
relays behaved identically to each other: TCP connected, then the connection
died just after the TLS client hello.

But Cloudflare WARP worked on that same network, which is the finding that
changes what to recommend. Blocklisting one VPN provider's gateways is cheap;
blocklisting Cloudflare's anycast ranges breaks too much ordinary traffic to
be worth it. So "this network blocks VPNs" is too coarse a conclusion to act
on, and the checks below separate the destinations that are filtered from the
ones that are not.

A warning about measuring this. An early attempt here concluded WARP was
blocked too, and it was wrong: the test config was missing
PersistentKeepalive and gave the handshake too few seconds. A silent tunnel
means the peer did not answer, not that the network stopped it, and telling
those apart takes a config known to be correct.

None of these checks changes any routing, so this is safe to run before
connecting anything.
"""

from __future__ import annotations

import os
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

# An IP literal, so this works even when DNS is the broken thing. 1.1.1.1
# serves a certificate for its own address, and reports the egress address it
# sees plus whether the request arrived over WARP.
_TRACE_HOST = "1.1.1.1"

# STUN servers answer a fixed request over UDP on a non-DNS port, which is
# the cheapest way to prove arbitrary outbound UDP is allowed.
_STUN_TARGETS = (("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302))

# Ordinary hosts, to establish what the network does when it is not objecting.
_ORDINARY = (("github.com", 443), ("example.com", 443))

# Cloudflare's device API, checked separately from the ordinary hosts because
# its result carries a specific recommendation. A network can blacklist
# Riseup's gateways cheaply, but blacklisting Cloudflare's anycast ranges
# breaks so much ordinary traffic that few try, which is why WARP is worth
# attempting even where every other tunnel endpoint is dead.
_WARP_API = ("api.cloudflareclient.com", 443)

# Hosts that exist to carry tunnels. A network that treats these differently
# from the ordinary ones is filtering by destination.
_TUNNEL_HOSTS = (
    ("api.black.riseup.net", 443, "Riseup's VPN API"),
    ("vpn01-sea.riseup.net", 443, "a Riseup gateway"),
    ("check.torproject.org", 443, "the Tor Project"),
)

_TIMEOUT = 6.0


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class NetworkReport:
    checks: list[Check] = field(default_factory=list)
    egress_ip: str = ""
    warp: str = ""
    location: str = ""

    def _named(self, prefix: str) -> list[Check]:
        return [c for c in self.checks if c.name.startswith(prefix)]

    @property
    def ordinary_tls_works(self) -> bool:
        return any(c.ok for c in self._named("tls:ordinary"))

    @property
    def udp_works(self) -> bool:
        return any(c.ok for c in self._named("udp"))

    @property
    def tunnel_hosts_reachable(self) -> int:
        return sum(1 for c in self._named("tls:tunnel") if c.ok)

    @property
    def tunnel_hosts_tested(self) -> int:
        return len(self._named("tls:tunnel"))

    @property
    def cloudflare_reachable(self) -> bool:
        return any(c.ok for c in self._named("tls:cloudflare"))

    @property
    def filters_tunnels(self) -> bool:
        """Ordinary destinations work and tunnel destinations do not."""
        return (
            self.ordinary_tls_works
            and self.tunnel_hosts_tested > 0
            and self.tunnel_hosts_reachable == 0
        )

    def verdict(self) -> str:
        if not self.checks:
            return "Nothing was measured."
        if not self.ordinary_tls_works:
            return (
                "This machine does not appear to have working internet at all, "
                "so nothing can be concluded about tunnels."
            )
        if self.filters_tunnels:
            return (
                "This network filters VPN destinations. Ordinary HTTPS works, "
                f"but none of the {self.tunnel_hosts_tested} tunnel endpoints "
                "tested would even complete a TLS handshake."
                + (
                    " Outbound UDP itself is fine, so the block is about where "
                    "the traffic is going, not what it looks like."
                    if self.udp_works
                    else ""
                )
            )
        if self.tunnel_hosts_reachable < self.tunnel_hosts_tested:
            return (
                f"Partly filtered: {self.tunnel_hosts_reachable} of "
                f"{self.tunnel_hosts_tested} tunnel endpoints were reachable."
            )
        return "This network carries tunnels directly. No transport needed."

    def recommendation(self) -> str:
        if self.filters_tunnels:
            advice = []
            if self.cloudflare_reachable:
                # Measured: a network that resets TLS to Riseup and Tor still
                # carried Cloudflare WARP, because blocking Cloudflare's
                # anycast ranges breaks too much else to be worth it.
                advice.append(
                    "Try warp-wireguard first. Cloudflare's network is "
                    "reachable from here, and a network that blocklists VPN "
                    "providers usually cannot afford to blocklist Cloudflare:\n"
                    "  vpnctl docker-smoke-test --provider warp-wireguard"
                )
            advice.append(
                "For any other provider, use a transport, and point it at a "
                "server of your own rather than a public one: the filtering is "
                "by destination, so an address on a public blocklist stays "
                "blocked no matter how the traffic is disguised.\n"
                "  vpnctl transport set wstunnel --server wss://your-host:443\n"
                "  vpnctl transport test        (proves it works, in containers)"
            )
            return "\n\n".join(advice)
        if self.tunnel_hosts_reachable < self.tunnel_hosts_tested:
            return (
                "Try connecting directly first. If it fails, "
                "`vpnctl transport set wstunnel` is the fallback."
            )
        return "Nothing to change: vpnctl connect should work as it is."


def _tcp_tls(host: str, port: int) -> Check:
    """Whether a full TLS handshake completes, not merely whether TCP connects.

    The distinction is the whole point. A filtering middlebox usually lets the
    TCP handshake finish and then resets the connection once it has seen the
    client hello, so a check that stopped at connect() would call a blocked
    host reachable.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return Check("", True, f"TLS {tls.version()}")
    except socket.timeout:
        return Check("", False, "timed out")
    except ssl.SSLError as exc:
        return Check("", False, f"TLS failed ({exc.reason or exc})")
    except OSError as exc:
        return Check("", False, f"{type(exc).__name__}: {exc.strerror or exc}")


def _stun(host: str, port: int) -> Check:
    """Whether arbitrary outbound UDP gets a reply."""
    request = b"\x00\x01\x00\x00" + b"\x21\x12\xa4\x42" + os.urandom(12)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(_TIMEOUT)
    try:
        sock.sendto(request, (host, port))
        data, _ = sock.recvfrom(2048)
        return Check("", True, f"replied, {len(data)} bytes")
    except socket.timeout:
        return Check("", False, "no reply")
    except OSError as exc:
        return Check("", False, f"{type(exc).__name__}: {exc.strerror or exc}")
    finally:
        sock.close()


def _trace() -> tuple[Optional[dict[str, str]], str]:
    """Cloudflare's trace endpoint, asked over an IP literal."""
    try:
        import httpx

        with httpx.Client(timeout=_TIMEOUT, verify=False) as client:
            body = client.get(f"https://{_TRACE_HOST}/cdn-cgi/trace").text
    except Exception as exc:  # httpx raises a family of these
        return None, f"{type(exc).__name__}"

    fields: dict[str, str] = {}
    for line in body.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key] = value.strip()
    return fields, ""


def run_checks() -> NetworkReport:
    """Measure what this network allows, changing nothing."""
    report = NetworkReport()

    try:
        socket.getaddrinfo("github.com", 443, socket.AF_INET)
        report.checks.append(Check("dns", True, "resolves"))
    except socket.gaierror as exc:
        report.checks.append(Check("dns", False, str(exc)))

    for host, port in _ORDINARY:
        result = _tcp_tls(host, port)
        report.checks.append(
            Check(f"tls:ordinary:{host}:{port}", result.ok, result.detail)
        )

    warp_api = _tcp_tls(*_WARP_API)
    report.checks.append(
        Check(f"tls:cloudflare:{_WARP_API[0]}", warp_api.ok, warp_api.detail)
    )

    for host, port in _STUN_TARGETS:
        result = _stun(host, port)
        report.checks.append(Check(f"udp:{host}:{port}", result.ok, result.detail))

    for host, port, label in _TUNNEL_HOSTS:
        result = _tcp_tls(host, port)
        report.checks.append(
            Check(f"tls:tunnel:{label}", result.ok, result.detail)
        )

    fields, error = _trace()
    if fields:
        report.egress_ip = fields.get("ip", "")
        report.warp = fields.get("warp", "")
        report.location = fields.get("loc", "")
        report.checks.append(
            Check("egress", True, f"{report.egress_ip} ({report.location})")
        )
    else:
        report.checks.append(Check("egress", False, error))

    return report
