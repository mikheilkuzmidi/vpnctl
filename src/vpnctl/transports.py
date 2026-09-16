"""Carrying a tunnel through a network that blocks tunnels.

A restrictive network does not usually block WireGuard by understanding it.
It blocks a list of destinations, and kills TLS connections to them just
after the client hello. Measured on one university network: arbitrary
outbound UDP was fine (STUN answered on 19302 and 3478), TCP 22 and 443 to
ordinary hosts were fine, and every known VPN endpoint was silently
unreachable, including a Tor relay and all 21 of Riseup's gateways.

So getting out is not about disguising WireGuard's packets. It is about
sending them somewhere nobody has blacklisted, in a shape the network
already carries. A transport does that: it accepts the tunnel's UDP on
localhost and relays it to the server over something ordinary.

    WireGuard  ->  127.0.0.1:51820  ->  wstunnel  ->  TLS 443  ->  server

One consequence is easy to miss and breaks everything when missed. Once the
tunnel is up with AllowedIPs 0.0.0.0/0, the default route belongs to the
tunnel, so the transport's own connection to the server would be routed into
the tunnel it is carrying. Every transport therefore declares the addresses
that must stay off the tunnel, and the adapter pins host routes for them
before handing over the default route.
"""

from __future__ import annotations

import abc
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

_STARTUP_TIMEOUT = 8.0
_POLL = 0.15


class TransportError(RuntimeError):
    """The transport could not be started."""


class Transport(abc.ABC):
    """Somewhere for a tunnel's UDP to go other than straight out."""

    @property
    @abc.abstractmethod
    def kind(self) -> str:
        """Stable identifier, as written in the config."""

    @abc.abstractmethod
    def start(self, endpoint: str) -> str:
        """Begin carrying traffic for endpoint, and return what to dial instead.

        endpoint is "host:port" as the provider would otherwise have used.
        """

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop carrying traffic. Must not raise if already stopped."""

    def excluded_ips(self) -> list[str]:
        """Addresses that must not be routed into the tunnel.

        The transport's own path to the server, which would otherwise be
        carried by the tunnel it is establishing.
        """
        return []

    def doctor(self) -> list[str]:
        """Problems preventing this transport from working, if any."""
        return []


class DirectTransport(Transport):
    """No transport at all: dial the server straight out."""

    @property
    def kind(self) -> str:
        return "direct"

    def start(self, endpoint: str) -> str:
        return endpoint

    def stop(self) -> None:
        return None


@dataclass
class WstunnelSettings:
    """Where the wstunnel server is and how to talk to it."""

    server: str = ""
    local_port: int = 51820
    # Sent as the TLS server name. Overriding it is the difference between a
    # connection that looks like it is going to a VPN and one that looks like
    # any other HTTPS request.
    sni: str = ""
    path_prefix: str = ""
    credentials: str = ""
    verify_certificate: bool = False


class WstunnelTransport(Transport):
    """WireGuard's UDP inside a WebSocket over TLS, normally on port 443.

    wstunnel is the relay on both ends. It is a single static binary on the
    client and a single process on the server, and the traffic it produces is
    an HTTPS connection to whatever host is running it, which is the property
    that matters.
    """

    def __init__(self, settings: WstunnelSettings) -> None:
        self._settings = settings
        self._process: Optional[subprocess.Popen] = None
        self._server_host = urlparse(settings.server).hostname or ""

    @property
    def kind(self) -> str:
        return "wstunnel"

    def _binary(self) -> str:
        found = shutil.which("wstunnel")
        if not found:
            raise TransportError(
                "wstunnel not found. Install: brew install wstunnel\n"
                "The same binary runs on the server: see "
                "`vpnctl bootstrap-wireguard-vps --with-wstunnel`."
            )
        return found

    def excluded_ips(self) -> list[str]:
        """The server's address, resolved, as host routes.

        Resolved here rather than left as a hostname because the exclusion is
        installed as a route, and a route needs an address. Resolution has to
        happen before the tunnel takes over the default route, since after
        that DNS goes through the tunnel that does not work yet.
        """
        if not self._server_host:
            return []
        try:
            infos = socket.getaddrinfo(self._server_host, None, socket.AF_INET)
        except socket.gaierror as exc:
            raise TransportError(
                f"Could not resolve the wstunnel server {self._server_host}: {exc}"
            ) from exc
        return sorted({f"{info[4][0]}/32" for info in infos})

    def start(self, endpoint: str) -> str:
        if not self._settings.server:
            raise TransportError(
                "transport.server is not set. It is the wstunnel server's URL, "
                "for example wss://vpn.example.com:443"
            )

        host, _, port = endpoint.rpartition(":")
        if not port.isdigit():
            raise TransportError(f"Cannot carry {endpoint!r}: it has no port")

        local_port = self._settings.local_port
        args = [
            self._binary(),
            "client",
            # Listen for the tunnel's UDP on localhost and hand it to the
            # server, which forwards it to the real WireGuard port.
            "-L",
            f"udp://127.0.0.1:{local_port}:{host}:{port}",
        ]
        if self._settings.sni:
            args += ["--tls-sni-override", self._settings.sni]
        if self._settings.path_prefix:
            args += ["-P", self._settings.path_prefix]
        if self._settings.credentials:
            args += ["--http-upgrade-credentials", self._settings.credentials]
        if self._settings.verify_certificate:
            args += ["--tls-verify-certificate"]
        args.append(self._settings.server)

        self._process = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        local = f"127.0.0.1:{local_port}"
        self._await_listener(local_port)
        return local

    def _await_listener(self, port: int) -> None:
        """Wait until the local UDP port is actually bound.

        Returning before then would have wg-quick dial a port nothing is
        listening on, which presents as a tunnel that comes up and never
        hands shakes: the same symptom as a blocked network, from a different
        cause, which is worth not confusing.
        """
        deadline = time.monotonic() + _STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._process and self._process.poll() is not None:
                stderr = ""
                if self._process.stderr:
                    stderr = self._process.stderr.read()[:500]
                raise TransportError(
                    f"wstunnel exited immediately (code "
                    f"{self._process.returncode}).\n{stderr}"
                )
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                # Something holds the port, which is wstunnel having started.
                return
            finally:
                probe.close()
            time.sleep(_POLL)

        self.stop()
        raise TransportError(
            f"wstunnel did not start listening on 127.0.0.1:{port} within "
            f"{_STARTUP_TIMEOUT:.0f}s"
        )

    def stop(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def doctor(self) -> list[str]:
        issues: list[str] = []
        if not shutil.which("wstunnel"):
            issues.append("wstunnel not found (brew install wstunnel)")
        if not self._settings.server:
            issues.append("transport.server not set")
        elif not self._settings.server.startswith(("ws://", "wss://", "http://", "https://")):
            issues.append(
                f"transport.server should be a URL like wss://host:443, "
                f"got {self._settings.server!r}"
            )
        return issues


def build_transport(kind: str, settings: WstunnelSettings) -> Transport:
    """The transport named in the config."""
    if kind in ("", "direct", "none"):
        return DirectTransport()
    if kind == "wstunnel":
        return WstunnelTransport(settings)
    raise TransportError(
        f"Unknown transport {kind!r}. Available: direct, wstunnel"
    )
