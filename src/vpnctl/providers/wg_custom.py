"""Self-hosted WireGuard adapter.

Disabled by default.  Enabled when the user adds an endpoint in
~/.config/vpnctl/config.toml under [providers.wireguard-custom].

Manages the tunnel via `wg-quick` (from wireguard-tools, installed via
Homebrew).  The private key lives in a user-local file with strict 0600
permissions - it is never logged or committed.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import tempfile
import time
import re
from pathlib import Path
from typing import Optional

from vpnctl.providers.base import (
    DoctorResult,
    ProgressFn,
    ProbeResult,
    ProviderAdapter,
    ProviderStatus,
)
from vpnctl.probe import run_probe
from vpnctl.transports import DirectTransport, Transport, TransportError
from vpnctl.split_tunnel import (
    add_macos_routes,
    get_default_gateway,
    remove_macos_routes,
)

_WG_QUICK = "wg-quick"
_WG = "wg"
_PROVIDER_ID = "wireguard-custom"

_CONNECT_TIMEOUT = 15
# Generous, because the first handshake also pays for DNS resolution of the
# endpoint and any retry the peer needs.
_HANDSHAKE_TIMEOUT = 25
_POLL_INTERVAL = 0.5


class WgCustomAdapter(ProviderAdapter):
    """Self-hosted WireGuard endpoint."""

    def __init__(
        self,
        endpoint: str,
        public_key: str,
        interface: str = "wgcustom",
        key_file: Optional[str] = None,
        address: str = "10.8.0.2/32",
        dns: str = "1.1.1.1",
        allowed_ips: str = "0.0.0.0/0",
        excludes: list[str] | None = None,
        provider_id: str = _PROVIDER_ID,
        mtu: Optional[int] = None,
        private_key: Optional[str] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self._endpoint = endpoint
        self._public_key = public_key
        self._interface = interface
        self._key_file = Path(key_file).expanduser() if key_file else None
        self._address = address
        self._dns = dns
        self._allowed_ips = allowed_ips
        self._excludes: list[str] = excludes or []
        self._tmp_conf: Optional[Path] = None
        self._pre_vpn_gateway: Optional[str] = None
        # Everything below here is what lets a hosted provider reuse this
        # class rather than restate the whole wg-quick lifecycle: the only
        # differences are where the parameters come from, what the tunnel is
        # called, and whether an MTU has to be pinned.
        self._provider_id = provider_id
        self._mtu = mtu
        self._private_key = private_key
        # True when the tunnel is described in the user's config file, false
        # when a subclass fetches it from a provider. Decides which of the
        # doctor checks below can say anything useful.
        self._self_configured = private_key is None
        # How the tunnel's UDP reaches the server. Direct unless the network
        # between here and there will not carry it.
        self._transport: Transport = transport or DirectTransport()
        # What wg-quick should actually dial, which is the transport's local
        # listener rather than the server when a transport is in use.
        self._dial_endpoint: Optional[str] = None
        self._transport_routes: list[str] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def _read_private_key(self) -> str:
        # A provider that obtains its key over the network holds it in memory
        # rather than pointing at a file the user manages.
        if self._private_key:
            return self._private_key
        if self._key_file is None:
            raise RuntimeError(
                f"{self._provider_id}: key_file not configured in "
                "~/.config/vpnctl/config.toml"
            )
        if not self._key_file.exists():
            raise RuntimeError(
                f"{self._provider_id}: key_file not found: {self._key_file}"
            )
        mode = stat.S_IMODE(self._key_file.stat().st_mode)
        if mode & 0o077:
            raise RuntimeError(
                f"{self._provider_id}: key_file {self._key_file} has unsafe "
                f"permissions ({oct(mode)}).  Run: chmod 600 {self._key_file}"
            )
        return self._key_file.read_text().strip()

    @property
    def dns(self) -> str:
        """The resolver this tunnel should use, for callers that set it up."""
        return self._dns

    def _build_conf(self, private_key: str, *, with_dns: bool = True) -> str:
        conf = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {self._address}\n"
        )
        if self._dns and with_dns:
            conf += f"DNS = {self._dns}\n"
        if self._mtu:
            conf += f"MTU = {self._mtu}\n"
        conf += (
            "\n"
            "[Peer]\n"
            f"PublicKey = {self._public_key}\n"
            f"AllowedIPs = {self._allowed_ips}\n"
            f"Endpoint = {self._dial_endpoint or self._endpoint}\n"
            "PersistentKeepalive = 25\n"
        )
        return conf

    def render_config(self, *, with_dns: bool = True) -> str:
        """The wg-quick config for this tunnel.

        with_dns=False is for a container: wg-quick implements DNS= by
        shelling out to resolvconf or resolvectl, and in a container neither
        works, so the whole `wg-quick up` fails with "sd_bus_open_system: No
        such file or directory" before the tunnel is ever established. The
        caller sets the resolver itself instead, and checks it separately.
        """
        return self._build_conf(self._read_private_key(), with_dns=with_dns)

    def _write_tmp_conf(self) -> Path:
        conf = self.render_config()
        tmp = Path(tempfile.gettempdir()) / f"{self._interface}.conf"
        tmp.write_text(conf)
        tmp.chmod(0o600)
        return tmp

    def _alias_name_file(self) -> Path:
        return Path("/var/run/wireguard") / f"{self._interface}.name"

    def _read_alias_name(self) -> Optional[str]:
        name_file = self._alias_name_file()
        if not name_file.exists():
            return None
        try:
            value = name_file.read_text().strip()
        except PermissionError:
            result = subprocess.run(
                ["sudo", "-n", "cat", str(name_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                return None
            value = result.stdout.strip()
        return value or None

    def _wg_show(self, interface: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [_WG, "show", interface],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 and "Permission denied" in result.stderr:
            result = subprocess.run(
                ["sudo", "-n", _WG, "show", interface],
                capture_output=True,
                text=True,
                check=False,
            )
        return result

    def _latest_handshake(self, interface: str) -> Optional[int]:
        """Seconds since the most recent handshake, or None if there has been none.

        `wg show <iface>` succeeding only means the interface exists. On a
        network that drops WireGuard, the interface comes up, the default
        route is moved onto it, and not a single packet is ever answered: the
        machine is left with no working connection while every check that
        looks at the interface reports success.
        """
        result = self._wg_show_field(interface, "latest-handshakes")
        if result is None:
            return None
        newest = 0
        for line in result.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                newest = max(newest, int(parts[1]))
        if newest == 0:
            return None
        return max(0, int(time.time()) - newest)

    def _wg_show_field(self, interface: str, field: str) -> Optional[str]:
        result = subprocess.run(
            [_WG, "show", interface, field],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 and "Permission denied" in result.stderr:
            result = subprocess.run(
                ["sudo", "-n", _WG, "show", interface, field],
                capture_output=True,
                text=True,
                check=False,
            )
        return result.stdout if result.returncode == 0 else None

    def handshake_age(self) -> Optional[int]:
        """Seconds since this tunnel last heard from its peer, if ever."""
        interface = self._resolve_real_interface()
        if interface is None:
            return None
        return self._latest_handshake(interface)

    def _resolve_real_interface(self) -> Optional[str]:
        real_interface = self._read_alias_name()
        if real_interface:
            return real_interface

        result = subprocess.run(
            [_WG, "show", "interfaces"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return None

        if self._interface in result.stdout.split():
            return self._interface
        return None

    def _cleanup_stale_mapping(self) -> None:
        real_interface = self._resolve_real_interface()
        tmp_conf = self._tmp_conf or self._write_tmp_conf()
        down_result = subprocess.run(
            ["sudo", _WG_QUICK, "down", str(tmp_conf)],
            capture_output=True,
            text=True,
            check=False,
        )
        if down_result.returncode == 0:
            return

        paths = [str(self._alias_name_file())]
        if real_interface:
            paths.append(f"/var/run/wireguard/{real_interface}.sock")
        subprocess.run(
            ["sudo", "rm", "-f", *paths],
            capture_output=True,
            text=True,
            check=False,
        )

    def prepare(self) -> None:
        missing = []
        if not shutil.which(_WG_QUICK):
            missing.append(_WG_QUICK)
        if not shutil.which(_WG):
            missing.append(_WG)
        if missing:
            raise RuntimeError(
                f"wireguard-tools not found ({', '.join(missing)}). "
                "Install: brew install wireguard-tools"
            )
        self._read_private_key()

    def connect(self) -> None:
        self.prepare()
        self._pre_vpn_gateway = get_default_gateway()

        # The transport starts first, while there is still a working default
        # route: it has to resolve and reach the server, and after wg-quick
        # runs neither DNS nor that route is available yet.
        try:
            self._dial_endpoint = self._transport.start(self._endpoint)
            self._transport_routes = self._transport.excluded_ips()
        except TransportError as exc:
            self._transport.stop()
            self._dial_endpoint = None
            raise RuntimeError(f"{self._provider_id}: {exc}") from exc

        # Pin the transport's own path outside the tunnel before the tunnel
        # claims the default route. Without this the transport's connection to
        # the server is routed into the tunnel it is carrying, and nothing
        # moves in either direction.
        if self._transport_routes and self._pre_vpn_gateway:
            add_macos_routes(self._transport_routes, self._pre_vpn_gateway)

        self._tmp_conf = self._write_tmp_conf()
        result = subprocess.run(
            ["sudo", _WG_QUICK, "up", str(self._tmp_conf)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 and re.search(
            r"already exists as", result.stderr
        ):
            self._cleanup_stale_mapping()
            result = subprocess.run(
                ["sudo", _WG_QUICK, "up", str(self._tmp_conf)],
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            self._cleanup_tmp()
            self._stop_transport()
            raise RuntimeError(
                f"wg-quick up failed: {result.stderr.strip()}"
            )
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        interface: Optional[str] = None
        while time.monotonic() < deadline:
            if self.status() == ProviderStatus.CONNECTED:
                interface = self._resolve_real_interface()
                break
            time.sleep(_POLL_INTERVAL)

        if interface is None:
            self.disconnect()
            raise RuntimeError(
                f"{self._provider_id}: timed out waiting for interface "
                f"{self._interface}"
            )

        # The interface existing is not the same as the tunnel working, and
        # the difference matters here more than anywhere else: the default
        # route has just been moved onto it. Returning success without a
        # handshake hands back a machine with no internet.
        handshake_deadline = time.monotonic() + _HANDSHAKE_TIMEOUT
        while time.monotonic() < handshake_deadline:
            if self._latest_handshake(interface) is not None:
                if self._excludes and self._pre_vpn_gateway:
                    add_macos_routes(self._excludes, self._pre_vpn_gateway)
                return
            time.sleep(_POLL_INTERVAL)

        self.disconnect()
        raise RuntimeError(
            f"{self._provider_id}: the tunnel came up but the peer never "
            f"answered, so it was torn down again and this machine is back on "
            f"its own connection.\n"
            f"Either {self._endpoint.rpartition(':')[0] or self._endpoint} is "
            f"not reachable, or this network drops WireGuard. "
            f"`vpnctl docker-smoke-test` tells them apart without touching "
            f"your routing."
        )

    def _stop_transport(self) -> None:
        """Stop the transport and remove the routes that kept it reachable."""
        if self._transport_routes:
            remove_macos_routes(self._transport_routes)
            self._transport_routes = []
        self._transport.stop()
        self._dial_endpoint = None

    def disconnect(self) -> None:
        if not shutil.which(_WG_QUICK):
            self._stop_transport()
            return
        remove_macos_routes(self._excludes)
        created_tmp_conf = False
        if self._tmp_conf is None or not self._tmp_conf.exists():
            self._tmp_conf = self._write_tmp_conf()
            created_tmp_conf = True

        if self._tmp_conf and self._tmp_conf.exists():
            subprocess.run(
                ["sudo", _WG_QUICK, "down", str(self._tmp_conf)],
                capture_output=True,
                text=True,
                check=False,
            )
            self._cleanup_tmp()
        elif created_tmp_conf:
            self._cleanup_tmp()
        self._stop_transport()
        self._pre_vpn_gateway = None

    def _cleanup_tmp(self) -> None:
        if self._tmp_conf and self._tmp_conf.exists():
            try:
                self._tmp_conf.unlink()
            except OSError:
                pass
        self._tmp_conf = None

    def status(self) -> ProviderStatus:
        if not shutil.which(_WG):
            return ProviderStatus.UNKNOWN
        real_interface = self._resolve_real_interface()
        if real_interface is None:
            return ProviderStatus.DISCONNECTED
        result = self._wg_show(real_interface)
        if result.returncode == 0:
            return ProviderStatus.CONNECTED
        return ProviderStatus.DISCONNECTED

    def probe(self, on_progress: Optional[ProgressFn] = None) -> ProbeResult:
        return run_probe(self._provider_id, on_progress)

    def doctor(self) -> DoctorResult:
        issues: list[str] = []
        hints: list[str] = []

        for tool in (_WG_QUICK, _WG):
            if not shutil.which(tool):
                issues.append(f"{tool} not found")
                hints.append("brew install wireguard-tools")
                break

        for problem in self._transport.doctor():
            issues.append(f"transport {self._transport.kind}: {problem}")

        if self._interface.startswith("utun"):
            hints.append(
                "Use a stable alias like 'wgcustom' instead of a utun name; "
                "macOS assigns real utun devices dynamically."
            )

        # The rest of these are about a tunnel the user describes in the
        # config file. A subclass that obtains its parameters from a provider
        # API has no endpoint or key_file to check and would otherwise be
        # told to go and edit the self-hosted section of its config.
        if not self._self_configured:
            return DoctorResult(
                provider_id=self._provider_id,
                ok=len(issues) == 0,
                issues=issues,
                hints=hints,
            )

        if not self._endpoint:
            issues.append("endpoint not configured")
            hints.append(
                f"Set endpoint = '1.2.3.4:51820' in "
                f"[providers.{self._provider_id}] in ~/.config/vpnctl/config.toml"
            )

        if self._key_file:
            if not self._key_file.exists():
                issues.append(f"key_file not found: {self._key_file}")
                hints.append(
                    f"Create {self._key_file} with your WireGuard private key "
                    f"then run: chmod 600 {self._key_file}"
                )
            else:
                mode = stat.S_IMODE(self._key_file.stat().st_mode)
                if mode & 0o077:
                    issues.append(
                        f"key_file has unsafe permissions: {oct(mode)}"
                    )
                    hints.append(f"chmod 600 {self._key_file}")
        else:
            issues.append("key_file not configured")
            hints.append(
                f"Set key_file = '~/.config/vpnctl/wg-custom.key' in "
                f"[providers.{self._provider_id}] in ~/.config/vpnctl/config.toml"
            )

        return DoctorResult(
            provider_id=self._provider_id,
            ok=len(issues) == 0,
            issues=issues,
            hints=hints,
        )
