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
from vpnctl.split_tunnel import (
    add_macos_routes,
    get_default_gateway,
    remove_macos_routes,
)

_WG_QUICK = "wg-quick"
_WG = "wg"
_PROVIDER_ID = "wireguard-custom"

_CONNECT_TIMEOUT = 15
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

    @property
    def provider_id(self) -> str:
        return _PROVIDER_ID

    def _read_private_key(self) -> str:
        if self._key_file is None:
            raise RuntimeError(
                "wireguard-custom: key_file not configured in "
                "~/.config/vpnctl/config.toml"
            )
        if not self._key_file.exists():
            raise RuntimeError(
                f"wireguard-custom: key_file not found: {self._key_file}"
            )
        mode = stat.S_IMODE(self._key_file.stat().st_mode)
        if mode & 0o077:
            raise RuntimeError(
                f"wireguard-custom: key_file {self._key_file} has unsafe "
                f"permissions ({oct(mode)}).  Run: chmod 600 {self._key_file}"
            )
        return self._key_file.read_text().strip()

    def _build_conf(self, private_key: str) -> str:
        conf = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {self._address}\n"
        )
        if self._dns:
            conf += f"DNS = {self._dns}\n"
        conf += (
            "\n"
            "[Peer]\n"
            f"PublicKey = {self._public_key}\n"
            f"AllowedIPs = {self._allowed_ips}\n"
            f"Endpoint = {self._endpoint}\n"
            "PersistentKeepalive = 25\n"
        )
        return conf

    def render_config(self) -> str:
        return self._build_conf(self._read_private_key())

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
            raise RuntimeError(
                f"wg-quick up failed: {result.stderr.strip()}"
            )
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            if self.status() == ProviderStatus.CONNECTED:
                if self._excludes and self._pre_vpn_gateway:
                    add_macos_routes(self._excludes, self._pre_vpn_gateway)
                return
            time.sleep(_POLL_INTERVAL)
        self.disconnect()
        raise RuntimeError(
            f"{_PROVIDER_ID}: timed out waiting for interface {self._interface}"
        )

    def disconnect(self) -> None:
        if not shutil.which(_WG_QUICK):
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
        return run_probe(_PROVIDER_ID, on_progress)

    def doctor(self) -> DoctorResult:
        issues: list[str] = []
        hints: list[str] = []

        for tool in (_WG_QUICK, _WG):
            if not shutil.which(tool):
                issues.append(f"{tool} not found")
                hints.append("brew install wireguard-tools")
                break

        if self._interface.startswith("utun"):
            hints.append(
                "Use a stable alias like 'wgcustom' instead of a utun name; "
                "macOS assigns real utun devices dynamically."
            )

        if not self._endpoint:
            issues.append("endpoint not configured")
            hints.append(
                "Set endpoint = '1.2.3.4:51820' in "
                "[providers.wireguard-custom] in ~/.config/vpnctl/config.toml"
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
                "Set key_file = '~/.config/vpnctl/wg-custom.key' in "
                "[providers.wireguard-custom] in ~/.config/vpnctl/config.toml"
            )

        return DoctorResult(
            provider_id=_PROVIDER_ID,
            ok=len(issues) == 0,
            issues=issues,
            hints=hints,
        )
