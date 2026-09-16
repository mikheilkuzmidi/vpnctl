"""A free nonprofit VPN, over OpenVPN.

Riseup and Calyx are the free-and-anonymous options that are not a single
large company. They speak OpenVPN rather than WireGuard, which turns out to
be an advantage on a restrictive network: they offer TCP on 53, 80 and 1194,
and a network that drops UDP tunnels often carries TCP on a port it already
expects to see traffic on.

OpenVPN is driven as a child process rather than through its management
interface. It needs root to create the tun device, the same as wg-quick, so
connect() runs it under sudo and the password prompt belongs to the user.
Readiness is taken from OpenVPN's own "Initialization Sequence Completed",
which it prints once the tunnel is genuinely usable: polling the interface
instead would report success while the TLS handshake was still in progress.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from vpnctl import riseup
from vpnctl.platform import sudo_prefix
from vpnctl.probe import run_probe
from vpnctl.providers.base import (
    DoctorResult,
    ProbeResult,
    ProgressFn,
    ProviderAdapter,
    ProviderStatus,
)

_OPENVPN = "openvpn"

# Homebrew puts openvpn in sbin, which is not on a normal user's PATH, so
# shutil.which reports it missing on a machine where it is installed.
_EXTRA_BIN_DIRS = ("/opt/homebrew/sbin", "/usr/local/sbin", "/usr/sbin")

_CONNECT_TIMEOUT = 60
_POLL_INTERVAL = 0.5

_READY = "Initialization Sequence Completed"

# Options from the provider that are safe to pass through. Anything else in
# eip-service.json is ignored rather than trusted: the config is fetched over
# the network, and it ends up as arguments to a process running as root.
_ALLOWED_OPTIONS = frozenset(
    {
        "auth",
        "cipher",
        "data-ciphers",
        "dev",
        "float",
        "keepalive",
        "key-direction",
        "nobind",
        "persist-key",
        "persist-tun",
        "rcvbuf",
        "sndbuf",
        "tls-cipher",
        "tls-version-min",
        "verb",
    }
)

_OPTION_VALUE = re.compile(r"^[A-Za-z0-9 ._:\-]*$")


def find_openvpn() -> Optional[str]:
    """openvpn's path, looking where Homebrew puts it as well as on PATH."""
    found = shutil.which(_OPENVPN)
    if found:
        return found
    for directory in _EXTRA_BIN_DIRS:
        candidate = Path(directory) / _OPENVPN
        if candidate.is_file():
            return str(candidate)
    return None


class RiseupAdapter(ProviderAdapter):
    """Free nonprofit VPN over OpenVPN, no account and no payment."""

    def __init__(
        self,
        provider: str = "riseup",
        *,
        location: str = "",
        protocol: str = "tcp",
        port: int = 1194,
        bundle_path: Optional[Path] = None,
    ) -> None:
        self._provider = provider
        self._location = location
        self._protocol = protocol
        self._port = port
        self._bundle_path = bundle_path
        self._bundle: Optional[riseup.Bundle] = None
        self._process: Optional[subprocess.Popen] = None
        self._workdir: Optional[tempfile.TemporaryDirectory] = None

    @property
    def provider_id(self) -> str:
        return self._provider

    # -- config ----------------------------------------------------------

    def _render_options(self, options: dict) -> str:
        lines: list[str] = []
        for key, value in sorted(options.items()):
            if key not in _ALLOWED_OPTIONS:
                continue
            if value is True or value == "":
                lines.append(key)
                continue
            if value is False:
                continue
            text = str(value)
            # The provider's config arrives over the network and becomes
            # arguments to a root process, so anything unexpected is dropped
            # rather than escaped.
            if not _OPTION_VALUE.match(text):
                continue
            lines.append(f"{key} {text}")
        return "\n".join(lines)

    def render_config(self) -> str:
        """The OpenVPN config for the chosen gateway, certificates inline."""
        bundle = self._require_bundle()
        gateway = bundle.pick(
            location=self._location, protocol=self._protocol, port=self._port
        )

        # The client certificate and key arrive in one PEM blob; OpenVPN wants
        # them in separate inline blocks.
        cert = _extract(bundle.client_pem, "CERTIFICATE")
        key = _extract_key(bundle.client_pem)
        if not cert or not key:
            raise RuntimeError(
                f"{self._provider}: the client credential does not contain "
                "both a certificate and a key."
            )

        return "\n".join(
            [
                "client",
                f"remote {gateway.ip_address} {self._port} {self._protocol}",
                "resolv-retry infinite",
                "remote-cert-tls server",
                # Push the default route through the tunnel, which is the
                # whole point, and take the provider's DNS with it so
                # resolution does not leak to the local network.
                "redirect-gateway def1",
                "script-security 0",
                "verify-x509-name server name-prefix",
                self._render_options(bundle.openvpn_options),
                "",
                "<ca>",
                bundle.ca_pem.strip(),
                "</ca>",
                "<cert>",
                cert.strip(),
                "</cert>",
                "<key>",
                key.strip(),
                "</key>",
                "",
            ]
        )

    def _require_bundle(self) -> riseup.Bundle:
        if self._bundle is None:
            raise RuntimeError(
                f"{self._provider}: prepare() has not run, so there is no "
                "configuration to use."
            )
        return self._bundle

    # -- lifecycle -------------------------------------------------------

    def prepare(self) -> None:
        if find_openvpn() is None:
            raise RuntimeError(
                "openvpn not found. Install: brew install openvpn\n"
                "If it is installed, Homebrew keeps it in sbin, which may not "
                "be on your PATH."
            )
        if self._bundle is None:
            self._bundle = riseup.load_or_fetch(self._provider, self._bundle_path)

    def connect(self) -> None:
        self.prepare()
        config = self.render_config()

        self._workdir = tempfile.TemporaryDirectory(prefix="vpnctl-openvpn-")
        config_path = Path(self._workdir.name) / f"{self._provider}.conf"
        config_path.write_text(config)
        config_path.chmod(0o600)

        binary = find_openvpn() or _OPENVPN
        self._process = subprocess.Popen(
            [*sudo_prefix(), binary, "--config", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        deadline = time.monotonic() + _CONNECT_TIMEOUT
        transcript: list[str] = []
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                remaining = self._process.stdout.read() if self._process.stdout else ""
                transcript.append(remaining)
                self._cleanup()
                raise RuntimeError(
                    f"{self._provider}: openvpn exited before connecting.\n"
                    + "".join(transcript)[-1500:]
                )
            line = self._process.stdout.readline() if self._process.stdout else ""
            if line:
                transcript.append(line)
                if _READY in line:
                    return
                continue
            time.sleep(_POLL_INTERVAL)

        self.disconnect()
        raise RuntimeError(
            f"{self._provider}: openvpn did not finish connecting within "
            f"{_CONNECT_TIMEOUT}s.\n" + "".join(transcript)[-1500:]
        )

    def _cleanup(self) -> None:
        if self._workdir is not None:
            self._workdir.cleanup()
            self._workdir = None
        self._process = None

    def disconnect(self) -> None:
        if self._process is None:
            self._cleanup()
            return
        if self._process.poll() is None:
            # openvpn runs under sudo, so the child this process can see is
            # sudo itself: terminating it does not reach openvpn. Ask sudo to
            # do the killing.
            subprocess.run(
                [*sudo_prefix(), "pkill", "-TERM", "-f", f"openvpn --config .*{self._provider}"],
                capture_output=True,
                text=True,
                check=False,
            )
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._cleanup()

    def status(self) -> ProviderStatus:
        if self._process is None:
            return ProviderStatus.DISCONNECTED
        if self._process.poll() is None:
            return ProviderStatus.CONNECTED
        return ProviderStatus.DISCONNECTED

    def probe(self, on_progress: Optional[ProgressFn] = None) -> ProbeResult:
        return run_probe(self._provider, on_progress)

    def doctor(self) -> DoctorResult:
        issues: list[str] = []
        hints: list[str] = []

        if find_openvpn() is None:
            issues.append("openvpn not found")
            hints.append("brew install openvpn")

        try:
            bundle = riseup.load(self._provider, self._bundle_path)
        except riseup.RiseupError as exc:
            issues.append(str(exc))
            bundle = None

        if bundle is None:
            hints.append(
                f"No {self._provider} configuration cached yet. It is fetched "
                "automatically, anonymously and for free, on the first "
                "connect. Do it from a network that is not blocking the "
                "provider, and it will be reused afterwards."
            )
        else:
            age_days = bundle.age_seconds / 86400
            hints.append(
                f"{len(bundle.gateways)} gateways cached "
                f"({', '.join(bundle.locations())}), {age_days:.0f} days old."
            )
            try:
                gateway = bundle.pick(
                    location=self._location,
                    protocol=self._protocol,
                    port=self._port,
                )
                hints.append(
                    f"Would use {gateway.host} in {gateway.location} over "
                    f"{self._protocol}/{self._port}."
                )
            except riseup.RiseupError as exc:
                issues.append(str(exc))

        return DoctorResult(
            provider_id=self._provider,
            ok=len(issues) == 0,
            issues=issues,
            hints=hints,
        )


def _extract(pem: str, label: str) -> str:
    """The first PEM block with this label."""
    match = re.search(
        rf"-----BEGIN {label}-----.*?-----END {label}-----", pem, re.DOTALL
    )
    return match.group(0) if match else ""


def _extract_key(pem: str) -> str:
    """The private key block, whatever flavour of header it carries."""
    for label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"):
        block = _extract(pem, label)
        if block:
            return block
    return ""
