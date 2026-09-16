"""Helpers for provisioning a self-hosted WireGuard VPS over SSH."""

from __future__ import annotations

import re
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from vpnctl.config import configure_transport, configure_wg_custom

_SSH_OPTIONS = ["-o", "StrictHostKeyChecking=accept-new"]
_REMOTE_SCRIPT = "/tmp/vpnctl-setup-server.sh"


@dataclass
class BootstrapResult:
    endpoint: str
    server_public_key: str
    key_file: Path
    config_file: Path


def _require_tool(tool: str, install_hint: str) -> None:
    if shutil.which(tool):
        return
    raise RuntimeError(f"{tool} not found. Install it first: {install_hint}")


def _ensure_prereqs() -> None:
    _require_tool("ssh", "xcode-select --install")
    _require_tool("scp", "xcode-select --install")
    _require_tool("wg", "brew install wireguard-tools")


def _find_setup_script() -> Path:
    candidates = [
        Path.cwd() / "setup_server.sh",
        Path(__file__).resolve().parents[2] / "setup_server.sh",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError(
        "setup_server.sh not found. Run vpnctl from the repo root or keep "
        "setup_server.sh next to your working directory."
    )


def _ensure_private_key(path: Path) -> Path:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            path.chmod(0o600)
        return path

    result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True,
        text=True,
        check=True,
    )
    private_key = result.stdout.strip()
    if not private_key:
        raise RuntimeError("wg genkey returned an empty private key")

    path.write_text(f"{private_key}\n")
    path.chmod(0o600)
    return path


def _derive_public_key(private_key_path: Path) -> str:
    private_key = private_key_path.read_text().strip()
    result = subprocess.run(
        ["wg", "pubkey"],
        input=f"{private_key}\n",
        capture_output=True,
        text=True,
        check=True,
    )
    public_key = result.stdout.strip()
    if not public_key:
        raise RuntimeError("wg pubkey returned an empty public key")
    return public_key


def _scp_script(identity_file: Path, ssh_target: str, local_script: Path) -> None:
    subprocess.run(
        [
            "scp",
            *_SSH_OPTIONS,
            "-i",
            str(identity_file),
            str(local_script),
            f"{ssh_target}:{_REMOTE_SCRIPT}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )


def _run_remote_setup(
    identity_file: Path,
    ssh_target: str,
    client_public_key: str,
    port: int,
    with_wstunnel: bool = False,
) -> tuple[str, str]:
    remote_cmd = " ".join(
        [
            "bash",
            shlex.quote(_REMOTE_SCRIPT),
            shlex.quote(client_public_key),
            shlex.quote(str(port)),
            shlex.quote("yes" if with_wstunnel else "no"),
        ]
    )
    result = subprocess.run(
        [
            "ssh",
            *_SSH_OPTIONS,
            "-i",
            str(identity_file),
            ssh_target,
            remote_cmd,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    server_public_key = ""
    server_endpoint = ""
    for line in result.stdout.splitlines():
        pubkey_match = re.match(r"^SERVER_PUBKEY=(.+)$", line.strip())
        endpoint_match = re.match(r"^SERVER_ENDPOINT=(.+)$", line.strip())
        if pubkey_match:
            server_public_key = pubkey_match.group(1).strip()
        if endpoint_match:
            server_endpoint = endpoint_match.group(1).strip()

    if not server_public_key:
        raise RuntimeError(
            "Remote setup did not return SERVER_PUBKEY.\n"
            f"Remote stdout:\n{result.stdout}\nRemote stderr:\n{result.stderr}"
        )

    return server_public_key, server_endpoint


def bootstrap_wireguard_vps(
    *,
    ssh_target: str,
    identity_file: str,
    endpoint_host: str | None = None,
    port: int = 51820,
    key_file: str = "~/.config/vpnctl/wg-custom.key",
    with_wstunnel: bool = False,
) -> BootstrapResult:
    """Provision the VPS and wire the local client config without connecting.

    with_wstunnel also installs the relay that carries the tunnel over TCP
    443, and points the local transport at it. That is what makes the server
    usable from a network which drops WireGuard but carries HTTPS.
    """
    _ensure_prereqs()

    identity_path = Path(identity_file).expanduser()
    if not identity_path.exists():
        raise RuntimeError(f"SSH identity file not found: {identity_path}")

    local_script = _find_setup_script()

    key_path = _ensure_private_key(Path(key_file))
    client_public_key = _derive_public_key(key_path)

    _scp_script(identity_path, ssh_target, local_script)
    server_public_key, server_endpoint = _run_remote_setup(
        identity_path,
        ssh_target,
        client_public_key,
        port,
        with_wstunnel=with_wstunnel,
    )

    if endpoint_host:
        endpoint = f"{endpoint_host}:{port}"
    elif server_endpoint:
        endpoint = server_endpoint
    else:
        endpoint = f"{ssh_target.split('@')[-1]}:{port}"

    config_file = configure_wg_custom(
        endpoint=endpoint,
        public_key=server_public_key,
        key_file=str(key_path),
    )

    if with_wstunnel:
        # The relay listens on the same host, so the transport's server is
        # that host on 443 while WireGuard keeps dialling its own port
        # through it.
        configure_transport(
            kind="wstunnel",
            server=f"wss://{endpoint.rpartition(':')[0]}:443",
            local_port=port,
        )

    return BootstrapResult(
        endpoint=endpoint,
        server_public_key=server_public_key,
        key_file=key_path,
        config_file=config_file,
    )
