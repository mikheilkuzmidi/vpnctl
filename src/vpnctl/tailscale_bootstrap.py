"""SSH helpers for provisioning a Tailscale exit node on a VPS."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=30",
]
_REMOTE_SCRIPT = "/tmp/vpnctl-setup-tailscale.sh"
_MARKER = "===VPNCTL==="


@dataclass
class TailscaleBootstrapResult:
    hostname: str
    tailscale_ip: str
    auth_url: str
    status: str
    needs_approval: bool


def _require_tool(tool: str, install_hint: str) -> None:
    if shutil.which(tool):
        return
    raise RuntimeError(f"{tool} not found. Install it first: {install_hint}")


def _ensure_prereqs() -> None:
    _require_tool("ssh", "xcode-select --install")
    _require_tool("scp", "xcode-select --install")


def _find_setup_script() -> Path:
    candidates = [
        Path.cwd() / "setup_tailscale_exit_node.sh",
        Path(__file__).resolve().parents[2] / "setup_tailscale_exit_node.sh",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError(
        "setup_tailscale_exit_node.sh not found. "
        "Run vpnctl from the repo root or keep the script in the working directory."
    )


def _scp_script(identity_file: Path, ssh_target: str, local_script: Path) -> None:
    subprocess.run(
        [
            "scp", *_SSH_OPTS,
            "-i", str(identity_file),
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
    hostname: str,
    auth_key: str,
) -> tuple[str, str, str]:
    """Run the setup script on the VPS over SSH.

    Returns (auth_url, tailscale_ip, status).
    """
    cmd_parts = ["bash", _REMOTE_SCRIPT]
    if hostname:
        cmd_parts += ["--hostname", hostname]
    if auth_key:
        cmd_parts += ["--auth-key", auth_key]

    remote_cmd = " ".join(shlex.quote(p) for p in cmd_parts)
    result = subprocess.run(
        [
            "ssh", *_SSH_OPTS,
            "-i", str(identity_file),
            ssh_target,
            remote_cmd,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    auth_url = tailscale_ip = status = ""
    in_section = False
    for line in result.stdout.splitlines():
        if _MARKER in line:
            in_section = True
            continue
        if not in_section:
            continue
        m = re.match(r"^TAILSCALE_AUTH_URL=(.+)$", line.strip())
        if m:
            auth_url = m.group(1).strip()
        m = re.match(r"^TAILSCALE_IP=(.+)$", line.strip())
        if m:
            tailscale_ip = m.group(1).strip()
        m = re.match(r"^TAILSCALE_STATUS=(.+)$", line.strip())
        if m:
            status = m.group(1).strip()

    if not auth_url and not tailscale_ip and not status:
        raise RuntimeError(
            "Remote setup produced no output markers.\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    return auth_url, tailscale_ip, status


def bootstrap_tailscale_exit_node(
    *,
    ssh_target: str,
    identity_file: str,
    hostname: str = "exit-node",
    auth_key: str = "",
) -> TailscaleBootstrapResult:
    """Install Tailscale on the VPS and configure it as an exit node over SSH.

    For fully-unattended setup pass auth_key (generate a reusable auth key at
    https://login.tailscale.com/admin/settings/keys).

    Without auth_key the returned result contains an auth_url that must be
    visited in a browser to authenticate the node.
    """
    _ensure_prereqs()

    identity_path = Path(identity_file).expanduser()
    if not identity_path.exists():
        raise RuntimeError(f"SSH identity file not found: {identity_path}")

    local_script = _find_setup_script()
    _scp_script(identity_path, ssh_target, local_script)
    auth_url, tailscale_ip, status = _run_remote_setup(
        identity_path, ssh_target, hostname, auth_key,
    )

    return TailscaleBootstrapResult(
        hostname=hostname,
        tailscale_ip=tailscale_ip,
        auth_url=auth_url,
        status=status,
        needs_approval=status != "Running",
    )
