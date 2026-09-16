"""Proving the obfuscated transport works, in containers.

A transport is hard to trust on someone's word: "it went through" could just
mean the block was not there. So this test builds both ends and blocks the
direct path itself.

Two containers on a private network. The server runs WireGuard and drops
inbound UDP on the WireGuard port, leaving only TCP 443 open, which is what a
restrictive network leaves open. The client then shows two things in order:
that a direct tunnel gets no handshake, and that the same tunnel does get one
when carried over TCP 443. The first half is what makes the second half mean
something.

None of this touches the host's routing.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_IMAGE = "vpnctl/wg-bypass:local"
_NETWORK_PREFIX = "vpnctl-bypass-"


class BypassError(RuntimeError):
    """The test could not be run, as distinct from the transport failing."""


@dataclass
class BypassResult:
    direct_blocked: bool
    tunnelled: bool
    carried_traffic: bool
    output: str

    @property
    def ok(self) -> bool:
        """A pass needs all three: a real block, a handshake, and traffic."""
        return self.direct_blocked and self.tunnelled and self.carried_traffic


def _run(args: list[str], *, timeout: float = 600.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, check=False, timeout=timeout
    )


def _require_docker() -> None:
    if _run(["docker", "version", "--format", "{{.Server.Version}}"]).returncode != 0:
        raise BypassError("Docker is not available. Start Docker Desktop first.")


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (Path.cwd(), *here.parents):
        if (candidate / "docker" / "wg-bypass" / "Dockerfile").exists():
            return candidate
    raise BypassError(
        "Could not find docker/wg-bypass/Dockerfile. This test runs from a "
        "clone of the repository."
    )


def _ensure_image(repo_root: Path, *, rebuild: bool) -> None:
    if not rebuild and _run(["docker", "image", "inspect", _IMAGE]).returncode == 0:
        return
    build = _run(
        [
            "docker", "build", "-t", _IMAGE,
            "-f", str(repo_root / "docker" / "wg-bypass" / "Dockerfile"),
            str(repo_root),
        ]
    )
    if build.returncode != 0:
        raise BypassError(
            f"Could not build the test image.\n{build.stdout}\n{build.stderr}"
        )


def _keypair(directory: Path, name: str) -> None:
    """Generate a WireGuard keypair at 0600, using the wg already required."""
    if not shutil.which("wg"):
        raise BypassError("wg not found. Install: brew install wireguard-tools")
    private = _run(["wg", "genkey"]).stdout.strip()
    public = subprocess.run(
        ["wg", "pubkey"], input=private, capture_output=True, text=True, check=True
    ).stdout.strip()
    key_file = directory / f"{name}.key"
    key_file.write_text(private + "\n")
    key_file.chmod(0o600)
    (directory / f"{name}.pub").write_text(public + "\n")


def run_bypass_test(*, rebuild: bool = False) -> BypassResult:
    """Build both ends, block the direct path, and see if the transport wins."""
    _require_docker()
    _ensure_image(_repo_root(), rebuild=rebuild)

    # Unique names, so a previous run that died does not collide with this one.
    suffix = secrets.token_hex(4)
    network = f"{_NETWORK_PREFIX}{suffix}"
    server = f"bypass-server-{suffix}"

    with tempfile.TemporaryDirectory(prefix="vpnctl-bypass-") as tmpdir:
        keys = Path(tmpdir) / "keys"
        keys.mkdir()
        _keypair(keys, "server")
        _keypair(keys, "client")

        created_network = _run(["docker", "network", "create", network]).returncode == 0
        try:
            started = _run(
                [
                    "docker", "run", "-d", "--name", server, "--network", network,
                    "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                    "-v", f"{keys}:/keys:ro", _IMAGE, "bypass-server",
                ]
            )
            if started.returncode != 0:
                raise BypassError(
                    f"Could not start the server container: {started.stderr.strip()}"
                )

            client = _run(
                [
                    "docker", "run", "--rm", "--network", network,
                    "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                    "-v", f"{keys}:/keys:ro", _IMAGE, "bypass-client", server,
                ]
            )
            combined = (client.stdout or "") + (client.stderr or "")
        finally:
            _run(["docker", "rm", "-f", server])
            if created_network:
                _run(["docker", "network", "rm", network])

    if "DIRECT=reachable" in combined:
        raise BypassError(
            "The direct path was not blocked, so the test proves nothing about "
            f"the transport.\noutput:\n{combined}"
        )

    return BypassResult(
        direct_blocked="DIRECT=blocked" in combined,
        tunnelled="TUNNELLED=yes" in combined,
        carried_traffic="TRAFFIC=yes" in combined,
        output=combined,
    )
