"""Docker-based WireGuard smoke test.

Runs the self-hosted WireGuard config inside an isolated Docker container, so
the host Mac's routing and interfaces are untouched. This validates the VPS,
keys, and tunnel behavior, but it does not replace the native macOS client
path.

The container gets its own network namespace, NET_ADMIN and a tun device, and
nothing else: no --net=host, no privileged mode. So the tunnel it builds
carries only the container's traffic, and the Mac keeps its own default route
throughout. That makes this the safe way to answer "does this tunnel work",
which is a different question from "connect me to it".
"""

from __future__ import annotations

import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from vpnctl.config import Config
from vpnctl.providers.riseup import RiseupAdapter
from vpnctl.providers.warp_wireguard import WarpWireguardAdapter
from vpnctl.providers.wg_custom import WgCustomAdapter

_IMAGE = "vpnctl/wg-smoke:local"

# Asked over an IP literal so the answer does not depend on DNS, which is
# exactly one of the things being tested.
_TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"

# Every provider the sandbox can exercise. A provider qualifies by being a
# WireGuard tunnel that can render a config: that is all the container needs.
SANDBOXABLE = ("warp-wireguard", "wireguard-custom", "riseup", "calyx")

# The two tunnel programs need different entrypoints and different config
# filenames, but the checks they run and the lines they print are the same.
_OPENVPN_PROVIDERS = ("riseup", "calyx")


@dataclass
class DockerSmokeResult:
    provider_id: str
    public_ip: str
    baseline_ip: str
    warp: str
    dns_ok: bool
    output: str

    @property
    def egress_changed(self) -> bool:
        """Whether traffic actually came out somewhere else.

        The point of the whole exercise. A tunnel that hands shakes and then
        egresses from the same address has not done anything.
        """
        return bool(self.public_ip) and self.public_ip != self.baseline_ip


class NoHandshake(RuntimeError):
    """The interface came up but the peer never replied."""


class NotConfigured(RuntimeError):
    """There is no self-hosted tunnel described in the config to test."""


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )


def _require_docker() -> None:
    result = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if result.returncode != 0:
        raise RuntimeError(
            "Docker daemon is not available. Start Docker Desktop first."
        )


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (Path.cwd(), *here.parents):
        dockerfile = candidate / "docker" / "wg-smoke" / "Dockerfile"
        if dockerfile.exists():
            return candidate
    raise RuntimeError("Could not find docker/wg-smoke/Dockerfile")


def _ensure_image(repo_root: Path, *, rebuild: bool) -> None:
    inspect = _run(["docker", "image", "inspect", _IMAGE])
    if inspect.returncode == 0 and not rebuild:
        return

    build = _run(
        [
            "docker",
            "build",
            "-t",
            _IMAGE,
            "-f",
            str(repo_root / "docker" / "wg-smoke" / "Dockerfile"),
            str(repo_root),
        ]
    )
    if build.returncode != 0:
        raise RuntimeError(
            "Failed to build Docker smoke image.\n"
            f"stdout:\n{build.stdout}\n"
            f"stderr:\n{build.stderr}"
        )


def _expected_public_ip(endpoint: str) -> str:
    host, _, _port = endpoint.rpartition(":")
    return host or endpoint


def _baseline_egress() -> str:
    """This machine's egress address with no tunnel, for comparison.

    The container shares the host's egress path, so measuring it here rather
    than inside the container avoids a second image run.
    """
    try:
        with httpx.Client(timeout=15.0) as client:
            body = client.get(_TRACE_URL).text
    except httpx.HTTPError:
        return ""
    for line in body.splitlines():
        key, _, value = line.partition("=")
        if key == "ip":
            return value.strip()
    return ""


def _adapter_for(cfg: Config, provider_id: str):
    """The adapter whose config the container should run.

    Anything that can render a WireGuard config can be tested this way, which
    is why this returns the same adapters used for a real connection rather
    than a sandbox-specific reimplementation of them.
    """
    if provider_id in _OPENVPN_PROVIDERS:
        return RiseupAdapter(
            provider_id,
            location=cfg.riseup.location,
            protocol=cfg.riseup.protocol,
            port=cfg.riseup.port,
        )
    if provider_id == "warp-wireguard":
        return WarpWireguardAdapter()
    if provider_id == "wireguard-custom":
        return WgCustomAdapter(
            endpoint=cfg.wg_custom.endpoint,
            public_key=cfg.wg_custom.public_key,
            interface="wgsmoke",
            key_file=cfg.wg_custom.key_file,
            address=cfg.wg_custom.address,
            dns=cfg.wg_custom.dns,
            allowed_ips=cfg.wg_custom.allowed_ips,
            excludes=[],
        )
    raise NotConfigured(
        f"{provider_id} cannot be tested in the sandbox. "
        f"Choose one of: {', '.join(SANDBOXABLE)}"
    )


def run_docker_smoke(
    cfg: Config,
    *,
    provider_id: str = "wireguard-custom",
    rebuild: bool = False,
) -> DockerSmokeResult:
    """Run one provider's WireGuard client inside Docker and check it works."""
    _require_docker()

    adapter = _adapter_for(cfg, provider_id)

    # Deliberately not gated on the provider's enabled flag. That flag decides
    # whether a provider is a candidate for connecting *this machine*, and
    # wanting to check a tunnel inside a container is not a reason to make it
    # one. What the test does need is a tunnel it can actually describe.
    if provider_id == "wireguard-custom":
        missing = [
            name
            for name, value in (
                ("endpoint", cfg.wg_custom.endpoint),
                ("public_key", cfg.wg_custom.public_key),
                ("key_file", cfg.wg_custom.key_file),
                ("address", cfg.wg_custom.address),
            )
            if not value
        ]
        if missing:
            raise NotConfigured(
                "wireguard-custom has no "
                + ", ".join(missing)
                + " in the config, so there is no tunnel to test. "
                "`vpnctl bootstrap-wireguard-vps` sets one up, or use "
                "`--provider warp-wireguard` for the free hosted one."
            )

    adapter.prepare()
    baseline = _baseline_egress()

    repo_root = _repo_root()
    _ensure_image(repo_root, rebuild=rebuild)

    openvpn = provider_id in _OPENVPN_PROVIDERS

    with tempfile.TemporaryDirectory(prefix="vpnctl-docker-") as tmpdir:
        if openvpn:
            conf_path = Path(tmpdir) / "openvpn.conf"
            conf_path.write_text(adapter.render_config())
            entrypoint = ["--entrypoint", "/usr/local/bin/vpnctl-openvpn-smoke"]
            # openvpn installs the provider's resolver itself, so there is
            # nothing for the entrypoint to set.
            env = []
        else:
            conf_path = Path(tmpdir) / "wgsmoke.conf"
            # Without with_dns=False, wg-quick tries resolvconf inside the
            # container and the tunnel never comes up at all.
            conf_path.write_text(adapter.render_config(with_dns=False))
            entrypoint = []
            # The resolver to install inside the container once the tunnel is
            # up, so DNS is checked rather than merely avoided. It is the
            # provider's own, which is the one a real connection would use.
            env = ["-e", f"SMOKE_DNS={adapter.dns or '1.1.1.1'}"]
        conf_path.chmod(0o600)

        run = _run(
            [
                "docker",
                "run",
                "--rm",
                "--cap-add",
                "NET_ADMIN",
                "--device",
                "/dev/net/tun",
                *env,
                *entrypoint,
                "-v",
                f"{tmpdir}:/config:ro",
                _IMAGE,
                f"/config/{conf_path.name}",
            ]
        )

    combined = (run.stdout or "") + (run.stderr or "")

    if "NO_HANDSHAKE=1" in combined:
        raise NoHandshake(
            f"{provider_id}: the tunnel came up, but the peer never answered "
            "the handshake.\n"
            "The interface, keys and routes are all fine: packets went out and "
            "nothing came back. That is what a network blocking WireGuard "
            "looks like, and also what a server that is down looks like.\n"
            f"output:\n{combined}"
        )
    if "NO_TUNNEL=1" in combined:
        raise NoHandshake(
            f"{provider_id}: the tunnel never came up. openvpn either exited "
            "or never finished its initialisation sequence, which is what a "
            "blocked or unreachable gateway looks like from here.\n"
            f"output:\n{combined}"
        )
    if "NO_EGRESS=1" in combined:
        raise RuntimeError(
            f"{provider_id}: handshake succeeded but no traffic came back "
            f"through the tunnel.\noutput:\n{combined}"
        )
    if run.returncode != 0:
        raise RuntimeError(
            f"{provider_id}: sandbox test failed.\n"
            f"stdout:\n{run.stdout}\n"
            f"stderr:\n{run.stderr}"
        )

    fields = {}
    for line in combined.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("PUBLIC_IP", "WARP", "DNS", "LOC"):
            fields[key] = value.strip()

    result = DockerSmokeResult(
        provider_id=provider_id,
        public_ip=fields.get("PUBLIC_IP", ""),
        baseline_ip=baseline,
        warp=fields.get("WARP", ""),
        dns_ok=fields.get("DNS") == "ok",
        output=combined,
    )

    if not result.egress_changed and baseline:
        raise RuntimeError(
            f"{provider_id}: the tunnel is up but traffic still leaves from "
            f"{baseline}, so nothing is being carried through it.\n"
            f"output:\n{combined}"
        )

    # A self-hosted tunnel has a checkable answer: traffic must come out of
    # the machine it was sent to. A hosted provider does not, because it
    # egresses from whichever of its own addresses it chooses.
    if provider_id == "wireguard-custom":
        expected = _expected_public_ip(cfg.wg_custom.endpoint)  # noqa: E501
        if result.public_ip != expected:
            raise RuntimeError(
                "The tunnel carried traffic, but not to your server.\n"
                f"expected={expected}\nactual={result.public_ip}\n"
                f"output:\n{combined}"
            )

    return result
