"""Docker-based WireGuard smoke test.

Runs the self-hosted WireGuard config inside an isolated Docker container, so
the host Mac's routing and interfaces are untouched. This validates the VPS,
keys, and tunnel behavior, but it does not replace the native macOS client
path.
"""

from __future__ import annotations

import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from vpnctl.config import Config
from vpnctl.providers.wg_custom import WgCustomAdapter

_IMAGE = "vpnctl/wg-smoke:local"


@dataclass
class DockerSmokeResult:
    public_ip: str
    output: str


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


def run_docker_smoke(
    cfg: Config,
    *,
    rebuild: bool = False,
) -> DockerSmokeResult:
    """Run the configured self-hosted WireGuard client inside Docker."""
    _require_docker()

    if not cfg.wg_custom.enabled:
        raise RuntimeError("wireguard-custom is disabled in config")

    adapter = WgCustomAdapter(
        endpoint=cfg.wg_custom.endpoint,
        public_key=cfg.wg_custom.public_key,
        interface="wgsmoke",
        key_file=cfg.wg_custom.key_file,
        address=cfg.wg_custom.address,
        dns="",
        allowed_ips=cfg.wg_custom.allowed_ips,
        excludes=[],
    )
    adapter.prepare()

    repo_root = _repo_root()
    _ensure_image(repo_root, rebuild=rebuild)

    with tempfile.TemporaryDirectory(prefix="vpnctl-docker-") as tmpdir:
        conf_path = Path(tmpdir) / "wgsmoke.conf"
        conf_path.write_text(adapter.render_config())
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
                "-v",
                f"{tmpdir}:/config:ro",
                _IMAGE,
                "/config/wgsmoke.conf",
            ]
        )

    combined = (run.stdout or "") + (run.stderr or "")
    if run.returncode != 0:
        raise RuntimeError(
            "Docker smoke test failed.\n"
            f"stdout:\n{run.stdout}\n"
            f"stderr:\n{run.stderr}"
        )

    public_ip = ""
    for line in combined.splitlines():
        if line.startswith("PUBLIC_IP="):
            public_ip = line.split("=", 1)[1].strip()
            break

    expected = _expected_public_ip(cfg.wg_custom.endpoint)
    if public_ip != expected:
        raise RuntimeError(
            "Docker smoke test connected, but public IP did not match the VPS.\n"
            f"expected={expected}\nactual={public_ip}\noutput:\n{combined}"
        )

    return DockerSmokeResult(public_ip=public_ip, output=combined)
