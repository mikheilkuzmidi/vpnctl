"""The sandbox test's own failure reporting.

The point of this path is that it answers "does this tunnel work" without
touching the host's routing, so the thing worth pinning is that it says
something true when the answer is no.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

import pytest

from vpnctl import docker_smoke
from vpnctl.config import load_config


def _cfg(tmp_path: Path, monkeypatch, **overrides):
    key = tmp_path / "wg.key"
    key.write_text("A" * 43 + "=\n")
    key.chmod(0o600)
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", tmp_path / "absent.toml")
    cfg = load_config()
    fields = {
        "enabled": False,
        "endpoint": "203.0.113.10:51820",
        "public_key": "B" * 43 + "=",
        "key_file": str(key),
        "address": "10.8.0.2/32",
        "allowed_ips": "0.0.0.0/0",
    }
    fields.update(overrides)
    return dataclasses.replace(cfg, wg_custom=dataclasses.replace(cfg.wg_custom, **fields))


def _fake_docker(monkeypatch, *, stdout: str, returncode: int = 0):
    """Stand in for every docker invocation the module makes."""
    calls: list[list[str]] = []

    def fake_run(args, *, cwd=None):
        calls.append(args)
        if args[:2] == ["docker", "version"] or args[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        return subprocess.CompletedProcess(args, returncode, stdout, "")

    monkeypatch.setattr(docker_smoke, "_run", fake_run)
    monkeypatch.setattr(docker_smoke, "_repo_root", lambda: Path("/repo"))
    return calls


def test_a_disabled_provider_is_still_testable(tmp_path, monkeypatch):
    """enabled governs connecting this machine, not running a container."""
    cfg = _cfg(tmp_path, monkeypatch, enabled=False)
    _fake_docker(monkeypatch, stdout="PUBLIC_IP=203.0.113.10\n")
    result = docker_smoke.run_docker_smoke(cfg)
    assert result.public_ip == "203.0.113.10"


def test_an_unconfigured_tunnel_says_so(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch, endpoint="", public_key="")
    _fake_docker(monkeypatch, stdout="")
    with pytest.raises(docker_smoke.NotConfigured) as exc:
        docker_smoke.run_docker_smoke(cfg)
    assert "endpoint" in str(exc.value)
    assert "public_key" in str(exc.value)
    assert "bootstrap-wireguard-vps" in str(exc.value)


def test_a_silent_peer_is_not_reported_as_a_dns_error(tmp_path, monkeypatch):
    # The real symptom of a dead VPS: every packet including DNS goes into a
    # tunnel nothing is answering, so curl fails to resolve its own hostname.
    cfg = _cfg(tmp_path, monkeypatch)
    _fake_docker(
        monkeypatch,
        stdout="[smoke] waiting for a handshake\nNO_HANDSHAKE=1\n"
        "curl: (6) Could not resolve host: ifconfig.me\n",
        returncode=3,
    )
    with pytest.raises(docker_smoke.NoHandshake) as exc:
        docker_smoke.run_docker_smoke(cfg)
    message = str(exc.value)
    assert "203.0.113.10" in message
    assert "51820" in message
    assert "public key is a peer" in message


def test_the_wrong_egress_ip_is_a_failure(tmp_path, monkeypatch):
    """A tunnel that carries traffic somewhere else is worse than no tunnel."""
    cfg = _cfg(tmp_path, monkeypatch)
    _fake_docker(monkeypatch, stdout="PUBLIC_IP=198.51.100.7\n")
    with pytest.raises(RuntimeError, match="did not match"):
        docker_smoke.run_docker_smoke(cfg)


def test_the_container_gets_no_more_than_it_needs(tmp_path, monkeypatch):
    """No --net=host and no --privileged, or the host's routing is in scope."""
    cfg = _cfg(tmp_path, monkeypatch)
    calls = _fake_docker(monkeypatch, stdout="PUBLIC_IP=203.0.113.10\n")
    docker_smoke.run_docker_smoke(cfg)
    run = next(c for c in calls if c[:2] == ["docker", "run"])
    assert "--privileged" not in run
    assert not any(arg.startswith("--net") or arg.startswith("--network") for arg in run)
    assert "NET_ADMIN" in run
