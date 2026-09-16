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
from unittest.mock import patch

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
    # No test may reach the network. Before this was pinned, one of these
    # actually registered a device against Cloudflare's live API.
    monkeypatch.setattr(docker_smoke, "_baseline_egress", lambda: "198.51.100.1")
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
    assert "never answered" in message
    # Both explanations are given, because from here they are indistinguishable.
    assert "blocking WireGuard" in message
    assert "is down" in message
    assert "Could not resolve host" not in message.split("output:")[0]


def test_the_wrong_egress_ip_is_a_failure(tmp_path, monkeypatch):
    """A tunnel that carries traffic somewhere else is worse than no tunnel."""
    cfg = _cfg(tmp_path, monkeypatch)
    _fake_docker(monkeypatch, stdout="PUBLIC_IP=198.51.100.7\n")
    with pytest.raises(RuntimeError, match="not to your server"):
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


def test_a_tunnel_that_does_not_change_the_egress_is_a_failure(tmp_path, monkeypatch):
    """A handshake is not the same as carrying traffic."""
    cfg = _cfg(tmp_path, monkeypatch)
    _fake_docker(monkeypatch, stdout="PUBLIC_IP=198.51.100.1\n")
    with pytest.raises(RuntimeError, match="still leaves from"):
        docker_smoke.run_docker_smoke(cfg)


def test_warp_is_verified_by_the_egress_changing(tmp_path, monkeypatch):
    """A hosted provider has no predictable egress address, so compare."""
    from vpnctl import warp

    cfg = _cfg(tmp_path, monkeypatch)
    device = tmp_path / "warp-device.json"
    warp.save(
        warp.WarpDevice(
            device_id="d", token="t", private_key="A" * 43 + "=",
            public_key="B" * 43 + "=", address_v4="172.16.0.2",
            address_v6="::1", peer_public_key="C" * 43 + "=",
            endpoint_host="engage.cloudflareclient.com:2408",
            endpoint_v4="162.159.192.2:0", ports=[2408],
        ),
        device,
    )
    _fake_docker(monkeypatch, stdout="PUBLIC_IP=104.28.200.73\nWARP=on\nDNS=ok\n")
    monkeypatch.setattr(
        docker_smoke, "_adapter_for",
        lambda cfg, pid: __import__(
            "vpnctl.providers.warp_wireguard", fromlist=["WarpWireguardAdapter"]
        ).WarpWireguardAdapter(device_path=device),
    )
    with patch("shutil.which", return_value="/opt/homebrew/bin/wg-quick"):
        result = docker_smoke.run_docker_smoke(cfg, provider_id="warp-wireguard")

    assert result.egress_changed
    assert result.warp == "on"
    assert result.dns_ok


def test_an_unknown_provider_is_refused(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _fake_docker(monkeypatch, stdout="")
    with pytest.raises(docker_smoke.NotConfigured, match="warp-wireguard"):
        docker_smoke.run_docker_smoke(cfg, provider_id="warp-masque")
