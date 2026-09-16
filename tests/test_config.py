"""Tests for config loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

from vpnctl.config import configure_wg_custom, load_config


def _write_config(tmp_path: Path, content: str) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text(textwrap.dedent(content))
    return cfg


def test_defaults_from_empty_toml(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path, "[policy]\n")
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    cfg = load_config()

    assert cfg.policy.probe_interval_minutes == 10
    assert cfg.policy.benchmark_interval_minutes == 30
    assert cfg.policy.consecutive_rounds_to_act == 2
    assert cfg.policy.min_rtt_improvement_ms == 15.0
    assert cfg.policy.min_score_improvement_pct == 20.0
    assert cfg.warp_masque.enabled is True
    assert cfg.warp_wireguard.enabled is True
    assert cfg.wg_custom.enabled is False


def test_custom_policy(tmp_path, monkeypatch):
    content = """\
        [policy]
        probe_interval_minutes = 5
        benchmark_interval_minutes = 60
        consecutive_rounds_to_act = 3
        min_rtt_improvement_ms = 10.0
        min_score_improvement_pct = 15.0
    """
    cfg_path = _write_config(tmp_path, content)
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    cfg = load_config()

    assert cfg.policy.probe_interval_minutes == 5
    assert cfg.policy.benchmark_interval_minutes == 60
    assert cfg.policy.consecutive_rounds_to_act == 3
    assert cfg.policy.min_rtt_improvement_ms == 10.0
    assert cfg.policy.min_score_improvement_pct == 15.0


def test_wg_custom_disabled_by_default(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path, "[policy]\n")
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    cfg = load_config()

    assert cfg.wg_custom.enabled is False
    assert cfg.wg_custom.endpoint == ""
    assert cfg.wg_custom.address == "10.8.0.2/32"
    assert cfg.wg_custom.interface == "wgcustom"
    assert cfg.wg_custom.allowed_ips == "0.0.0.0/0"


def test_wg_custom_enabled(tmp_path, monkeypatch):
    content = """\
        [providers.wireguard-custom]
        enabled = true
        endpoint = "1.2.3.4:51820"
        public_key = "PUBKEY"
        key_file = "~/.config/vpnctl/wg.key"
    """
    cfg_path = _write_config(tmp_path, content)
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    cfg = load_config()

    assert cfg.wg_custom.enabled is True
    assert cfg.wg_custom.endpoint == "1.2.3.4:51820"
    assert cfg.wg_custom.public_key == "PUBKEY"
    assert cfg.wg_custom.key_file == "~/.config/vpnctl/wg.key"
    assert cfg.wg_custom.interface == "wgcustom"
    assert cfg.wg_custom.allowed_ips == "0.0.0.0/0"


def test_providers_disabled(tmp_path, monkeypatch):
    content = """\
        [providers.warp-masque]
        enabled = false

        [providers.warp-wireguard]
        enabled = false
    """
    cfg_path = _write_config(tmp_path, content)
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    cfg = load_config()

    assert cfg.warp_masque.enabled is False
    assert cfg.warp_wireguard.enabled is False


def test_configure_wg_custom_updates_file(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path, "[policy]\n")
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg_path)

    written = configure_wg_custom(
        endpoint="203.0.113.1:51820",
        public_key="SERVERPUBKEY",
        key_file="~/.config/vpnctl/wg-custom.key",
    )

    cfg = load_config()

    assert written == cfg_path
    assert cfg.wg_custom.enabled is True
    assert cfg.wg_custom.endpoint == "203.0.113.1:51820"
    assert cfg.wg_custom.public_key == "SERVERPUBKEY"
    assert cfg.wg_custom.address == "10.8.0.2/32"
    assert cfg.wg_custom.interface == "wgcustom"
    assert cfg.wg_custom.allowed_ips == "0.0.0.0/0"


def test_probe_can_be_imported_first(tmp_path):
    """vpnctl.probe must not need a provider to have been imported already.

    providers/__init__ used to import every adapter, and every adapter
    imports run_probe from vpnctl.probe, so importing probe first walked
    probe -> providers -> warp_masque -> probe and died on a partially
    initialised module. It passed only because some other import usually got
    there first, which made it a bug that hid from the test suite.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c", "import vpnctl.probe; print(vpnctl.probe.run_probe)"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "run_probe" in result.stdout
