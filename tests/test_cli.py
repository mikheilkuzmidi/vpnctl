"""Integration-style tests for CLI commands using Click's test runner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vpnctl.cli import main
from vpnctl.providers.base import ProbeResult, ProviderStatus


def _make_result(pid: str, rtt: float, score: float, error=None) -> ProbeResult:
    return ProbeResult(
        provider_id=pid,
        median_rtt_ms=rtt,
        jitter_ms=2.0,
        loss_pct=0.0,
        throughput_mbps=10.0,
        score=score,
        error=error,
    )


def _minimal_config(tmp_path: Path, monkeypatch) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text("[policy]\n")
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg)


def test_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "benchmark" in result.output
    assert "doctor" in result.output
    assert "connect" in result.output
    assert "status" in result.output
    assert "watch" in result.output
    assert "disconnect" in result.output


def test_doctor_all_ok(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)
    import subprocess
    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("shutil.which", return_value="/usr/bin/warp-cli"):
        with patch("subprocess.run", return_value=fake_proc):
            runner = CliRunner()
            result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "All checks passed" in result.output


def test_doctor_missing_warp_cli(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)
    with patch("shutil.which", return_value=None):
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 1
    assert "warp-cli" in result.output


def test_status_no_results(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)
    results_file = tmp_path / "last_benchmark.toml"
    monkeypatch.setattr("vpnctl.selector.results_path", lambda: results_file)
    with patch("shutil.which", return_value=None):
        runner = CliRunner()
        result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "benchmark" in result.output.lower()


def test_connect_uses_cached_winner(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    fake_results = [_make_result("warp-masque", 30.0, 65.0)]
    mock_adapter = MagicMock()
    mock_adapter.provider_id = "warp-masque"
    mock_adapter.connect.return_value = None

    with patch("vpnctl.cli.load_results", return_value=fake_results):
        with patch("vpnctl.cli.build_providers", return_value=[mock_adapter]):
            runner = CliRunner()
            result = runner.invoke(main, ["connect"])

    assert result.exit_code == 0
    mock_adapter.connect.assert_called_once()


def test_connect_rolls_back_on_failure(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    fake_results = [_make_result("warp-masque", 30.0, 65.0)]
    mock_adapter = MagicMock()
    mock_adapter.provider_id = "warp-masque"
    mock_adapter.connect.side_effect = RuntimeError("timeout")

    with patch("vpnctl.cli.load_results", return_value=fake_results):
        with patch("vpnctl.cli.build_providers", return_value=[mock_adapter]):
            runner = CliRunner()
            result = runner.invoke(main, ["connect"])

    assert result.exit_code == 1
    mock_adapter.disconnect.assert_called()


def test_disconnect_no_active_tunnels(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    mock_adapter = MagicMock()
    mock_adapter.provider_id = "warp-masque"
    mock_adapter.status.return_value = ProviderStatus.DISCONNECTED

    with patch("vpnctl.cli.build_providers", return_value=[mock_adapter]):
        runner = CliRunner()
        result = runner.invoke(main, ["disconnect"])

    assert result.exit_code == 0
    assert "No active tunnels" in result.output
    mock_adapter.disconnect.assert_not_called()


def test_disconnect_active_tunnel(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    mock_adapter = MagicMock()
    mock_adapter.provider_id = "warp-masque"
    mock_adapter.status.return_value = ProviderStatus.CONNECTED

    with patch("vpnctl.cli.build_providers", return_value=[mock_adapter]):
        runner = CliRunner()
        result = runner.invoke(main, ["disconnect"])

    assert result.exit_code == 0
    mock_adapter.disconnect.assert_called_once()


def test_benchmark_no_providers(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    with patch("vpnctl.cli.build_providers", return_value=[]):
        runner = CliRunner()
        result = runner.invoke(main, ["benchmark"])

    assert result.exit_code == 1


def test_connect_named_provider(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    mock_warp = MagicMock()
    mock_warp.provider_id = "warp-masque"
    mock_wg = MagicMock()
    mock_wg.provider_id = "warp-wireguard"
    mock_wg.connect.return_value = None

    with patch("vpnctl.cli.build_providers", return_value=[mock_warp, mock_wg]):
        runner = CliRunner()
        result = runner.invoke(main, ["connect", "warp-wireguard"])

    assert result.exit_code == 0
    mock_wg.connect.assert_called_once()
    mock_warp.connect.assert_not_called()


def test_connect_disconnects_other_active_provider(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    active = MagicMock()
    active.provider_id = "warp-masque"
    active.status.return_value = ProviderStatus.CONNECTED

    target = MagicMock()
    target.provider_id = "warp-wireguard"
    target.status.return_value = ProviderStatus.DISCONNECTED
    target.connect.return_value = None

    with patch("vpnctl.cli.build_providers", return_value=[active, target]):
        runner = CliRunner()
        result = runner.invoke(main, ["connect", "warp-wireguard"])

    assert result.exit_code == 0
    active.disconnect.assert_called_once()
    target.connect.assert_called_once()


def test_docker_smoke_test_invokes_runner(tmp_path, monkeypatch):
    _minimal_config(tmp_path, monkeypatch)

    fake_result = MagicMock()
    fake_result.public_ip = "3.134.65.158"

    with patch("vpnctl.cli.run_docker_smoke", return_value=fake_result) as mock_run:
        runner = CliRunner()
        result = runner.invoke(main, ["docker-smoke-test"])

    assert result.exit_code == 0
    mock_run.assert_called_once()
    assert "3.134.65.158" in result.output


# ---------------------------------------------------------------------------
# split-tunnel
#
# Every command in this group used to raise NameError: cli.py read and wrote
# TOML without importing either library. Nothing caught it because nothing
# invoked the group, so these cover the whole round trip.
# ---------------------------------------------------------------------------


def _split_tunnel_config(tmp_path: Path, monkeypatch, body: str) -> Path:
    cfg = tmp_path / "config.toml"
    cfg.write_text(body)
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", cfg)
    return cfg


def test_split_tunnel_list_reads_the_config(tmp_path, monkeypatch):
    _split_tunnel_config(
        tmp_path,
        monkeypatch,
        '[split_tunnel]\nenabled = true\nexcludes = ["10.0.0.0/8"]\n',
    )
    with patch("vpnctl.cli.list_warp_excludes", return_value=[]):
        result = CliRunner().invoke(main, ["split-tunnel", "list"])
    assert result.exit_code == 0, result.output
    assert "enabled" in result.output
    assert "10.0.0.0/8" in result.output


def test_split_tunnel_list_without_a_config(tmp_path, monkeypatch):
    monkeypatch.setattr("vpnctl.config._CONFIG_FILE", tmp_path / "absent.toml")
    with patch("vpnctl.cli.list_warp_excludes", return_value=[]):
        result = CliRunner().invoke(main, ["split-tunnel", "list"])
    assert result.exit_code == 0, result.output
    assert "No excludes configured" in result.output


def test_split_tunnel_add_then_remove_round_trips(tmp_path, monkeypatch):
    cfg = _split_tunnel_config(tmp_path, monkeypatch, "[policy]\n")

    added = CliRunner().invoke(main, ["split-tunnel", "add", "172.16.0.0/12"])
    assert added.exit_code == 0, added.output
    assert "172.16.0.0/12" in cfg.read_text()

    # Adding it twice must not duplicate the entry.
    again = CliRunner().invoke(main, ["split-tunnel", "add", "172.16.0.0/12"])
    assert again.exit_code == 0, again.output
    assert cfg.read_text().count("172.16.0.0/12") == 1

    removed = CliRunner().invoke(main, ["split-tunnel", "remove", "172.16.0.0/12"])
    assert removed.exit_code == 0, removed.output
    assert "172.16.0.0/12" not in cfg.read_text()


def test_split_tunnel_enable_and_disable_persist(tmp_path, monkeypatch):
    cfg = _split_tunnel_config(tmp_path, monkeypatch, "[policy]\n")

    assert CliRunner().invoke(main, ["split-tunnel", "enable"]).exit_code == 0
    assert "enabled = true" in cfg.read_text()

    assert CliRunner().invoke(main, ["split-tunnel", "disable"]).exit_code == 0
    assert "enabled = false" in cfg.read_text()
