"""Tests for provider doctor() checks — missing tools, bad permissions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vpnctl.providers.base import ProviderStatus
from vpnctl.providers.warp_masque import WarpMasqueAdapter
from vpnctl.providers.warp_wireguard import WarpWireguardAdapter
from vpnctl.providers.wg_custom import WgCustomAdapter


def test_warp_masque_doctor_missing_warp_cli():
    with patch("shutil.which", return_value=None):
        result = WarpMasqueAdapter().doctor()
    assert not result.ok
    assert any("warp-cli" in i for i in result.issues)
    assert any("brew" in h for h in result.hints)


def test_warp_wireguard_doctor_missing_warp_cli():
    with patch("shutil.which", return_value=None):
        result = WarpWireguardAdapter().doctor()
    assert not result.ok
    assert any("warp-cli" in i for i in result.issues)


def test_warp_masque_doctor_ok():
    import subprocess
    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("shutil.which", return_value="/usr/local/bin/warp-cli"):
        with patch("subprocess.run", return_value=fake_proc):
            result = WarpMasqueAdapter().doctor()
    assert result.ok
    assert result.issues == []


def test_warp_masque_prepare_uses_current_protocol_command():
    import subprocess

    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("shutil.which", return_value="/usr/local/bin/warp-cli"):
        with patch("subprocess.run", return_value=fake_proc) as mock_run:
            WarpMasqueAdapter().prepare()

    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == [
        "warp-cli",
        "tunnel",
        "protocol",
        "set",
        "MASQUE",
    ]


def test_warp_wireguard_prepare_uses_current_protocol_command():
    import subprocess

    fake_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("shutil.which", return_value="/usr/local/bin/warp-cli"):
        with patch("subprocess.run", return_value=fake_proc) as mock_run:
            WarpWireguardAdapter().prepare()

    mock_run.assert_called_once()
    assert mock_run.call_args.args[0] == [
        "warp-cli",
        "tunnel",
        "protocol",
        "set",
        "WireGuard",
    ]


def test_wg_custom_doctor_no_wireguard_tools():
    with patch("shutil.which", return_value=None):
        adapter = WgCustomAdapter(
            endpoint="1.2.3.4:51820",
            public_key="KEY",
            key_file="~/.config/vpnctl/wg.key",
        )
        result = adapter.doctor()
    assert not result.ok
    assert any("wireguard-tools" in h for h in result.hints)


def test_wg_custom_doctor_missing_key_file(tmp_path):
    missing = tmp_path / "missing.key"
    with patch("shutil.which", return_value="/usr/local/bin/wg-quick"):
        adapter = WgCustomAdapter(
            endpoint="1.2.3.4:51820",
            public_key="KEY",
            key_file=str(missing),
        )
        result = adapter.doctor()
    assert not result.ok
    assert any("not found" in i for i in result.issues)


def test_wg_custom_doctor_unsafe_permissions(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o644)

    with patch("shutil.which", return_value="/usr/local/bin/wg-quick"):
        adapter = WgCustomAdapter(
            endpoint="1.2.3.4:51820",
            public_key="KEY",
            key_file=str(key_file),
        )
        result = adapter.doctor()
    assert not result.ok
    assert any("unsafe permissions" in i for i in result.issues)
    assert any("chmod 600" in h for h in result.hints)


def test_wg_custom_doctor_ok(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    with patch("shutil.which", return_value="/usr/local/bin/wg-quick"):
        adapter = WgCustomAdapter(
            endpoint="1.2.3.4:51820",
            public_key="KEY",
            key_file=str(key_file),
        )
        result = adapter.doctor()
    assert result.ok
    assert result.issues == []


def test_wg_custom_doctor_no_endpoint(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    with patch("shutil.which", return_value="/usr/local/bin/wg-quick"):
        adapter = WgCustomAdapter(
            endpoint="",
            public_key="KEY",
            key_file=str(key_file),
        )
        result = adapter.doctor()
    assert not result.ok
    assert any("endpoint" in i for i in result.issues)


def test_wg_custom_status_uses_real_interface_mapping(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    adapter = WgCustomAdapter(
        endpoint="1.2.3.4:51820",
        public_key="KEY",
        interface="wgcustom",
        key_file=str(key_file),
    )

    import subprocess

    fake_proc = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="interface: utun6\n",
        stderr="",
    )
    with patch("shutil.which", return_value="/usr/local/bin/wg"):
        with patch.object(adapter, "_resolve_real_interface", return_value="utun6"):
            with patch("subprocess.run", return_value=fake_proc) as mock_run:
                status = adapter.status()

    assert status == ProviderStatus.CONNECTED
    assert mock_run.call_args.args[0] == ["wg", "show", "utun6"]


def test_wg_custom_status_reads_alias_file_via_sudo_when_needed(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    adapter = WgCustomAdapter(
        endpoint="1.2.3.4:51820",
        public_key="KEY",
        interface="wgcustom",
        key_file=str(key_file),
    )

    import subprocess

    denied = PermissionError("nope")
    cat_proc = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="utun6\n",
        stderr="",
    )
    show_proc = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="interface: utun6\n",
        stderr="",
    )

    fake_name_file = MagicMock()
    fake_name_file.exists.return_value = True
    fake_name_file.read_text.side_effect = denied

    with patch.object(adapter, "_alias_name_file", return_value=fake_name_file):
        with patch("shutil.which", return_value="/usr/local/bin/wg"):
            with patch("subprocess.run", side_effect=[cat_proc, show_proc]) as mock_run:
                status = adapter.status()

    assert status == ProviderStatus.CONNECTED
    assert mock_run.call_args_list[0].args[0] == ["sudo", "-n", "cat", str(fake_name_file)]
    assert mock_run.call_args_list[1].args[0] == ["wg", "show", "utun6"]


def test_wg_custom_status_uses_sudo_wg_show_on_permission_denied(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    adapter = WgCustomAdapter(
        endpoint="1.2.3.4:51820",
        public_key="KEY",
        interface="wgcustom",
        key_file=str(key_file),
    )

    import subprocess

    denied_proc = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="Unable to access interface: Permission denied",
    )
    sudo_proc = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="interface: utun6\n",
        stderr="",
    )

    with patch.object(adapter, "_resolve_real_interface", return_value="utun6"):
        with patch("shutil.which", return_value="/usr/local/bin/wg"):
            with patch("subprocess.run", side_effect=[denied_proc, sudo_proc]) as mock_run:
                status = adapter.status()

    assert status == ProviderStatus.CONNECTED
    assert mock_run.call_args_list[0].args[0] == ["wg", "show", "utun6"]
    assert mock_run.call_args_list[1].args[0] == ["sudo", "-n", "wg", "show", "utun6"]


def test_wg_custom_doctor_warns_on_utun_alias(tmp_path):
    key_file = tmp_path / "wg.key"
    key_file.write_text("PRIVATEKEY")
    key_file.chmod(0o600)

    with patch("shutil.which", return_value="/usr/local/bin/wg-quick"):
        adapter = WgCustomAdapter(
            endpoint="1.2.3.4:51820",
            public_key="KEY",
            interface="utun9",
            key_file=str(key_file),
        )
        result = adapter.doctor()

    assert result.ok
    assert any("wgcustom" in h for h in result.hints)
