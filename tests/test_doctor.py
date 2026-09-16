"""Tests for provider doctor() checks - missing tools, bad permissions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vpnctl.providers.base import ProviderStatus
from vpnctl.providers.warp_masque import WarpMasqueAdapter
from vpnctl.providers.warp_wireguard import WarpWireguardAdapter
from vpnctl import warp


def _fake_device() -> warp.WarpDevice:
    """A registration response's worth of values, with nothing real in it."""
    return warp.WarpDevice(
        device_id="00000000-0000-0000-0000-000000000000",
        token="0" * 36,
        private_key="A" * 43 + "=",
        public_key="B" * 43 + "=",
        address_v4="172.16.0.2",
        address_v6="2606:4700:110::1",
        peer_public_key="C" * 43 + "=",
        endpoint_host="engage.cloudflareclient.com:2408",
        endpoint_v4="162.159.192.2:0",
        ports=[2408, 500, 1701, 4500],
    )
from vpnctl.providers.wg_custom import WgCustomAdapter


def test_warp_masque_doctor_missing_warp_cli():
    with patch("shutil.which", return_value=None):
        result = WarpMasqueAdapter().doctor()
    assert not result.ok
    assert any("warp-cli" in i for i in result.issues)
    assert any("brew" in h for h in result.hints)


def test_warp_wireguard_doctor_needs_wireguard_not_warp_cli(tmp_path):
    """WARP now runs over stock wg-quick, so warp-cli is not a prerequisite."""
    device = tmp_path / "warp-device.json"
    with patch("shutil.which", return_value=None):
        result = WarpWireguardAdapter(device_path=device).doctor()
    assert not result.ok
    assert any("wg-quick" in i or "wg " in f"{i} " for i in result.issues)
    assert not any("warp-cli" in i for i in result.issues)
    assert any("wireguard-tools" in h for h in result.hints)


def test_warp_wireguard_doctor_does_not_register(tmp_path):
    """A dependency check must not create an account on a third party."""
    device = tmp_path / "warp-device.json"
    with patch("vpnctl.warp.register", side_effect=AssertionError("registered!")):
        result = WarpWireguardAdapter(device_path=device).doctor()
    assert not device.exists()
    assert any("registered yet" in h for h in result.hints)


def test_warp_wireguard_doctor_flags_a_split_tunnel_clash(tmp_path):
    """WARP's own address is inside 172.16.0.0/12."""
    device = tmp_path / "warp-device.json"
    warp.save(_fake_device(), device)
    result = WarpWireguardAdapter(
        excludes=["172.16.0.0/12"], device_path=device
    ).doctor()
    assert not result.ok
    assert any("172.16.0.0/12" in i for i in result.issues)


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


def test_warp_wireguard_renders_the_config_cloudflare_handed_out(tmp_path):
    device = tmp_path / "warp-device.json"
    warp.save(_fake_device(), device)

    adapter = WarpWireguardAdapter(device_path=device)
    with patch("shutil.which", return_value="/opt/homebrew/bin/wg-quick"):
        adapter.prepare()
    conf = adapter.render_config()

    assert "PrivateKey = " + _fake_device().private_key in conf
    assert "Address = 172.16.0.2/32" in conf          # the API omits the prefix
    assert "Endpoint = engage.cloudflareclient.com:2408" in conf
    assert "MTU = 1280" in conf                        # what the WARP client uses
    assert "PersistentKeepalive = 25" in conf          # handshakes are flaky without it
    assert "DNS = 1.1.1.1" in conf                     # resolver inside the tunnel


def test_warp_wireguard_reuses_a_cached_registration(tmp_path):
    device = tmp_path / "warp-device.json"
    warp.save(_fake_device(), device)
    with patch("vpnctl.warp.register", side_effect=AssertionError("registered again!")):
        adapter = WarpWireguardAdapter(device_path=device)
        with patch("shutil.which", return_value="/opt/homebrew/bin/wg-quick"):
            adapter.prepare()
    assert adapter.render_config().count("PrivateKey") == 1


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
