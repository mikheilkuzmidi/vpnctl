"""Tests for Tailscale exit-node bootstrap helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vpnctl.tailscale_bootstrap import (
    TailscaleBootstrapResult,
    _find_setup_script,
    _run_remote_setup,
    bootstrap_tailscale_exit_node,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _vps_stdout(
    ip: str = "",
    auth_url: str = "",
    status: str = "Running",
) -> str:
    lines = ["Installing packages...", "", "===VPNCTL==="]
    if auth_url:
        lines.append(f"TAILSCALE_AUTH_URL={auth_url}")
    if ip:
        lines.append(f"TAILSCALE_IP={ip}")
    lines.append(f"TAILSCALE_STATUS={status}")
    return "\n".join(lines)


def _proc(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )


# ── _find_setup_script ────────────────────────────────────────────────────────

class TestFindSetupScript:
    def test_finds_script_in_cwd(self, tmp_path, monkeypatch):
        script = tmp_path / "setup_tailscale_exit_node.sh"
        script.write_text("#!/bin/bash\n")
        monkeypatch.chdir(tmp_path)
        assert _find_setup_script() == script

    def test_raises_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import vpnctl.tailscale_bootstrap as tb
        monkeypatch.setattr(tb, "__file__", str(tmp_path / "fake_module.py"))
        with pytest.raises(RuntimeError, match="setup_tailscale_exit_node.sh not found"):
            _find_setup_script()


# ── _run_remote_setup ─────────────────────────────────────────────────────────

class TestRunRemoteSetup:
    def test_parses_ip_and_running_status(self):
        stdout = _vps_stdout(ip="100.64.0.1", status="Running")
        with patch("subprocess.run", return_value=_proc(stdout)):
            auth_url, ip, status = _run_remote_setup(
                Path("/fake.pem"), "ubuntu@1.2.3.4", "exit-node", ""
            )
        assert ip == "100.64.0.1"
        assert status == "Running"
        assert auth_url == ""

    def test_parses_auth_url_and_needs_auth_status(self):
        stdout = _vps_stdout(
            auth_url="https://login.tailscale.com/a/abc123",
            status="needs-auth",
        )
        with patch("subprocess.run", return_value=_proc(stdout)):
            auth_url, ip, status = _run_remote_setup(
                Path("/fake.pem"), "ubuntu@1.2.3.4", "exit-node", ""
            )
        assert auth_url == "https://login.tailscale.com/a/abc123"
        assert status == "needs-auth"
        assert ip == ""

    def test_raises_when_no_markers_in_output(self):
        with patch("subprocess.run", return_value=_proc("no markers here")):
            with pytest.raises(RuntimeError, match="no output markers"):
                _run_remote_setup(
                    Path("/fake.pem"), "ubuntu@1.2.3.4", "exit-node", ""
                )

    def test_ignores_output_before_marker(self):
        stdout = "noise line\nmore noise\n===VPNCTL===\nTAILSCALE_IP=100.1.2.3\nTAILSCALE_STATUS=Running"
        with patch("subprocess.run", return_value=_proc(stdout)):
            _, ip, status = _run_remote_setup(
                Path("/fake.pem"), "ubuntu@1.2.3.4", "exit-node", ""
            )
        assert ip == "100.1.2.3"
        assert status == "Running"

    def test_includes_auth_key_in_remote_command(self):
        stdout = _vps_stdout(ip="100.1.2.3", status="Running")
        with patch("subprocess.run", return_value=_proc(stdout)) as mock_run:
            _run_remote_setup(
                Path("/fake.pem"), "ubuntu@1.2.3.4", "exit-node", "tskey-auth-fake"
            )
        call_args = mock_run.call_args[0][0]
        remote_cmd = call_args[-1]
        assert "--auth-key" in remote_cmd
        assert "tskey-auth-fake" in remote_cmd

    def test_includes_hostname_in_remote_command(self):
        stdout = _vps_stdout(ip="100.1.2.3", status="Running")
        with patch("subprocess.run", return_value=_proc(stdout)) as mock_run:
            _run_remote_setup(
                Path("/fake.pem"), "ubuntu@1.2.3.4", "my-exit-node", ""
            )
        call_args = mock_run.call_args[0][0]
        remote_cmd = call_args[-1]
        assert "--hostname" in remote_cmd
        assert "my-exit-node" in remote_cmd


# ── bootstrap_tailscale_exit_node ─────────────────────────────────────────────

class TestBootstrapTailscaleExitNode:
    def _write_key(self, tmp_path: Path) -> Path:
        key = tmp_path / "vps.pem"
        key.write_text("fake-key")
        return key

    def _write_script(self, tmp_path: Path) -> Path:
        script = tmp_path / "setup_tailscale_exit_node.sh"
        script.write_text("#!/bin/bash\n")
        return script

    def test_returns_result_when_authenticated(self, tmp_path):
        key = self._write_key(tmp_path)
        script = self._write_script(tmp_path)
        stdout = _vps_stdout(ip="100.64.0.1", status="Running")

        with patch("vpnctl.tailscale_bootstrap._find_setup_script", return_value=script):
            with patch("shutil.which", return_value="/usr/bin/ssh"):
                with patch("subprocess.run", return_value=_proc(stdout)):
                    result = bootstrap_tailscale_exit_node(
                        ssh_target="ubuntu@1.2.3.4",
                        identity_file=str(key),
                        hostname="frankfurt-exit",
                        auth_key="tskey-auth-fake",
                    )

        assert isinstance(result, TailscaleBootstrapResult)
        assert result.tailscale_ip == "100.64.0.1"
        assert result.status == "Running"
        assert result.hostname == "frankfurt-exit"
        assert not result.needs_approval

    def test_returns_result_with_auth_url(self, tmp_path):
        key = self._write_key(tmp_path)
        script = self._write_script(tmp_path)
        stdout = _vps_stdout(
            auth_url="https://login.tailscale.com/a/abc123",
            status="needs-auth",
        )

        with patch("vpnctl.tailscale_bootstrap._find_setup_script", return_value=script):
            with patch("shutil.which", return_value="/usr/bin/ssh"):
                with patch("subprocess.run", return_value=_proc(stdout)):
                    result = bootstrap_tailscale_exit_node(
                        ssh_target="ubuntu@1.2.3.4",
                        identity_file=str(key),
                    )

        assert result.auth_url == "https://login.tailscale.com/a/abc123"
        assert result.needs_approval
        assert result.tailscale_ip == ""

    def test_raises_on_missing_identity_file(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/ssh"):
            with pytest.raises(RuntimeError, match="SSH identity file not found"):
                bootstrap_tailscale_exit_node(
                    ssh_target="ubuntu@1.2.3.4",
                    identity_file=str(tmp_path / "nonexistent.pem"),
                )

    def test_raises_on_missing_ssh_tool(self, tmp_path):
        key = self._write_key(tmp_path)
        with patch("shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="ssh not found"):
                bootstrap_tailscale_exit_node(
                    ssh_target="ubuntu@1.2.3.4",
                    identity_file=str(key),
                )

    def test_propagates_subprocess_error(self, tmp_path):
        key = self._write_key(tmp_path)
        script = self._write_script(tmp_path)

        with patch("vpnctl.tailscale_bootstrap._find_setup_script", return_value=script):
            with patch("shutil.which", return_value="/usr/bin/ssh"):
                with patch(
                    "subprocess.run",
                    side_effect=subprocess.CalledProcessError(1, "scp", stderr="denied"),
                ):
                    with pytest.raises(subprocess.CalledProcessError):
                        bootstrap_tailscale_exit_node(
                            ssh_target="ubuntu@1.2.3.4",
                            identity_file=str(key),
                        )


# ── CLI integration ───────────────────────────────────────────────────────────

class TestBootstrapTailscaleCLI:
    def test_cli_command_exists(self):
        from click.testing import CliRunner
        from vpnctl.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["bootstrap-tailscale-exit-node", "--help"])
        assert result.exit_code == 0
        assert "--ssh-target" in result.output
        assert "--identity-file" in result.output
        assert "--auth-key" in result.output

    def test_cli_success_with_ip(self, tmp_path):
        from click.testing import CliRunner
        from vpnctl.cli import main

        key = tmp_path / "vps.pem"
        key.write_text("fake")
        fake_result = TailscaleBootstrapResult(
            hostname="frankfurt-exit",
            tailscale_ip="100.64.0.1",
            auth_url="",
            status="Running",
            needs_approval=False,
        )

        with patch("vpnctl.cli.bootstrap_tailscale_exit_node", return_value=fake_result):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "bootstrap-tailscale-exit-node",
                    "--ssh-target", "ubuntu@1.2.3.4",
                    "--identity-file", str(key),
                ],
            )

        assert result.exit_code == 0
        assert "100.64.0.1" in result.output

    def test_cli_shows_auth_url_when_needs_auth(self, tmp_path):
        from click.testing import CliRunner
        from vpnctl.cli import main

        key = tmp_path / "vps.pem"
        key.write_text("fake")
        fake_result = TailscaleBootstrapResult(
            hostname="exit-node",
            tailscale_ip="",
            auth_url="https://login.tailscale.com/a/abc123",
            status="needs-auth",
            needs_approval=True,
        )

        with patch("vpnctl.cli.bootstrap_tailscale_exit_node", return_value=fake_result):
            runner = CliRunner()
            result = runner.invoke(
                main,
                [
                    "bootstrap-tailscale-exit-node",
                    "--ssh-target", "ubuntu@1.2.3.4",
                    "--identity-file", str(key),
                ],
            )

        assert result.exit_code == 0
        assert "https://login.tailscale.com/a/abc123" in result.output
