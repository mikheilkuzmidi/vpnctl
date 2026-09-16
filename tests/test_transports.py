"""The transport layer, and the routing trap it exists to avoid."""

from __future__ import annotations

import socket
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vpnctl.transports import (
    DirectTransport,
    TransportError,
    WstunnelSettings,
    WstunnelTransport,
    build_transport,
)


def test_direct_transport_changes_nothing():
    transport = DirectTransport()
    assert transport.start("203.0.113.10:51820") == "203.0.113.10:51820"
    assert transport.excluded_ips() == []
    transport.stop()  # must not raise


def test_build_transport_knows_both_kinds():
    assert build_transport("direct", WstunnelSettings()).kind == "direct"
    assert build_transport("", WstunnelSettings()).kind == "direct"
    assert build_transport("wstunnel", WstunnelSettings(server="wss://h:443")).kind == "wstunnel"
    with pytest.raises(TransportError, match="Unknown transport"):
        build_transport("obfs9000", WstunnelSettings())


def test_wstunnel_needs_a_server():
    transport = WstunnelTransport(WstunnelSettings())
    with pytest.raises(TransportError, match="transport.server is not set"):
        transport.start("203.0.113.10:51820")


def test_wstunnel_excludes_its_own_server_from_the_tunnel():
    """The trap: without this the transport's path is routed into the tunnel.

    AllowedIPs is 0.0.0.0/0, so once the tunnel owns the default route, the
    transport's own connection to the server would be carried by the tunnel
    it is establishing, and nothing moves in either direction.
    """
    transport = WstunnelTransport(WstunnelSettings(server="wss://vpn.example.com:443"))
    fake = [(socket.AF_INET, None, None, "", ("198.51.100.9", 443))]
    with patch("socket.getaddrinfo", return_value=fake):
        assert transport.excluded_ips() == ["198.51.100.9/32"]


def test_wstunnel_resolves_the_server_before_the_tunnel_takes_over():
    """A hostname cannot be a route, and DNS stops working mid-connect."""
    transport = WstunnelTransport(WstunnelSettings(server="wss://nope.invalid:443"))
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
        with pytest.raises(TransportError, match="Could not resolve"):
            transport.excluded_ips()


def test_wstunnel_builds_the_forwarding_argument():
    settings = WstunnelSettings(
        server="wss://vpn.example.com:443", local_port=51821, sni="www.example.com"
    )
    transport = WstunnelTransport(settings)
    process = MagicMock(poll=MagicMock(return_value=None))

    with patch("shutil.which", return_value="/opt/homebrew/bin/wstunnel"), \
         patch("subprocess.Popen", return_value=process) as popen, \
         patch.object(transport, "_await_listener"):
        local = transport.start("203.0.113.10:51820")

    assert local == "127.0.0.1:51821"
    args = popen.call_args.args[0]
    assert "-L" in args
    forward = args[args.index("-L") + 1]
    # Local UDP in, the real endpoint out.
    assert forward == "udp://127.0.0.1:51821:203.0.113.10:51820"
    assert args[args.index("--tls-sni-override") + 1] == "www.example.com"
    assert args[-1] == "wss://vpn.example.com:443"


def test_wstunnel_refuses_an_endpoint_with_no_port():
    transport = WstunnelTransport(WstunnelSettings(server="wss://h:443"))
    with patch("shutil.which", return_value="/opt/homebrew/bin/wstunnel"):
        with pytest.raises(TransportError, match="no port"):
            transport.start("203.0.113.10")


def test_wstunnel_reports_an_immediate_exit_rather_than_waiting():
    """A relay that dies at once must not look like a slow start."""
    transport = WstunnelTransport(WstunnelSettings(server="wss://h:443"))
    dead = MagicMock(poll=MagicMock(return_value=1), returncode=1)
    dead.stderr.read.return_value = "bind: permission denied"
    with patch("shutil.which", return_value="/opt/homebrew/bin/wstunnel"), \
         patch("subprocess.Popen", return_value=dead):
        with pytest.raises(TransportError, match="exited immediately"):
            transport.start("203.0.113.10:51820")


def test_wstunnel_doctor_reports_what_is_missing():
    with patch("shutil.which", return_value=None):
        issues = WstunnelTransport(WstunnelSettings()).doctor()
    assert any("wstunnel not found" in i for i in issues)
    assert any("server not set" in i for i in issues)

    with patch("shutil.which", return_value="/usr/bin/wstunnel"):
        issues = WstunnelTransport(WstunnelSettings(server="vpn.example.com")).doctor()
    assert any("should be a URL" in i for i in issues)


def test_stop_is_safe_before_start():
    WstunnelTransport(WstunnelSettings(server="wss://h:443")).stop()


def test_stop_kills_a_relay_that_ignores_terminate():
    transport = WstunnelTransport(WstunnelSettings(server="wss://h:443"))
    process = MagicMock(poll=MagicMock(return_value=None))
    process.wait.side_effect = subprocess.TimeoutExpired(cmd="wstunnel", timeout=5)
    transport._process = process
    transport.stop()
    process.terminate.assert_called_once()
    process.kill.assert_called_once()
