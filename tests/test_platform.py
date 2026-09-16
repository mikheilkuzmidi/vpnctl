"""The one module that knows which operating system this is.

The captured command output below is real, taken from this Mac and from the
Debian container the tests run tunnels in, with addresses swapped for
documentation ranges. Mocked output would not have caught the thing that
actually bit: Linux `route` has no `get` verb, so the macOS parser applied to
a Linux system returns None silently rather than failing.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from vpnctl import platform

# `route -n get default` on macOS 26.
DARWIN_ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
"""

# `ip -4 route show default` in the ubuntu:24.04 container.
LINUX_IP_ROUTE = "default via 198.51.100.1 dev eth0 \n"

# What net-tools `route` prints when handed the macOS invocation: usage on
# stderr, nothing on stdout. This is the silent-failure case.
LINUX_ROUTE_USAGE = ""


def _result(stdout: str, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


# -- run() -------------------------------------------------------------------


def test_a_missing_binary_is_a_failed_result_not_an_exception():
    """check=False covers a bad exit code, not an absent executable.

    This is the bug that made `vpnctl connect` die with a traceback on Linux
    before wg-quick was ever reached: `route` is not installed on Debian.
    """
    outcome = platform.run(["a-command-that-does-not-exist"])
    assert outcome.returncode == 127
    assert "not found" in outcome.stderr


def test_a_hanging_command_is_a_failed_result_too():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("x", 1)):
        outcome = platform.run(["sleep", "99"], timeout=0.01)
    assert outcome.returncode == 124
    assert "timed out" in outcome.stderr


# -- sudo_prefix() -----------------------------------------------------------


def test_root_needs_no_sudo():
    """The container case, and what lets the demo be recorded without a password."""
    with patch.object(platform.os, "geteuid", return_value=0):
        assert platform.sudo_prefix() == []
        assert platform.sudo_prefix(noninteractive=True) == []


def test_a_missing_sudo_is_not_prepended():
    """Prefixing with an absent binary turns a permission error into "not found"."""
    with patch.object(platform.os, "geteuid", return_value=501), \
         patch("shutil.which", return_value=None):
        assert platform.sudo_prefix() == []


def test_reads_are_non_interactive_and_writes_are_not():
    """Not cosmetic: status() is polled twice a second by the live monitor.

    An interactive sudo there would block the interface on a password prompt
    that nobody is looking at.
    """
    with patch.object(platform.os, "geteuid", return_value=501), \
         patch("shutil.which", return_value="/usr/bin/sudo"):
        assert platform.sudo_prefix() == ["sudo"]
        assert platform.sudo_prefix(noninteractive=True) == ["sudo", "-n"]


# -- default_gateway() -------------------------------------------------------


def test_the_macos_parser_reads_real_macos_output():
    with patch.object(platform, "IS_MACOS", True), \
         patch.object(platform, "run", return_value=_result(DARWIN_ROUTE)) as ran:
        assert platform.default_gateway() == "192.0.2.1"
    assert ran.call_args.args[0] == ["route", "-n", "get", "default"]


def test_the_linux_parser_reads_real_linux_output():
    with patch.object(platform, "IS_MACOS", False), \
         patch.object(platform, "run", return_value=_result(LINUX_IP_ROUTE)) as ran:
        assert platform.default_gateway() == "198.51.100.1"
    # iproute2, not net-tools: `ip` is present on minimal containers, `route`
    # is not, and `route` has no `get` verb anyway.
    assert ran.call_args.args[0] == ["ip", "-4", "route", "show", "default"]


def test_the_macos_parser_does_not_silently_match_linux_output():
    """The original failure mode. `gateway:` never appears in `default via`."""
    assert platform._DARWIN_GATEWAY.search(LINUX_IP_ROUTE) is None
    assert platform._LINUX_GATEWAY.search(DARWIN_ROUTE) is None


def test_a_failed_lookup_is_none_not_an_exception():
    with patch.object(platform, "run", return_value=_result("", returncode=127)):
        assert platform.default_gateway() is None
    with patch.object(platform, "run", return_value=_result(LINUX_ROUTE_USAGE)):
        assert platform.default_gateway() is None


# -- routes ------------------------------------------------------------------


def test_route_syntax_differs_per_platform():
    with patch.object(platform, "IS_MACOS", True), \
         patch.object(platform, "run") as ran, \
         patch.object(platform, "sudo_prefix", return_value=[]):
        platform.add_host_routes(["10.0.0.0/8"], "192.0.2.1")
    assert ran.call_args.args[0] == ["route", "-q", "add", "-net", "10.0.0.0/8", "192.0.2.1"]

    with patch.object(platform, "IS_MACOS", False), \
         patch.object(platform, "run") as ran, \
         patch.object(platform, "sudo_prefix", return_value=[]):
        platform.add_host_routes(["10.0.0.0/8"], "198.51.100.1")
    # `replace` not `add`: ip route add fails on an existing route, and this
    # runs on every connect.
    assert ran.call_args.args[0] == ["ip", "route", "replace", "10.0.0.0/8", "via", "198.51.100.1"]


def test_routes_are_a_no_op_without_a_gateway():
    """default_gateway() returning None must not produce a broken command."""
    with patch.object(platform, "run") as ran:
        platform.add_host_routes(["10.0.0.0/8"], "")
        platform.add_host_routes([], "192.0.2.1")
        platform.remove_host_routes([])
    ran.assert_not_called()


# -- dns_is_manageable() -----------------------------------------------------


def test_macos_can_always_manage_dns():
    with patch.object(platform, "IS_MACOS", True):
        assert platform.dns_is_manageable() is True


def test_no_resolver_tool_means_dns_cannot_be_managed():
    with patch.object(platform, "IS_MACOS", False), \
         patch("shutil.which", return_value=None):
        assert platform.dns_is_manageable() is False


def test_systemds_resolvconf_without_a_bus_cannot_manage_dns(tmp_path):
    """The real container case, verified by hand.

    /usr/sbin/resolvconf there is a symlink to resolvectl and there is no
    D-Bus socket, so wg-quick's DNS line fails with sd_bus_open_system and
    its EXIT trap removes the interface: no tunnel at all.
    """
    resolvectl = tmp_path / "resolvectl"
    resolvectl.write_text("")
    link = tmp_path / "resolvconf"
    link.symlink_to(resolvectl)

    with patch.object(platform, "IS_MACOS", False), \
         patch("shutil.which", return_value=str(link)), \
         patch.object(Path, "exists", return_value=False):
        assert platform.dns_is_manageable() is False


def test_openresolv_can_manage_dns(tmp_path):
    """Debian's own resolvconf needs no bus, so leave it to do its job."""
    real = tmp_path / "resolvconf"
    real.write_text("")
    with patch.object(platform, "IS_MACOS", False), \
         patch("shutil.which", return_value=str(real)):
        assert platform.dns_is_manageable() is True
