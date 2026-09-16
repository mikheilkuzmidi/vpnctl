"""The bypass proof's own logic: a pass needs the block to have been real."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from vpnctl import bypass


def _docker(output: str, *, returncode: int = 0):
    def fake_run(args, *, timeout=600.0):
        if args[:2] == ["docker", "version"] or args[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        if args[:3] == ["docker", "run", "--rm"]:
            return subprocess.CompletedProcess(args, returncode, output, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    return fake_run


def test_a_pass_needs_block_handshake_and_traffic():
    result = bypass.BypassResult(True, True, True, "")
    assert result.ok
    # Any one missing is not a pass. A handshake with no traffic in particular
    # is the failure that looks like success.
    assert not bypass.BypassResult(True, True, False, "").ok
    assert not bypass.BypassResult(True, False, True, "").ok
    assert not bypass.BypassResult(False, True, True, "").ok


def test_the_transport_winning_is_reported(tmp_path):
    output = "DIRECT=blocked\nTUNNELLED=yes\nTRAFFIC=yes\n"
    with patch.object(bypass, "_run", _docker(output)), \
         patch.object(bypass, "_repo_root", return_value=tmp_path), \
         patch.object(bypass, "_keypair"):
        result = bypass.run_bypass_test()
    assert result.ok


def test_an_unblocked_direct_path_invalidates_the_test(tmp_path):
    """If the block was not there, a success proves nothing.

    This is the difference between a test and a demonstration, so it is an
    error rather than a pass.
    """
    output = "DIRECT=reachable\nTUNNELLED=yes\nTRAFFIC=yes\n"
    with patch.object(bypass, "_run", _docker(output)), \
         patch.object(bypass, "_repo_root", return_value=tmp_path), \
         patch.object(bypass, "_keypair"):
        with pytest.raises(bypass.BypassError, match="proves nothing"):
            bypass.run_bypass_test()


def test_a_transport_that_does_not_get_through_is_a_clean_failure(tmp_path):
    output = "DIRECT=blocked\nTUNNELLED=no\n"
    with patch.object(bypass, "_run", _docker(output, returncode=4)), \
         patch.object(bypass, "_repo_root", return_value=tmp_path), \
         patch.object(bypass, "_keypair"):
        result = bypass.run_bypass_test()
    assert result.direct_blocked
    assert not result.tunnelled
    assert not result.ok


def test_containers_are_cleaned_up_even_when_the_client_fails(tmp_path):
    removed: list[list[str]] = []

    def fake_run(args, *, timeout=600.0):
        if args[:3] == ["docker", "rm", "-f"] or args[:3] == ["docker", "network", "rm"]:
            removed.append(args)
        if args[:2] == ["docker", "version"] or args[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "1\n", "")
        if args[:3] == ["docker", "run", "--rm"]:
            return subprocess.CompletedProcess(args, 4, "DIRECT=blocked\nTUNNELLED=no\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    with patch.object(bypass, "_run", fake_run), \
         patch.object(bypass, "_repo_root", return_value=tmp_path), \
         patch.object(bypass, "_keypair"):
        bypass.run_bypass_test()

    assert any(a[:3] == ["docker", "rm", "-f"] for a in removed)
    assert any(a[:3] == ["docker", "network", "rm"] for a in removed)
