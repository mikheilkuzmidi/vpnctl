"""The menu's key handling, and that the probe reports its phases."""

from __future__ import annotations

import io
import sys

import pytest

from vpnctl import menu
from vpnctl.probe import _parse_loss, _parse_rtts


def _read_with(text: str) -> str:
    saved = sys.stdin
    sys.stdin = io.StringIO(text)
    try:
        return menu.read_key()
    finally:
        sys.stdin = saved


@pytest.mark.parametrize(
    "keys,expected",
    [
        ("\x1b[A", menu.UP),
        ("\x1b[B", menu.DOWN),
        ("k", menu.UP),
        ("j", menu.DOWN),
        ("\r", menu.ENTER),
        ("\n", menu.ENTER),
        ("q", menu.QUIT),
        ("\x03", menu.QUIT),
        ("z", menu.OTHER),
    ],
)
def test_keys_map_to_intents(keys: str, expected: str) -> None:
    assert _read_with(keys) == expected


def test_bare_escape_quits_rather_than_selecting() -> None:
    # A lone Escape must not fall through to OTHER and leave the user stuck.
    assert _read_with("\x1bx") == menu.QUIT


def test_menu_refuses_without_a_terminal() -> None:
    saved = sys.stdin
    sys.stdin = io.StringIO("")
    try:
        with pytest.raises(menu.NotATerminal):
            with menu.raw_mode():
                pass
    finally:
        sys.stdin = saved


PING_OUTPUT = """PING 1.1.1.1 (1.1.1.1): 56 data bytes

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 9 packets received, 10.0% packet loss
round-trip min/avg/max/stddev = 12.345/15.678/20.111/2.345 ms
"""


def test_rtt_and_loss_come_from_one_ping_run() -> None:
    # Both used to be read by separate functions that each ran their own ping,
    # which doubled the time a probe spent saying nothing.
    assert _parse_rtts(PING_OUTPUT) == [12.345, 15.678]
    assert _parse_loss(PING_OUTPUT) == 10.0


def test_loss_is_absent_rather_than_zero_when_ping_says_nothing() -> None:
    assert _parse_loss("no statistics here") is None
