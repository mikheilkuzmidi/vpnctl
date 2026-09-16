"""The menu's key handling, and that the probe reports its phases."""

from __future__ import annotations

import io
import sys

import pytest
from unittest.mock import patch

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


def test_raw_mode_turns_echo_off_and_leaves_signals_on(monkeypatch):
    """Arrow keys must not print themselves, but Ctrl-C must still work."""
    import termios

    import pytest

    class FakeStdin:
        def isatty(self) -> bool:
            return True

        def fileno(self) -> int:
            return 0

    # lflag starts with both ECHO and ISIG set, as a normal terminal has.
    state = [0, 0, 0, termios.ECHO | termios.ISIG, 0, 0, [b""] * 32]
    applied: list[list] = []

    monkeypatch.setattr(termios, "tcgetattr", lambda fd: list(state))
    monkeypatch.setattr(
        termios, "tcsetattr", lambda fd, when, attrs: applied.append(list(attrs))
    )
    monkeypatch.setattr("tty.setcbreak", lambda fd: None)
    monkeypatch.setattr("sys.stdin", FakeStdin())

    with menu.raw_mode():
        pass

    inside = applied[0]
    assert not inside[3] & termios.ECHO, "ECHO must be cleared"
    assert inside[3] & termios.ISIG, "ISIG must survive, or Ctrl-C is swallowed"
    assert applied[-1][3] == state[3], "the original flags must be restored"


def test_a_long_hint_wraps_with_its_indent_kept():
    """A Text has no hanging indent, so wrapping has to be done here.

    Left to rich, a hint long enough to wrap continued at column zero,
    outside the panel's padding, which read as a broken border.
    """
    from rich.console import Console

    console = Console(width=100, record=True, force_terminal=False)
    long_hint = (
        "An anonymous Cloudflare WARP device with no account, no payment and "
        "no limit on how much you use it, which is quite a long hint indeed."
    )
    with patch.object(menu, "read_key", return_value=menu.ENTER):
        menu.select(console, "t", [("Pick me", long_hint)])

    lines = [line for line in console.export_text().splitlines() if line.strip()]
    hint_lines = [
        line for line in lines if "Cloudflare" in line or "quite a long hint" in line
    ]
    assert len(hint_lines) > 1, "the hint should have wrapped"
    for line in hint_lines:
        # Inside the border, and indented under its label.
        body = line.lstrip("│ ").rstrip("│ ")
        assert line.lstrip().startswith("│"), line
        assert body, line
    # Every wrapped line carries the same indent as the first.
    indents = {len(line) - len(line.lstrip(" ")) for line in
               [l.split("│")[1] for l in hint_lines if "│" in l]}
    assert len(indents) == 1, f"inconsistent indents: {indents}"
