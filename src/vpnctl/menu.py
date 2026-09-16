"""An arrow-key menu, so the tool can be used without memorising commands.

Built on termios and rich rather than a prompt library. This package's whole
dependency list is click, rich, httpx and tomli-w, and a single-select menu is
not worth a fifth entry.

Raw keys rather than typed input for the same reason the rest of the interface
is careful: connect, disconnect and benchmark all change network state, and an
arrow key cannot be mistyped the way a command name can.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

UP = "up"
DOWN = "down"
ENTER = "enter"
QUIT = "quit"
OTHER = "other"


class NotATerminal(RuntimeError):
    """Raised when stdin cannot be put into raw mode."""


@contextmanager
def raw_mode():
    """Put the terminal into cbreak mode for the duration of the block."""
    if not sys.stdin.isatty():
        raise NotATerminal("stdin is not a terminal")

    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        # Restore whatever happened, or the shell is left without echo and the
        # user has to type `reset` blind.
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def read_key() -> str:
    """Block for one keypress and return one of the constants above."""
    ch = sys.stdin.read(1)

    if ch == "\x1b":
        # An escape sequence, or a bare Escape. Arrows arrive as ESC [ A.
        nxt = sys.stdin.read(1)
        if nxt != "[":
            return QUIT
        return {"A": UP, "B": DOWN}.get(sys.stdin.read(1), OTHER)

    if ch in ("\r", "\n"):
        return ENTER
    if ch in ("q", "Q", "\x03"):
        return QUIT
    if ch in ("k", "K"):
        return UP
    if ch in ("j", "J"):
        return DOWN
    return OTHER


def select(
    console: Console,
    title: str,
    options: list[tuple[str, str]],
    *,
    subtitle: str = "",
) -> Optional[int]:
    """Show a single-select list and return the chosen index, or None.

    options is a list of (label, hint) pairs.
    """
    index = 0
    while True:
        console.clear()
        body = Text()
        for position, (label, hint) in enumerate(options):
            selected = position == index
            body.append("  ")
            body.append("> " if selected else "  ", style="cyan" if selected else "")
            body.append(label + "\n", style="bold" if selected else "")
            if hint:
                body.append(f"      {hint}\n", style="dim")
        body.append("\n  up and down to move, enter to choose, q to quit", style="dim")
        console.print(Panel(body, title=title, subtitle=subtitle or None, border_style="cyan"))

        key = read_key()
        if key == UP:
            index = (index - 1) % len(options)
        elif key == DOWN:
            index = (index + 1) % len(options)
        elif key == ENTER:
            return index
        elif key == QUIT:
            return None
