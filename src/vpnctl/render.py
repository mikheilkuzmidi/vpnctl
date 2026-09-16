"""One way of drawing a screen.

Before this there were three. Two screens drew bordered panels, two drew
tables with a rule under the header, and about fifteen aligned themselves
with literal spaces inside f-strings at three different indent conventions.
`status` managed to be two of those at once.

The panels were the worst of it, because a panel sized to its content floats:
the setup screen was thirteen rows of box with seventeen empty rows below it
and eighteen empty columns to the right. Nothing here draws a border. A
screen is a header line, some blocks, and a footer of keys, all flush to the
left margin, which is how every other terminal program people already use
looks.

The helpers are deliberately few. A screen that needs something else should
print it plainly rather than growing this module.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

# Below this the two-pane menu has nowhere to put its detail column, and
# key/value blocks stop lining up usefully. Both fall back to one column.
NARROW = 60

# The gap between a label and its value, and between the two menu panes.
GUTTER = 2


def header(console: Console, title: str, status: Optional[str] = None) -> None:
    """The one line every screen starts with: what this is, and how it is.

    Title left, status right, so the eye finds the state in the same place on
    every screen rather than hunting for it in prose.
    """
    line = Text()
    line.append(title, style="bold")
    if status and console.width > NARROW:
        pad = console.width - len(title) - len(status)
        if pad > GUTTER:
            line.append(" " * pad)
            line.append(status, style="dim")
    elif status:
        line.append("  ")
        line.append(status, style="dim")
    console.print(line)
    console.print()


def rows(
    console: Console,
    pairs: Sequence[tuple[str, str]],
    *,
    indent: int = 2,
) -> None:
    """A key/value block, aligned once from the longest key.

    Every caller of this was previously padding labels by hand, which meant
    the alignment was a property of whoever typed the f-string. Values may
    carry rich markup; keys may not, because their width has to be known.
    """
    if not pairs:
        return
    width = max(len(key) for key, _ in pairs)
    table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 0))
    table.add_column("key", style="dim", width=indent + width + GUTTER)
    table.add_column("value", overflow="fold")
    for key, value in pairs:
        table.add_row(" " * indent + key.ljust(width + GUTTER), value)
    console.print(table)


def keys(console: Console, bindings: Iterable[tuple[str, str]]) -> None:
    """The footer line of key hints, in the order they are usually reached."""
    line = Text("  ")
    for index, (key, what) in enumerate(bindings):
        if index:
            line.append("   ")
        line.append(key, style="bold cyan")
        line.append(f" {what}", style="dim")
    console.print()
    console.print(line)


def verdict(console: Console, message: str, *, ok: bool = True) -> None:
    """The one-line conclusion a screen ends on."""
    console.print()
    console.print(f"[{'green' if ok else 'yellow'}]{message}[/]")
