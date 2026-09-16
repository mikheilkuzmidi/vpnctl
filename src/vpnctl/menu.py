"""An arrow-key menu, so the tool can be used without memorising commands.

Built on termios and rich rather than a prompt library. This package's whole
dependency list is click, rich, httpx and tomli-w, and a single-select menu is
not worth a fifth entry.

Raw keys rather than typed input for the same reason the rest of the
interface is careful: connect, disconnect and benchmark all change network
state, and an arrow key cannot be mistyped the way a command name can.

Two pieces of the shape are deliberate.

The list and the explanation sit side by side. An earlier version printed
every entry's hint under its label, which meant the screen was mostly hints,
and the one entry the user was actually looking at was not distinguished by
anything except two characters of cursor. Now only the highlighted entry is
explained, and there is room to explain it properly: Connect can say which
provider it will use and that it will ask for a password, which is the
question people actually have.

Nothing is hand-wrapped any more, and nothing draws a border. The old code
wrapped hints itself at a fixed 72 columns because a rich Text has no hanging
indent, and then a terminal exactly 80 columns wide clamped the panel and
re-wrapped the already-wrapped text, collapsing the indent to column one.
A table cell has its own width and wraps inside it, so the whole class of
problem is gone.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional, Sequence, Union

from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from vpnctl.render import GUTTER, NARROW

UP = "up"
DOWN = "down"
RIGHT = "right"
LEFT = "left"
ENTER = "enter"
QUIT = "quit"
OTHER = "other"

#: Returned by select() when the user asked to go up a level rather than
#: choosing anything. Distinct from None, which means quit entirely.
BACK = "back"

# Below this there is no useful two-pane layout. Labels plus the cursor and
# the submenu marker need about 22 columns, so at 60 the detail pane gets 35,
# where two sentences plus a fact run to a dozen lines against a seven row
# list: the body ends up driven by the prose and the list looks stranded.
# 72 leaves 47 columns, which is where two sentences fit in three lines.
_TWO_PANE_MIN = 72

# How wide the list column is allowed to get before the detail pane starts
# losing more than it gains. The longest shipped label is 26 characters and a
# row costs 4 for the cursor plus 3 for a submenu marker, so anything under
# 33 truncated a real entry at every terminal size.
_LIST_WIDTH = 33


class NotATerminal(RuntimeError):
    """Raised when stdin cannot be put into raw mode."""


@dataclass
class MenuEntry:
    """One line of a menu, and what it means.

    action is a dotted command path ("split-tunnel.list") resolved by the
    caller, or None for an entry that only opens a submenu. children makes it
    a submenu. detail is what the right pane shows and may be several
    sentences; hint is the one-line version, used when there is no detail and
    when listing a submenu's contents.
    """

    label: str
    action: Optional[str] = None
    hint: str = ""
    detail: str = ""
    children: list["MenuEntry"] = field(default_factory=list)
    #: Extra arguments for the command, keyed by Python parameter name rather
    #: than by flag, because ctx.invoke takes keyword arguments.
    kwargs: dict = field(default_factory=dict)
    #: (parameter, question) for a value to ask for before invoking. Needed
    #: because ctx.invoke fills defaults but does not enforce required=True,
    #: so a required parameter with no default silently arrives as None.
    prompt: Optional[tuple[str, str]] = None

    @property
    def is_submenu(self) -> bool:
        return bool(self.children)

    def explanation(self) -> str:
        return self.detail or self.hint


Option = Union[MenuEntry, tuple]


def _coerce(options: Sequence[Option]) -> list[MenuEntry]:
    """Accept (label, hint) pairs as well as entries, for the simple callers."""
    entries: list[MenuEntry] = []
    for option in options:
        if isinstance(option, MenuEntry):
            entries.append(option)
        else:
            label, hint = option[0], option[1] if len(option) > 1 else ""
            entries.append(MenuEntry(label=label, hint=hint))
    return entries


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
        # cbreak rather than raw, so Ctrl-C still raises KeyboardInterrupt
        # instead of arriving as a byte nobody handles.
        tty.setcbreak(fd)
        # cbreak leaves ECHO on, which prints every arrow key as ^[[B. The
        # redraw usually wipes it within a frame, so it reads as flicker
        # rather than as text, and whatever is on screen when the menu exits
        # keeps it. Turning ECHO off is the whole fix.
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
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
        return {"A": UP, "B": DOWN, "C": RIGHT, "D": LEFT}.get(
            sys.stdin.read(1), OTHER
        )

    if ch in ("\r", "\n"):
        return ENTER
    if ch in ("q", "Q", "\x03"):
        return QUIT
    if ch in ("k", "K"):
        return UP
    if ch in ("j", "J"):
        return DOWN
    if ch in ("l", "L"):
        return RIGHT
    if ch in ("h", "H"):
        return LEFT
    return OTHER


def _list_column(
    entries: list[MenuEntry], index: int, width: Optional[int] = None
) -> Text:
    """The list of labels, one per line, with the cursor on the selected one.

    Labels are truncated rather than wrapped. A wrapped label puts its
    continuation at column zero, outside the list column and across the
    divider, which is the same failure the old hand-wrapped hints had: the
    fix is for a line in this column to always be one line.
    """
    body = Text()
    for position, entry in enumerate(entries):
        selected = position == index
        marker = "  >" if entry.is_submenu else ""
        label = entry.label
        if width is not None:
            # 4 for the cursor and its indent, plus whatever the marker takes.
            room = width - 4 - len(marker)
            if room > 1 and len(label) > room:
                label = label[: room - 1] + "\u2026"
        body.append("  ")
        body.append("> " if selected else "  ", style="cyan" if selected else "")
        body.append(label, style="bold" if selected else "")
        if marker:
            # A marker to the right of the label, so a submenu is visibly a
            # place you go into rather than an action that runs.
            body.append(marker, style="dim")
        if position < len(entries) - 1:
            body.append("\n")
    return body


def _detail_column(entry: MenuEntry) -> Group:
    parts: list = [Text(entry.label, style="bold"), Text()]
    explanation = entry.explanation()
    if explanation:
        parts.append(Text(explanation))
    if entry.is_submenu:
        parts.append(Text())
        for child in entry.children:
            line = Text("  ")
            line.append(child.label, style="none")
            parts.append(line)
    return Group(*parts)


def _wrap(console: Console, renderable, width: int) -> list[Text]:
    """Render something to a fixed width and return its styled lines.

    Wrapping happens here, once, at the width the cell will actually be. The
    old code wrapped by hand at a fixed 72 and then let rich re-wrap the
    result when the panel was clamped, which is how the hanging indent
    collapsed at exactly 80 columns. Pre-wrapped lines in a fixed-width
    no-wrap cell cannot be re-flowed, so that cannot happen again.

    The styles have to be carried across by hand. render_lines puts them on
    Segment.style, not as escapes inside Segment.text, so joining the text
    and nothing else silently dropped every one: the cursor lost its colour
    and the selected label its weight, in the two-pane branch only, which is
    the one a normal terminal uses. The highlight was two characters of "> "
    and nothing more.
    """
    lines: list[Text] = []
    for segments in console.render_lines(
        renderable, console.options.update(width=width), pad=False
    ):
        line = Text()
        for segment in segments:
            line.append(segment.text, style=segment.style)
        lines.append(line)
    return lines


def render(
    console: Console,
    title: str,
    entries: list[MenuEntry],
    index: int,
    *,
    status: str = "",
    allow_back: bool = False,
    footer: Optional[list[tuple[str, str]]] = None,
) -> None:
    """Draw one frame of the menu. Separated out so tests can call it."""
    from vpnctl import render as layout

    console.clear()
    layout.header(console, title, status or None)

    entry = entries[index]
    if console.width < _TWO_PANE_MIN:
        # No room for two columns. The list alone still works, with only the
        # highlighted entry explained underneath: printing every entry's hint
        # is what made the old screen mostly hints.
        console.print(_list_column(entries, index, console.width - 2))
        console.print()
        for line in _wrap(console, _detail_column(entry), console.width - 4):
            console.print(Text("  ") + line, style="dim")
    else:
        # A row is 4 for the indent and cursor, the label, and 3 more when
        # the entry opens a submenu. Budgeting label + 6 was one short of
        # that, so the longest label in any level containing a submenu was
        # always truncated.
        widest = max(
            len(e.label) + (3 if e.is_submenu else 0) for e in entries
        )
        list_width = min(
            widest + 4 + GUTTER,
            max(18, console.width // 2),
            _LIST_WIDTH + GUTTER,
        )
        detail_width = console.width - list_width - 3

        left = _wrap(console, _list_column(entries, index, list_width), list_width)
        right = _wrap(console, _detail_column(entry), detail_width)

        # One grid row per body line, so the divider runs the full height of
        # whichever column is taller. Building it from len(entries) left the
        # divider short whenever the detail was longer than the list.
        body = Table(box=None, show_header=False, pad_edge=False, padding=(0, 0))
        body.add_column("list", width=list_width, no_wrap=True)
        body.add_column("divider", width=3, no_wrap=True)
        body.add_column("detail", width=detail_width, no_wrap=True)
        blank = Text("")
        for position in range(max(len(left), len(right))):
            body.add_row(
                left[position] if position < len(left) else blank,
                Text(" \u2502 ", style="dim"),
                right[position] if position < len(right) else blank,
            )
        console.print(body)

    layout.keys(console, footer or _default_footer(entries, allow_back))


def _default_footer(
    entries: list[MenuEntry], allow_back: bool = False
) -> list[tuple[str, str]]:
    """The keys this level actually responds to.

    It used to advertise "right open" whenever any entry was a submenu, so
    right-arrow on Connect looked like navigation and instead ran a command
    that moves the default route. And it never named the back key even when
    there was one to name.
    """
    bindings = [("up down", "move"), ("enter", "choose")]
    if any(entry.is_submenu for entry in entries):
        bindings.append(("right", "open"))
    if allow_back:
        bindings.append(("left", "back"))
    bindings.append(("q", "quit"))
    return bindings


def select(
    console: Console,
    title: str,
    options: Sequence[Option],
    *,
    subtitle: str = "",
    status: str = "",
    allow_back: bool = False,
) -> Union[int, str, None]:
    """Show a single-select list and return the chosen index.

    Returns the index for enter or right, BACK for left or escape when
    allow_back is set, and None to quit. Three outcomes rather than two
    because a tree needs to distinguish "go up" from "give up", and the
    caller owns the stack.
    """
    entries = _coerce(options)
    if not entries:
        return None

    index = 0
    while True:
        render(
            console,
            title,
            entries,
            index,
            status=status or subtitle,
            allow_back=allow_back,
        )

        key = read_key()
        if key == UP:
            index = (index - 1) % len(entries)
        elif key == DOWN:
            index = (index + 1) % len(entries)
        elif key == ENTER:
            return index
        elif key == RIGHT:
            # Only opens. Enter stays the one key that runs anything, since
            # connect, disconnect and benchmark all change network state and
            # a stray arrow while browsing should not trigger one.
            if entries[index].is_submenu:
                return index
        elif key == LEFT:
            if allow_back:
                return BACK
        elif key == QUIT:
            # q quits, from any depth. Returning BACK here meant three
            # levels down needed three presses, while the footer promised
            # quit the whole time.
            return None
