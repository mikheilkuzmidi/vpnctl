"""Live TUI monitor for vpnctl.

Displays real-time VPN metrics in the terminal using rich.Live:
  - Connection status per provider
  - RTT, jitter, packet loss, download speed
  - Rolling sparkline history
  - Split-tunnel configuration

Probe loop runs in a background thread; the display refreshes every 0.5 s.
Press Ctrl-C to quit.
"""

from __future__ import annotations

import statistics
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vpnctl.config import load_config
from vpnctl.providers.base import ProviderStatus
from vpnctl.selector import build_providers


# ---------------------------------------------------------------------------
# Probe constants (lighter than the full benchmark probe)
# ---------------------------------------------------------------------------

_PING_HOST = "1.1.1.1"
_PING_COUNT = 4
_DL_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
# How many samples to keep. Previously this was also the display width,
# which is why anything narrower than 88 columns silently dropped the oldest
# readings: rich truncated the row and added an ellipsis. Storage is cheap,
# so keep plenty and let the display decide how much of it fits.
_HISTORY = 512
_FAST_INTERVAL = 5      # seconds between RTT-only probes
_SLOW_INTERVAL = 30     # seconds between full (RTT + download) probes

# ---------------------------------------------------------------------------
# Sparkline
# ---------------------------------------------------------------------------

_SPARKS = " ▁▂▃▄▅▆▇█"


def _sparkline(values: list[float], width: int = 24) -> str:
    """Render the most recent values as bars, scaled to their own range.

    A sample never renders as a blank. Scaling min to the first character of
    _SPARKS, which is a space, meant the lowest reading in the window was
    invisible and a steady connection drew nothing at all: two readings of
    15ms and 28ms showed one bar, and two identical readings showed none.
    So the bars start at _SPARKS[1], and a range too narrow to plot reads as
    a steady mid-height line rather than a flat line at the bottom. The
    absolute numbers are on the row underneath either way.

    Two things about which samples are drawn, and where.

    The window is taken before the scaling, not after. Taking min and max
    over every stored value and then drawing only the last few meant the
    visible bars were scaled against readings that had scrolled off, so a
    spike ten minutes ago flattened everything still on screen.

    And the bars are right aligned, so the newest sample is always at the
    right edge and a half-filled buffer reads as "not enough history yet".
    Left aligned, the blank space sat after the newest reading, which reads
    as the recent samples being the missing ones. That matters most for the
    download series, which gains one sample every thirty seconds.
    """
    if not values:
        return " " * width
    window = list(values)[-width:]
    lo, hi = min(window), max(window)
    levels = len(_SPARKS) - 1  # index 0 is the blank, reserved for no data
    if hi - lo < max(hi, 1.0) * 0.02:
        return (_SPARKS[levels // 2] * len(window)).rjust(width)
    span = hi - lo
    chars = [
        _SPARKS[1 + round((v - lo) / span * (levels - 1))] for v in window
    ]
    return "".join(chars).rjust(width)


# ---------------------------------------------------------------------------
# Shared probe state (written by bg thread, read by render thread)
# ---------------------------------------------------------------------------

@dataclass
class ProbeState:
    rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loss_pct: Optional[float] = None
    dl_mbps: Optional[float] = None
    score: Optional[float] = None
    error: Optional[str] = None
    last_updated: Optional[float] = None
    probe_count: int = 0

    rtt_history: deque = field(default_factory=lambda: deque(maxlen=_HISTORY))
    dl_history: deque = field(default_factory=lambda: deque(maxlen=_HISTORY))

    #: provider_id -> status, refreshed by the probe thread.
    #:
    #: The renderer used to call p.status() for every provider on every
    #: frame. At two frames a second, with wg show and warp-cli status behind
    #: those calls, that was several subprocesses per second for as long as
    #: the monitor stayed open. It is a background concern, so it lives with
    #: the other background concerns.
    provider_status: dict = field(default_factory=dict)

    #: The last few probes, newest last, for the region that fills whatever
    #: height is left. The data was already being computed and discarded.
    events: deque = field(default_factory=lambda: deque(maxlen=200))

    lock: threading.Lock = field(default_factory=threading.Lock)


# ---------------------------------------------------------------------------
# Background probe functions
# ---------------------------------------------------------------------------

def _quick_ping(host: str = _PING_HOST, count: int = _PING_COUNT
                ) -> tuple[Optional[float], Optional[float], float]:
    """Returns (median_rtt_ms, jitter_ms, loss_pct)."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-q", host],
            capture_output=True, text=True,
            timeout=count * 2 + 5, check=False,
        )
        rtts: list[float] = []
        loss = 100.0
        for line in result.stdout.splitlines():
            if "round-trip" in line or "rtt" in line:
                parts = line.split("=")[-1].strip().split("/")
                if len(parts) >= 2:
                    try:
                        rtts += [float(parts[0].strip()), float(parts[1].strip())]
                    except ValueError:
                        pass
            if "packet loss" in line:
                for tok in line.split():
                    if "%" in tok:
                        try:
                            loss = float(tok.replace("%", ""))
                        except ValueError:
                            pass
        if rtts:
            med = statistics.median(rtts)
            jit = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
            return med, jit, loss
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None, None, 100.0


def _quick_download() -> float:
    """Return Mbps; 0.0 on failure."""
    try:
        import httpx
        start = time.monotonic()
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(_DL_URL)
            resp.read()
        elapsed = time.monotonic() - start
        return len(resp.content) * 8 / elapsed / 1_000_000 if elapsed > 0 else 0.0
    except (httpx.HTTPError, OSError):
        return 0.0


def _probe_loop(state: ProbeState, stop: threading.Event, providers=()) -> None:
    last_dl = 0.0
    while not stop.is_set():
        rtt, jit, loss = _quick_ping()
        now = time.monotonic()
        do_dl = (now - last_dl) >= _SLOW_INTERVAL

        dl = _quick_download() if do_dl else None
        if do_dl:
            last_dl = now

        # Provider status belongs here rather than in the renderer. Asking
        # each adapter runs wg show, and on macOS warp-cli status; at two
        # frames a second that was several subprocesses per second for as
        # long as the monitor was open.
        statuses = {}
        for provider in providers:
            try:
                statuses[provider.provider_id] = provider.status()
            except Exception:
                statuses[provider.provider_id] = ProviderStatus.UNKNOWN

        with state.lock:
            state.rtt_ms = rtt
            state.jitter_ms = jit
            state.loss_pct = loss
            state.last_updated = time.time()
            state.probe_count += 1
            if rtt is not None:
                state.rtt_history.append(rtt)
            if dl is not None:
                state.dl_mbps = dl
                state.dl_history.append(dl)
            if statuses:
                state.provider_status = statuses
            state.events.append(
                (
                    time.time(),
                    rtt,
                    jit,
                    loss,
                    dl,
                )
            )

        stop.wait(_FAST_INTERVAL)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt(value: Optional[float], unit: str, decimals: int = 1,
         warn: float = 9000.0) -> Text:
    """Format a metric where a bigger number is worse: latency, jitter, loss."""
    if value is None:
        return Text("-", style="dim")
    s = f"{value:.{decimals}f} {unit}"
    style = "red bold" if value >= warn else ("yellow" if value >= warn * 0.5 else "green")
    return Text(s, style=style)


def _fmt_throughput(value: Optional[float], floor: float) -> Text:
    """Format a metric where a bigger number is better.

    Download used to go through _fmt with warn=0.1, but warn means "red at or
    above this", so every usable connection was reported in red bold and a
    connection managing 0.05 Mbps was reported in green.
    """
    if value is None:
        return Text("-", style="dim")
    s = f"{value:.2f} Mbps"
    if value < floor:
        return Text(s, style="red bold")
    if value < floor * 5:
        return Text(s, style="yellow")
    return Text(s, style="green")


def _status_badge(s: ProviderStatus) -> Text:
    if s == ProviderStatus.CONNECTED:
        return Text("● CONNECTED", style="bold green")
    if s == ProviderStatus.CONNECTING:
        return Text("◌ CONNECTING…", style="bold yellow")
    if s == ProviderStatus.DISCONNECTED:
        return Text("○ DISCONNECTED", style="dim red")
    return Text("? UNKNOWN", style="dim")


def _regions(height: int, providers: int, excludes: int) -> dict[str, int]:
    """How many rows each part of the screen gets, computed not clipped.

    The old layout split the terminal into a fixed header, a fixed footer and
    a body divided in half, then put two panels in it. At 80x30 that left ten
    consecutive rows where both panels were entirely blank, and the waste grew
    with the terminal because nothing was height-capped: twenty blank rows at
    120x40.

    The content is about fourteen lines, so filling thirty rows means either
    padding or something worth showing. The probe log is the latter: the
    samples were already being measured and thrown away, and a latency spike
    is visible as it happens. It absorbs whatever is left, so nothing pads at
    any size, and it is the first thing to shrink when there is not enough.
    """
    fixed = {
        "header": 1,
        "metrics": 3,
        "history": 3,
        "providers": 2 if providers else 0,
        "split": 1 + min(excludes, 4) if excludes else 1,
        "footer": 2,
    }
    if height - sum(fixed.values()) < 3:
        # Not enough room for a log worth reading, so give the space back to
        # the split-tunnel list instead of showing two lines of history.
        fixed["split"] = 1
    # The log deliberately has no entry here: its height is measured from
    # what the rest actually took, because predicting it is what made the
    # screen run over the terminal in the first place.
    return fixed


def _metrics_strip(state: ProbeState, connected: bool, width: int = 80) -> Text:
    """The four numbers, side by side.

    Horizontal rather than a vertical key/value table. Spending width, which
    was 45 to 68 percent idle, instead of height is what actually removes the
    blank rows.
    """
    with state.lock:
        rtt, jit, loss, dl = (
            state.rtt_ms,
            state.jitter_ms,
            state.loss_pct,
            state.dl_mbps,
        )

    if not connected:
        line = Text("  ")
        line.append("no tunnel is up", style="yellow")
        line.append("   this machine's traffic is not protected", style="dim")
        return line

    metrics = [
        ("rtt", _fmt(rtt, "ms", warn=200)),
        ("jitter", _fmt(jit, "ms", warn=50)),
        ("loss", _fmt(loss, "%", warn=5)),
        ("down", _fmt_throughput(dl, floor=1.0)),
    ]
    # Four on one line needs about 66 columns. Below that they wrap, and a
    # wrapped metric strip is worse than two deliberate lines of two.
    per_line = 4 if width >= 72 else 2
    lines: list[Text] = []
    for start in range(0, len(metrics), per_line):
        line = Text("  ")
        for label, value in metrics[start : start + per_line]:
            line.append(f"{label} ", style="dim")
            line.append_text(value)
            line.append("    ")
        lines.append(line)
    return Text("\n").join(lines)


def _history_block(state: ProbeState, width: int) -> Text:
    """Both sparklines, sized to the terminal.

    The width used to be the same constant as the deque's maxlen, so anything
    narrower than 88 columns quietly dropped the oldest readings.
    """
    with state.lock:
        rtt_hist = list(state.rtt_history)
        dl_hist = list(state.dl_history)

    # 9 for the label, 18 for the range, plus padding.
    spark = max(12, width - 30)
    lines: list[Text] = []
    for label, values, unit, style in (
        ("rtt ms", rtt_hist, "ms", "green"),
        ("down", dl_hist, "Mbps", "blue"),
    ):
        line = Text(f"  {label:<8}", style="dim")
        line.append(_sparkline(values, spark), style=style)
        if values:
            window = values[-spark:]
            line.append(f"  {min(window):.0f}-{max(window):.0f} {unit}", style="dim")
        else:
            line.append("  collecting", style="dim")
        lines.append(line)
    return Text("\n").join(lines)


def _providers_line(state: ProbeState, providers) -> Text:
    """Every provider on one line while they fit."""
    with state.lock:
        statuses = dict(state.provider_status)

    line = Text("  ")
    for provider in providers:
        status = statuses.get(provider.provider_id)
        if status == ProviderStatus.CONNECTED:
            dot, style = "\u25cf", "green"
        elif status == ProviderStatus.CONNECTING:
            dot, style = "\u25cc", "yellow"
        elif status is None:
            dot, style = "\u00b7", "dim"
        else:
            dot, style = "\u25cb", "dim"
        line.append(dot + " ", style=style)
        line.append(provider.provider_id, style="dim")
        if provider.is_control:
            line.append(" control", style="dim")
        line.append("   ")
    return line


def _log_block(state: ProbeState, rows: int, width: int = 80) -> Text:
    """The last few probes, newest last.

    Every line has to fit on one row. A wrapped entry makes the block taller
    than it was allocated, which pushed the footer off the bottom at 60
    columns: the throughput reading is the first thing to go, since it only
    appears on one line in six anyway.
    """
    with state.lock:
        events = list(state.events)[-rows:]

    lines: list[Text] = []
    for when, rtt, jit, loss, dl in events:
        stamp = datetime.fromtimestamp(when).strftime("%H:%M:%S")
        line = Text(f"  {stamp}  ", style="dim")
        line.append("rtt ", style="dim")
        line.append(f"{rtt:.1f}" if rtt is not None else "-", style="none")
        line.append("   jitter ", style="dim")
        line.append(f"{jit:.1f}" if jit is not None else "-", style="none")
        line.append("   loss ", style="dim")
        line.append(f"{loss:.1f}%" if loss is not None else "-", style="none")
        suffix = f"   down {dl:.2f} Mbps" if dl is not None else ""
        if suffix and len(line.plain) + len(suffix) <= width:
            line.append("   down ", style="dim")
            line.append(f"{dl:.2f} Mbps", style="none")
        # Anything still over is truncated rather than wrapped.
        if len(line.plain) > width:
            line = Text(line.plain[:width])
        lines.append(line)
    return Text("\n").join(lines)


def _build_layout(state: ProbeState, providers, cfg) -> Group:
    """The whole screen, as a group of exactly-sized pieces.

    A Group rather than a Layout of Panels: a panel border costs two rows and
    two columns for no information, and four of them are what produced the
    blank middle of the screen.
    """
    console = Console()
    width, height = console.width, console.height

    with state.lock:
        statuses = dict(state.provider_status)
        count = state.probe_count
        last = state.last_updated

    tunnels = [p for p in providers if not p.is_control]
    connected = next(
        (
            p.provider_id
            for p in tunnels
            if statuses.get(p.provider_id) == ProviderStatus.CONNECTED
        ),
        None,
    )
    excludes = cfg.split_tunnel.excludes if cfg.split_tunnel.enabled else []
    regions = _regions(height, len(providers), len(excludes))

    age = f"{time.time() - last:.0f}s ago" if last else "never"
    status = (
        f"{connected} \u25cf connected" if connected else "\u25cb not connected"
    )

    pieces: list = []
    head = Text("  vpnctl ", style="bold cyan")
    head.append("live monitor", style="cyan")
    pad = width - len(head.plain) - len(status) - len(age) - 5
    head.append(" " * max(1, pad))
    head.append(status, style="green" if connected else "dim")
    head.append(f"   {age}", style="dim")
    pieces.append(head)

    pieces.append(Rule(style="dim"))
    pieces.append(_metrics_strip(state, connected is not None, width))
    pieces.append(Text(f"  probe {count}", style="dim"))
    pieces.append(Rule(style="dim"))
    pieces.append(_history_block(state, width))
    pieces.append(Rule(style="dim"))

    if providers:
        pieces.append(_providers_line(state, providers))

    # Everything above is fixed. Measure it, and share what is left between
    # the split-tunnel list and the probe log, always keeping one row for the
    # footer. Predicting these heights is what put the screen over the
    # terminal twice: once for the "+N more" line, once for a metrics strip
    # that wraps to two lines at 60 columns.
    def measured() -> int:
        return len(
            console.render_lines(Group(*pieces), console.options.update(width=width))
        )

    remaining = height - measured() - 1  # the footer
    split_budget = max(1, min(regions["split"], remaining - 1))

    split = Text("  split tunnel  ", style="dim")
    if excludes:
        split.append("\u25cf enabled", style="green")
        # One row for this line. If they all fit, the rest of the budget is
        # theirs; if they do not, one row has to be left for "+N more", which
        # is what the screen previously ran over the terminal height by.
        budget = max(0, split_budget - 1)
        shown = (
            excludes
            if len(excludes) <= budget
            else excludes[: max(0, budget - 1)]
        )
        for cidr in shown:
            split.append(f"\n                {cidr}", style="dim cyan")
        if len(excludes) > len(shown):
            split.append(
                f"\n                +{len(excludes) - len(shown)} more", style="dim"
            )
    else:
        split.append("\u25cb disabled", style="dim")
    pieces.append(split)

    # The log takes whatever is left after that, or is dropped entirely when
    # there is not enough for it to be worth reading.
    spare = height - measured() - 2  # the footer, and the rule above the log
    if spare >= 3:
        pieces.append(Rule(style="dim"))
        pieces.append(_log_block(state, spare, width))

    footer = Text("  ")
    footer.append("ctrl-c", style="bold cyan")
    footer.append(" quit", style="dim")
    footer.append(f"    probing every {_FAST_INTERVAL}s", style="dim")
    footer.append(f", speed every {_SLOW_INTERVAL}s", style="dim")
    pieces.append(footer)

    return Group(*pieces)


def run_tui() -> None:
    """Start the live TUI. Blocks until Ctrl-C."""
    cfg = load_config()
    providers = build_providers(cfg)
    console = Console()

    state = ProbeState()
    stop = threading.Event()

    probe_thread = threading.Thread(
        target=_probe_loop, args=(state, stop, providers), daemon=True
    )
    probe_thread.start()

    try:
        with Live(
            console=console,
            refresh_per_second=2,
            screen=True,
        ) as live:
            while True:
                live.update(
                    _build_layout(state, providers, cfg)
                )
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        probe_thread.join(timeout=2)
        console.print("\n[dim]Monitor stopped.[/dim]")
