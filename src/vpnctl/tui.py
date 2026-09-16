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
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
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
_HISTORY = 24           # sparkline width
_FAST_INTERVAL = 5      # seconds between RTT-only probes
_SLOW_INTERVAL = 30     # seconds between full (RTT + download) probes

# ---------------------------------------------------------------------------
# Sparkline
# ---------------------------------------------------------------------------

_SPARKS = " ▁▂▃▄▅▆▇█"


def _sparkline(values: list[float], width: int = _HISTORY) -> str:
    if not values:
        return " " * width
    lo, hi = min(values), max(values)
    span = hi - lo or 1.0
    chars = [_SPARKS[round((v - lo) / span * (len(_SPARKS) - 1))] for v in values]
    return "".join(chars[-width:]).ljust(width)


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


def _probe_loop(state: ProbeState, stop: threading.Event) -> None:
    last_dl = 0.0
    while not stop.is_set():
        rtt, jit, loss = _quick_ping()
        now = time.monotonic()
        do_dl = (now - last_dl) >= _SLOW_INTERVAL

        dl = _quick_download() if do_dl else None
        if do_dl:
            last_dl = now

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

        stop.wait(_FAST_INTERVAL)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt(value: Optional[float], unit: str, decimals: int = 1,
         warn: float = 9000.0) -> Text:
    if value is None:
        return Text("-", style="dim")
    s = f"{value:.{decimals}f} {unit}"
    style = "red bold" if value >= warn else ("yellow" if value >= warn * 0.5 else "green")
    return Text(s, style=style)


def _status_badge(s: ProviderStatus) -> Text:
    if s == ProviderStatus.CONNECTED:
        return Text("● CONNECTED", style="bold green")
    if s == ProviderStatus.CONNECTING:
        return Text("◌ CONNECTING…", style="bold yellow")
    if s == ProviderStatus.DISCONNECTED:
        return Text("○ DISCONNECTED", style="dim red")
    return Text("? UNKNOWN", style="dim")


def _build_layout(state: ProbeState, providers, cfg) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1),
    )

    # ---- Header --------------------------------------------------------
    ts = datetime.now().strftime("%H:%M:%S")
    header_text = Text()
    header_text.append("  vpnctl ", style="bold cyan")
    header_text.append("live monitor", style="cyan")
    header_text.append(f"   {ts}", style="dim")
    layout["header"].update(Panel(Align.center(header_text), style="cyan"))

    # ---- Left: status + metrics ----------------------------------------
    metrics_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    metrics_table.add_column("key", style="dim", width=14)
    metrics_table.add_column("value")

    with state.lock:
        rtt = state.rtt_ms
        jit = state.jitter_ms
        loss = state.loss_pct
        dl = state.dl_mbps
        last_up = state.last_updated
        count = state.probe_count

    age = f"{time.time() - last_up:.0f}s ago" if last_up else "never"

    # Provider rows
    any_connected = False
    status_lines: list[tuple[str, Text]] = []
    for p in providers:
        s = p.status()
        if s == ProviderStatus.CONNECTED:
            any_connected = True
        status_lines.append((p.provider_id, _status_badge(s)))

    for pid, badge in status_lines:
        metrics_table.add_row(pid, badge)

    metrics_table.add_row("", Text(""))

    if not any_connected:
        metrics_table.add_row("RTT", Text("- (not connected)", style="dim"))
        metrics_table.add_row("Jitter", Text("-", style="dim"))
        metrics_table.add_row("Loss", Text("-", style="dim"))
        metrics_table.add_row("Download", Text("-", style="dim"))
    else:
        metrics_table.add_row("RTT", _fmt(rtt, "ms", warn=200))
        metrics_table.add_row("Jitter", _fmt(jit, "ms", warn=50))
        metrics_table.add_row("Loss", _fmt(loss, "%", decimals=1, warn=5))
        metrics_table.add_row("Download", _fmt(dl, "Mbps", decimals=2, warn=0.1))

    metrics_table.add_row("", Text(""))
    metrics_table.add_row("Probes", Text(str(count), style="dim"))
    metrics_table.add_row("Last probe", Text(age, style="dim"))

    layout["left"].update(Panel(metrics_table, title="[bold]Connection & Metrics[/bold]"))

    # ---- Right: sparklines + split tunnel ------------------------------
    with state.lock:
        rtt_hist = list(state.rtt_history)
        dl_hist = list(state.dl_history)

    right_table = Table(box=None, show_header=False, padding=(0, 1))
    right_table.add_column("label", style="dim", width=12)
    right_table.add_column("spark")

    rtt_spark = _sparkline(rtt_hist)
    dl_spark = _sparkline(dl_hist)

    rtt_range = (
        f"{min(rtt_hist):.0f}-{max(rtt_hist):.0f} ms" if rtt_hist else "-"
    )
    dl_range = (
        f"{min(dl_hist):.1f}-{max(dl_hist):.1f} Mbps" if dl_hist else "-"
    )

    right_table.add_row(
        Text("RTT (ms)", style="green dim"),
        Text(rtt_spark, style="green"),
    )
    right_table.add_row("", Text(rtt_range, style="dim"))
    right_table.add_row("", Text(""))
    right_table.add_row(
        Text("Speed (Mbps)", style="blue dim"),
        Text(dl_spark, style="blue"),
    )
    right_table.add_row("", Text(dl_range, style="dim"))
    right_table.add_row("", Text(""))

    # Split tunnel section
    st_cfg = cfg.split_tunnel
    st_badge = (
        Text("● enabled", style="bold green")
        if st_cfg.enabled
        else Text("○ disabled", style="dim")
    )
    right_table.add_row(Text("Split tunnel", style="dim"), st_badge)

    if st_cfg.enabled and st_cfg.excludes:
        for cidr in st_cfg.excludes[:6]:
            right_table.add_row("", Text(cidr, style="dim cyan"))
        if len(st_cfg.excludes) > 6:
            right_table.add_row(
                "", Text(f"…+{len(st_cfg.excludes) - 6} more", style="dim")
            )

    layout["right"].update(
        Panel(right_table, title="[bold]History & Split Tunnel[/bold]")
    )

    # ---- Footer --------------------------------------------------------
    footer_text = Text()
    footer_text.append("  Probe every ", style="dim")
    footer_text.append(f"{_FAST_INTERVAL}s (RTT)  ", style="dim cyan")
    footer_text.append(f"{_SLOW_INTERVAL}s (speed)  ", style="dim cyan")
    footer_text.append("  Ctrl-C ", style="dim")
    footer_text.append("to quit", style="dim")
    layout["footer"].update(Panel(Align.center(footer_text), style="dim"))

    return layout


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def run_tui() -> None:
    """Start the live TUI. Blocks until Ctrl-C."""
    cfg = load_config()
    providers = build_providers(cfg)
    console = Console()

    state = ProbeState()
    stop = threading.Event()

    probe_thread = threading.Thread(
        target=_probe_loop, args=(state, stop), daemon=True
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
