"""The monitor's formatting, both of which used to read as the opposite of true."""

from __future__ import annotations

from vpnctl.tui import _SPARKS, _fmt, _fmt_throughput, _sparkline


def test_no_history_is_blank():
    assert _sparkline([], width=6) == " " * 6


def test_every_sample_draws_something():
    # The lowest reading used to map to _SPARKS[0], which is a space, so it
    # was invisible. Bars are right aligned, so the samples are at the end.
    line = _sparkline([15.0, 28.0], width=4)
    assert line.strip() == line[-2:], line
    assert " " not in line[-2:], line
    assert line[-1] == _SPARKS[-1], line


def test_a_steady_connection_draws_a_steady_line():
    # Two identical readings used to normalise to an empty string.
    line = _sparkline([30.0, 30.0, 30.0], width=5)
    assert line[-3:] == _SPARKS[len(_SPARKS) // 2] * 3, line
    assert line[:2] == "  ", line


def test_variation_still_spans_the_range():
    line = _sparkline([10.0, 20.0, 30.0], width=3)
    assert line[0] != line[1] != line[2], line
    assert line[2] == _SPARKS[-1], line


def test_sparkline_keeps_the_most_recent_samples():
    line = _sparkline([1.0, 2.0, 3.0, 100.0], width=2)
    assert line == _SPARKS[1] + _SPARKS[-1], line


def test_the_newest_sample_is_at_the_right_edge():
    """A half-filled buffer should read as missing history, not missing news.

    Left aligned, the blank space sat after the most recent reading, so a
    series that gains a sample every thirty seconds looked like the recent
    samples were the ones that had gone.
    """
    line = _sparkline([10.0, 50.0], width=10)
    assert line.startswith(" " * 8), line
    assert line[-1] == _SPARKS[-1], line


def test_the_visible_window_is_scaled_to_itself():
    """A spike that has scrolled off must not flatten what is still on screen.

    min and max were taken over every stored sample and then only the last
    few were drawn, so one old outlier compressed the whole visible range
    into a single level.
    """
    # An old spike, then a range that should still be plotted in full.
    values = [1000.0] + [10.0, 20.0, 30.0]
    line = _sparkline(values, width=3)
    assert line[0] == _SPARKS[1], line
    assert line[-1] == _SPARKS[-1], line
    assert len(set(line)) == 3, line


def test_latency_is_worse_when_it_is_higher():
    assert "green" in _fmt(20.0, "ms", warn=200).style
    assert "yellow" in _fmt(120.0, "ms", warn=200).style
    assert "red" in _fmt(400.0, "ms", warn=200).style


def test_throughput_is_worse_when_it_is_lower():
    # The whole point: 29.8 Mbps used to be red bold and 0.05 Mbps green.
    assert "green" in _fmt_throughput(29.8, floor=1.0).style
    assert "yellow" in _fmt_throughput(3.0, floor=1.0).style
    assert "red" in _fmt_throughput(0.05, floor=1.0).style


def test_a_missing_metric_is_a_dash():
    assert _fmt(None, "ms").plain == "-"
    assert _fmt_throughput(None, floor=1.0).plain == "-"


# ---------------------------------------------------------------------------
# Layout
#
# The old layout split the terminal into a fixed header and footer with a body
# divided into two panels. At 80x30 that left ten consecutive rows where both
# panels were entirely blank, and twenty at 120x40, because nothing was
# height-capped. These pin the absence of that rather than the design.
# ---------------------------------------------------------------------------

import pytest
from rich.console import Console

from vpnctl.tui import ProbeState, _build_layout, _metrics_strip, _regions


def _state_with_history(samples: int = 60):
    import time as _t

    state = ProbeState()
    now = _t.time()
    for i in range(samples):
        rtt = 20.0 + (i % 7)
        state.rtt_history.append(rtt)
        dl = 40.0 + (i % 3) if i % 6 == 0 else None
        if dl:
            state.dl_history.append(dl)
        state.events.append((now - (samples - i) * 5, rtt, 2.4, 0.0, dl))
    state.rtt_ms, state.jitter_ms, state.loss_pct, state.dl_mbps = 24.2, 3.1, 0.0, 41.8
    state.probe_count, state.last_updated = samples, now - 3
    return state


def _render(width: int, height: int, providers=(), excludes=()):
    from vpnctl.config import Config, SplitTunnelConfig

    cfg = Config(split_tunnel=SplitTunnelConfig(enabled=bool(excludes), excludes=list(excludes)))
    state = _state_with_history()

    import vpnctl.tui as tui_module

    original = tui_module.Console
    tui_module.Console = lambda *a, **k: Console(width=width, height=height)
    try:
        console = Console(width=width, height=height, record=True, force_terminal=False)
        console.print(_build_layout(state, list(providers), cfg))
        return console.export_text().rstrip("\n").split("\n")
    finally:
        tui_module.Console = original


def _longest_blank_run(lines) -> int:
    run = best = 0
    for line in lines:
        run = run + 1 if not line.strip() else 0
        best = max(best, run)
    return best


@pytest.mark.parametrize(
    "width,height", [(60, 20), (72, 24), (80, 24), (80, 30), (100, 30), (120, 40), (160, 50)]
)
def test_the_monitor_does_not_pad_or_overflow(width, height):
    lines = _render(width, height, excludes=["10.0.0.0/8", "192.168.0.0/16"])
    assert len(lines) <= height, f"{len(lines)} rows in a {height} row terminal"
    assert max(len(line.rstrip()) for line in lines) <= width
    assert _longest_blank_run(lines) <= 1


@pytest.mark.parametrize("width,height", [(80, 30), (120, 40)])
def test_the_monitor_uses_the_height_it_is_given(width, height):
    """Not merely "does not overflow": the whole point was ten blank rows."""
    lines = _render(width, height, excludes=["10.0.0.0/8"])
    assert len(lines) >= height - 1


def test_both_sparklines_are_drawn_at_every_width():
    """One of them vanished when the trailing newline was trimmed wrongly."""
    for width in (60, 80, 120):
        lines = _render(width, 30)
        bars = [line for line in lines if any(ch in line for ch in "▁▂▃▄▅▆▇█")]
        assert len(bars) == 2, f"{len(bars)} sparklines at {width} columns"


def test_the_sparkline_grows_with_the_terminal():
    """It used to be a fixed 24, so anything under 88 columns truncated it."""
    def bar_count(width):
        for line in _render(width, 30):
            if any(ch in line for ch in "▁▂▃▄▅▆▇█"):
                return sum(line.count(ch) for ch in "▁▂▃▄▅▆▇█ ".strip())
        return 0

    assert bar_count(120) > bar_count(80) > bar_count(60)


def test_no_ellipsis_anywhere():
    """rich adds one when it truncates, which is how the old one lost data."""
    for width in (60, 72, 80, 120):
        assert not any("…" in line for line in _render(width, 30))


def test_the_split_tunnel_list_fits_its_budget():
    """The "+N more" line was not counted, so the screen ran two rows over."""
    excludes = [f"10.{n}.0.0/16" for n in range(12)]
    lines = _render(80, 30, excludes=excludes)
    assert len(lines) <= 30
    assert any("more" in line for line in lines)


def test_metrics_go_on_two_lines_when_four_will_not_fit():
    state = _state_with_history()
    assert "\n" not in _metrics_strip(state, True, width=100).plain
    assert "\n" in _metrics_strip(state, True, width=60).plain


def test_an_unprotected_machine_is_told_so_on_the_metrics_line():
    state = _state_with_history()
    assert "not protected" in _metrics_strip(state, False, width=100).plain


def test_regions_leaves_the_log_out_because_it_is_measured():
    assert "log" not in _regions(30, 3, 2)
    assert sum(_regions(30, 3, 2).values()) < 30
