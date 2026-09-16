"""The monitor's formatting, both of which used to read as the opposite of true."""

from __future__ import annotations

from vpnctl import render
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

from vpnctl.tui import ProbeState, _build_layout, _metrics_column


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

    # The layout is sized from the console it is drawn on, so one console
    # does both jobs and there is nothing to monkeypatch.
    console = Console(
        width=width, height=height, record=True, force_terminal=False,
        theme=render.THEME,
    )
    console.print(_build_layout(state, list(providers), cfg, console))
    return console.export_text().rstrip("\n").split("\n")


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
    """Narrower means taller, not less.

    Two ways this has broken: a trailing newline trimmed wrongly removed the
    download row, and the single-column fallback below 72 columns dropped the
    whole history pane, losing both sparklines and the split-tunnel state.
    """
    for width in (50, 60, 72, 80, 120):
        lines = _render(width, 30)
        bars = [line for line in lines if any(ch in line for ch in "▁▂▃▄▅▆▇█")]
        assert len(bars) == 2, f"{len(bars)} sparklines at {width} columns"


def test_the_sparkline_grows_with_the_terminal():
    """It used to be a fixed 24, so anything under 88 columns truncated it.

    Compared within the two-column layout only. Below 72 columns the panes
    stack, so each one gets the full width and the sparkline is legitimately
    wider than it is at 80 in two columns.
    """
    def bar_count(width):
        for line in _render(width, 40):
            if any(ch in line for ch in "▁▂▃▄▅▆▇█"):
                return sum(line.count(ch) for ch in "▁▂▃▄▅▆▇█")
        return 0

    assert bar_count(160) > bar_count(120) > bar_count(80)


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


def test_an_unprotected_machine_is_told_so_in_the_connection_pane():
    state = _state_with_history()
    pane = _metrics_column(state, None, [], width=48).plain
    assert "no tunnel is up" in pane
    assert "not protected" in pane


def test_the_connection_pane_shows_the_numbers_when_connected():
    state = _state_with_history()
    pane = _metrics_column(state, "warp-wireguard", [], width=48).plain
    for label in ("rtt", "jitter", "loss", "download", "probes", "last probe"):
        assert label in pane


@pytest.mark.parametrize(
    "width,height",
    [(20, 24), (40, 24), (60, 10), (80, 10), (60, 20), (72, 24), (80, 30), (200, 50)],
)
def test_the_footer_is_never_cropped_away(width, height):
    """It is the only place ctrl-c is written down.

    Only the log panel used to be height-aware, so the frame had a hard floor
    of eighteen rows and anything shorter lost the footer off the bottom.
    The narrow cases are separate: below about 54 columns the footer text
    wraps to a four-row panel, and the layout assumed three.
    """
    lines = _render(width, height)
    assert len(lines) <= height
    assert any("ctrl-c" in line for line in lines)


def test_every_probe_row_shows_a_throughput_figure():
    """Throughput is measured every 30s, not on every 5s probe.

    So most rows had an empty download column. The last known figure is
    carried onto each event instead, flagged so a repeated number can be
    dimmed rather than presented as a fresh measurement.
    """
    import time as _t

    from vpnctl.tui import _log_lines

    state = ProbeState()
    now = _t.time()
    state.events.append((now - 15, 20.0, 2.0, 0.0, 40.0, True))
    state.events.append((now - 10, 21.0, 2.1, 0.0, 40.0, False))
    state.events.append((now - 5, 22.0, 2.2, 0.0, 40.0, False))

    rendered = _log_lines(state, 5, 100)
    rows = rendered.plain.rstrip("\n").split("\n")
    assert len(rows) == 3
    for row in rows:
        assert "download" in row, row
        assert "40.00 Mbps" in row, row

    # The fresh one is undimmed and the carried ones are dimmed, so a
    # repeated figure does not look like it was just taken.
    styles = [
        span.style
        for span in rendered.spans
        if isinstance(span.style, str) and span.style == "muted"
    ]
    assert styles, "carried figures should be dimmed"


def test_a_row_from_before_the_flag_existed_still_renders():
    """The deque can hold events recorded by an older build."""
    import time as _t

    from vpnctl.tui import _log_lines

    state = ProbeState()
    state.events.append((_t.time(), 20.0, 2.0, 0.0, 40.0))
    assert "40.00 Mbps" in _log_lines(state, 2, 100).plain


def test_a_probe_before_any_throughput_reading_shows_no_figure():
    import time as _t

    from vpnctl.tui import _log_lines

    state = ProbeState()
    state.events.append((_t.time(), 20.0, 2.0, 0.0, None, False))
    row = _log_lines(state, 2, 100).plain
    assert "rtt" in row
    assert "download" not in row
