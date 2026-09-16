"""The monitor's formatting, both of which used to read as the opposite of true."""

from __future__ import annotations

from vpnctl.tui import _SPARKS, _fmt, _fmt_throughput, _sparkline


def test_no_history_is_blank():
    assert _sparkline([], width=6) == " " * 6


def test_every_sample_draws_something():
    # The lowest reading used to map to _SPARKS[0], which is a space, so it
    # was invisible.
    line = _sparkline([15.0, 28.0], width=4)
    assert line[:2].strip() == line[:2], line
    assert " " not in line[:2], line
    assert line[1] == _SPARKS[-1], line


def test_a_steady_connection_draws_a_steady_line():
    # Two identical readings used to normalise to an empty string.
    line = _sparkline([30.0, 30.0, 30.0], width=5)
    assert line[:3] == _SPARKS[len(_SPARKS) // 2] * 3, line


def test_variation_still_spans_the_range():
    line = _sparkline([10.0, 20.0, 30.0], width=3)
    assert line[0] != line[1] != line[2], line
    assert line[2] == _SPARKS[-1], line


def test_sparkline_keeps_the_most_recent_samples():
    line = _sparkline([1.0, 2.0, 3.0, 100.0], width=2)
    assert line == _SPARKS[1] + _SPARKS[-1], line


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
