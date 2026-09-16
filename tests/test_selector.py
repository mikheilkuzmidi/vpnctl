"""Tests for selector logic - scoring, ranking, policy, persistence."""

from __future__ import annotations

from vpnctl.providers.base import ProbeResult
from vpnctl.selector import load_results, pick_winner, save_results, should_switch


def _make_result(pid: str, rtt: float, score: float, error=None) -> ProbeResult:
    return ProbeResult(
        provider_id=pid,
        median_rtt_ms=rtt,
        jitter_ms=2.0,
        loss_pct=0.0,
        throughput_mbps=10.0,
        score=score,
        error=error,
    )


def test_pick_winner_returns_highest_score():
    results = [
        _make_result("warp-wireguard", 40.0, 55.0),
        _make_result("warp-masque", 30.0, 65.0),
    ]
    winner = pick_winner(results)
    assert winner is not None
    assert winner.provider_id == "warp-masque"


def test_pick_winner_skips_errored():
    results = [
        _make_result("warp-wireguard", 40.0, 55.0),
        _make_result("warp-masque", 0.0, 0.0, error="connect failed"),
    ]
    winner = pick_winner(results)
    assert winner is not None
    assert winner.provider_id == "warp-wireguard"


def test_pick_winner_all_failed():
    results = [
        _make_result("warp-wireguard", 0.0, 0.0, error="failed"),
        _make_result("warp-masque", 0.0, 0.0, error="failed"),
    ]
    assert pick_winner(results) is None


def test_should_switch_rtt_improvement():
    current = _make_result("warp-masque", 60.0, 40.0)
    candidate = _make_result("warp-wireguard", 40.0, 50.0)
    assert should_switch(current, candidate, min_rtt_improvement_ms=15.0, min_score_improvement_pct=20.0)


def test_should_switch_score_improvement():
    current = _make_result("warp-masque", 50.0, 40.0)
    candidate = _make_result("warp-wireguard", 48.0, 50.0)
    assert should_switch(current, candidate, min_rtt_improvement_ms=15.0, min_score_improvement_pct=20.0)


def test_should_not_switch_below_thresholds():
    current = _make_result("warp-masque", 50.0, 50.0)
    candidate = _make_result("warp-wireguard", 48.0, 55.0)
    assert not should_switch(current, candidate, min_rtt_improvement_ms=15.0, min_score_improvement_pct=20.0)


def test_save_and_load_results(tmp_path, monkeypatch):
    results_file = tmp_path / "last_benchmark.toml"
    monkeypatch.setattr("vpnctl.selector.results_path", lambda: results_file)
    monkeypatch.setattr("vpnctl.config._RESULTS_FILE", results_file)

    original = [
        _make_result("warp-masque", 30.0, 65.0),
        _make_result("warp-wireguard", 40.0, 55.0),
    ]
    save_results(original)
    assert results_file.exists()

    loaded = load_results()
    assert len(loaded) == 2
    assert loaded[0].provider_id == "warp-masque"
    assert loaded[0].median_rtt_ms == 30.0
    assert loaded[0].score == 65.0


def test_load_results_returns_empty_when_absent(tmp_path, monkeypatch):
    results_file = tmp_path / "no_such_file.toml"
    monkeypatch.setattr("vpnctl.selector.results_path", lambda: results_file)
    assert load_results() == []


def test_save_results_with_error(tmp_path, monkeypatch):
    results_file = tmp_path / "last_benchmark.toml"
    monkeypatch.setattr("vpnctl.selector.results_path", lambda: results_file)

    original = [_make_result("warp-masque", 0.0, 0.0, error="connect failed")]
    save_results(original)

    loaded = load_results()
    assert len(loaded) == 1
    assert loaded[0].error == "connect failed"
    assert not loaded[0].ok
