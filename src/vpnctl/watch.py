"""Watch daemon - periodic probe + full benchmark with policy enforcement.

The watch loop runs in the foreground (Ctrl-C to stop).  It has two
interleaved timers:

  probe_interval        - light RTT probe on the *active* tunnel only
  benchmark_interval    - full cross-provider benchmark (connect each, probe,
                          disconnect, rank)

Policy:
  - After a full benchmark, if an alternative provider wins, increment its
    consecutive-win counter.
  - Only recommend (or apply) a switch when the same alternative has won
    `consecutive_rounds_to_act` rounds in a row AND the gain meets the
    min_rtt or min_score thresholds.
  - With --apply the switch is executed automatically; otherwise a
    recommendation is printed.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass
from typing import Optional

from vpnctl.config import Config
from vpnctl.providers.base import ProbeResult, ProviderAdapter, ProviderStatus
from vpnctl.selector import (
    build_providers,
    control_provider_ids,
    pick_winner,
    run_benchmark,
    save_results,
    should_switch,
)


@dataclass
class _WinCounter:
    provider_id: str
    count: int = 0


def _find_active(providers: list[ProviderAdapter]) -> Optional[ProviderAdapter]:
    for p in providers:
        if p.status() == ProviderStatus.CONNECTED:
            return p
    return None


def _find_by_id(
    providers: list[ProviderAdapter], pid: str
) -> Optional[ProviderAdapter]:
    for p in providers:
        if p.provider_id == pid:
            return p
    return None


def run_watch(
    cfg: Config,
    *,
    apply: bool = False,
    log_cb=None,
) -> None:
    """Main watch loop.  Blocks until SIGINT/SIGTERM or KeyboardInterrupt."""

    def _log(msg: str) -> None:
        if log_cb:
            log_cb(msg)

    providers = build_providers(cfg)
    if not providers:
        _log("No providers enabled - nothing to watch.")
        return

    policy = cfg.policy
    probe_secs = policy.probe_interval_minutes * 60
    bench_secs = policy.benchmark_interval_minutes * 60

    win_counters: dict[str, _WinCounter] = {}
    current_pid: Optional[str] = None
    current_result: Optional[ProbeResult] = None

    last_probe = 0.0
    last_bench = 0.0

    _stop = False

    def _handle_signal(_signum, _frame):
        nonlocal _stop
        _stop = True

    signal.signal(signal.SIGTERM, _handle_signal)

    _log(
        f"Watch started - probe every {policy.probe_interval_minutes}m, "
        f"benchmark every {policy.benchmark_interval_minutes}m, "
        f"auto-apply={apply}"
    )

    while not _stop:
        now = time.monotonic()

        should_probe = (now - last_probe) >= probe_secs
        should_bench = (now - last_bench) >= bench_secs

        if should_bench:
            _log("--- Full benchmark starting ---")
            results = run_benchmark(providers, status_cb=_log)
            save_results(results)
            last_bench = time.monotonic()
            last_probe = last_bench

            winner = pick_winner(results, controls=control_provider_ids(providers))
            if winner is None:
                _log("All providers failed - staying put.")
                time.sleep(30)
                continue

            active = _find_active(providers)
            if active is None:
                _log(f"No active tunnel; connecting winner: {winner.provider_id}")
                _connect(winner.provider_id, providers, _log)
                current_pid = winner.provider_id
                current_result = winner
                win_counters.clear()
                time.sleep(30)
                continue

            if current_result is None:
                current_result = _probe_active(active, _log)

            if active.provider_id == winner.provider_id:
                _log(f"Active tunnel ({active.provider_id}) is still the winner.")
                win_counters.clear()
            elif should_switch(
                current_result,
                winner,
                policy.min_rtt_improvement_ms,
                policy.min_score_improvement_pct,
            ):
                pid = winner.provider_id
                ctr = win_counters.setdefault(pid, _WinCounter(pid))
                ctr.count += 1
                _log(
                    f"[policy] {pid} wins round {ctr.count}/"
                    f"{policy.consecutive_rounds_to_act} "
                    f"(rtt Δ={current_result.median_rtt_ms - winner.median_rtt_ms:.1f}ms)"
                )
                if ctr.count >= policy.consecutive_rounds_to_act:
                    if apply:
                        _log(f"[policy] Switching to {pid} (--apply set)")
                        try:
                            active.disconnect()
                        except Exception:
                            pass
                        _connect(pid, providers, _log)
                        current_pid = pid
                        current_result = winner
                        win_counters.clear()
                    else:
                        _log(
                            f"[policy] RECOMMEND switching to {pid} "
                            f"(run with --apply to auto-switch)"
                        )
            else:
                _log(
                    f"[policy] {winner.provider_id} wins but gain is below thresholds "
                    f"- staying on {active.provider_id}"
                )
                win_counters.clear()

        elif should_probe:
            active = _find_active(providers)
            if active is None:
                _log("No active tunnel during probe interval.")
            else:
                _log(f"[probe] pinging on {active.provider_id}…")
                result = _probe_active(active, _log)
                current_result = result
                current_pid = active.provider_id
            last_probe = time.monotonic()

        try:
            time.sleep(5)
        except KeyboardInterrupt:
            break

    _log("Watch loop stopped.")


def _probe_active(
    adapter: ProviderAdapter, log_cb
) -> ProbeResult:
    result = adapter.probe()
    log_cb(f"[probe] {result}")
    return result


def _connect(
    pid: str,
    providers: list[ProviderAdapter],
    log_cb,
) -> None:
    adapter = _find_by_id(providers, pid)
    if adapter is None:
        log_cb(f"[connect] unknown provider: {pid}")
        return
    try:
        adapter.connect()
        log_cb(f"[connect] {pid} connected")
    except Exception as exc:
        log_cb(f"[connect] {pid} failed: {exc}")
