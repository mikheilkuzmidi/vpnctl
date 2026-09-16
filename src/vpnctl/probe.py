"""Probe engine - RTT, jitter, packet loss, throughput, scoring.

run_probe() is the single entry-point used by every provider adapter.
It assumes the tunnel is already connected when called.

Scoring formula (lower is better for the raw metrics, higher is better for
the final score so the selector can use max()):

    score = 100
            - w_rtt   * median_rtt_ms
            - w_jit   * jitter_ms
            - w_loss  * loss_pct * LOSS_PENALTY
            + w_tput  * throughput_mbps

Weights are tuned so latency/stability dominate, throughput is secondary.
"""

from __future__ import annotations

import statistics
import subprocess
import time
from typing import Optional

from vpnctl.providers.base import ProbeResult, ProgressFn

# --- Probe targets ----------------------------------------------------------

_PING_TARGETS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
]

_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=2000000"

_PING_COUNT = 10
_DOWNLOAD_TIMEOUT = 10.0

# --- Scoring weights --------------------------------------------------------

W_RTT = 0.50
W_JIT = 0.20
W_LOSS = 0.20
W_TPUT = 0.10
LOSS_PENALTY = 5.0


def _parse_summary(stdout: str) -> tuple[Optional[float], Optional[float]]:
    """The mean RTT and the deviation, from ping's own summary line.

    macOS prints `round-trip min/avg/max/stddev = 8.1/9.0/10.2/0.7 ms` and
    Linux prints `rtt min/avg/max/mdev = ...`. Four numbers, and the last one
    is the jitter ping already measured across the whole run.

    This used to take the first two fields and append both to a list of "RTT
    samples", which meant two things were wrong at once. The minimum was
    mixed in with the mean, biasing the median low. And because the samples
    from all three targets were pooled, the standard deviation of that pool
    was really the spread between the three hosts, so a provider whose exit
    happened to be far from one of them was charged for jitter it did not
    have. The deviation ping reports was discarded.
    """
    for line in stdout.splitlines():
        if "round-trip" in line or "rtt" in line:
            parts = line.split("=")[-1].strip().split("/")
            if len(parts) >= 2:
                try:
                    # "9.0 ms" when the summary has only two fields.
                    avg = float(parts[1].split()[0].strip())
                except (ValueError, IndexError):
                    continue
                deviation = None
                if len(parts) >= 4:
                    try:
                        deviation = float(parts[3].split()[0].strip())
                    except (ValueError, IndexError):
                        deviation = None
                return avg, deviation
    return None, None


def _parse_rtts(stdout: str) -> list[float]:
    """Pull RTT samples in ms out of ping's output."""
    rtts: list[float] = []
    avg, _ = _parse_summary(stdout)
    if avg is not None:
        rtts.append(avg)
    if rtts:
        return rtts
    # No summary line: fall back to the per-reply times.
    for line in stdout.splitlines():
        stripped = line.strip()
        if "time=" in stripped:
            try:
                rtts.append(float(stripped.split("time=")[1].split()[0]))
            except (IndexError, ValueError):
                pass
    return rtts


def _parse_loss(stdout: str) -> Optional[float]:
    """Pull packet loss percent out of ping's output, or None if absent."""
    for line in stdout.splitlines():
        if "packet loss" in line:
            for tok in line.split():
                if "%" in tok:
                    try:
                        return float(tok.replace("%", ""))
                    except ValueError:
                        return None
    return None


def _ping_host(
    host: str, count: int = _PING_COUNT
) -> tuple[list[float], float, Optional[float]]:
    """Ping a host once and return (rtt samples, loss percent, deviation).

    Both numbers come from the same run. They used to be gathered by two
    functions that each shelled out their own `ping -c 10`, so three targets
    cost six ping runs: about a minute during which the command printed
    nothing and looked hung. One run per host halves that.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-q", host],
            capture_output=True,
            text=True,
            timeout=count * 2 + 5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [], 100.0, None

    rtts = _parse_rtts(result.stdout)
    _, deviation = _parse_summary(result.stdout)
    loss = _parse_loss(result.stdout)
    if loss is None:
        loss = 100.0 if not rtts else 0.0
    return rtts, loss, deviation


def _measure_download() -> float:
    """Return estimated download throughput in Mbps; 0.0 on failure."""
    try:
        import httpx

        start = time.monotonic()
        with httpx.Client(timeout=_DOWNLOAD_TIMEOUT) as client:
            resp = client.get(_DOWNLOAD_URL)
            resp.read()
        elapsed = time.monotonic() - start
        if elapsed <= 0:
            return 0.0
        bits = len(resp.content) * 8
        return bits / elapsed / 1_000_000
    except Exception:
        return 0.0


def _compute_score(
    median_rtt: float,
    jitter: float,
    loss_pct: float,
    tput: float,
) -> float:
    raw = (
        100.0
        - W_RTT * median_rtt
        - W_JIT * jitter
        - W_LOSS * loss_pct * LOSS_PENALTY
        + W_TPUT * tput
    )
    return max(raw, 0.0)


def run_probe(provider_id: str, on_progress: Optional[ProgressFn] = None) -> ProbeResult:
    """Run a full quality probe and return a ProbeResult.

    Never raises - errors are captured in ProbeResult.error.

    on_progress is called with a short phase description before each step. A
    probe takes tens of seconds, so a caller with no way to say which step is
    in flight can only print one line and hope the user waits.
    """

    def _say(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    all_rtts: list[float] = []
    all_jitters: list[float] = []
    loss_samples: list[float] = []

    total = len(_PING_TARGETS)
    for index, host in enumerate(_PING_TARGETS, start=1):
        _say(f"pinging {host} ({index}/{total})")
        samples, loss, deviation = _ping_host(host)
        if samples:
            all_rtts.extend(samples)
        if deviation is not None:
            all_jitters.append(deviation)
        loss_samples.append(loss)

    if not all_rtts:
        return ProbeResult(
            provider_id=provider_id,
            median_rtt_ms=9999.0,
            jitter_ms=9999.0,
            loss_pct=100.0,
            throughput_mbps=0.0,
            score=0.0,
            error="All ping targets unreachable - offline or captive portal?",
        )

    median_rtt = statistics.median(all_rtts)
    # ping's own deviation, averaged across the targets, rather than the
    # spread between the targets themselves.
    jitter = (
        statistics.mean(all_jitters)
        if all_jitters
        else (statistics.stdev(all_rtts) if len(all_rtts) > 1 else 0.0)
    )
    loss_pct = statistics.mean(loss_samples)
    _say("measuring download throughput")
    tput = _measure_download()

    score = _compute_score(median_rtt, jitter, loss_pct, tput)

    return ProbeResult(
        provider_id=provider_id,
        median_rtt_ms=round(median_rtt, 2),
        jitter_ms=round(jitter, 2),
        loss_pct=round(loss_pct, 2),
        throughput_mbps=round(tput, 3),
        score=round(score, 2),
    )
