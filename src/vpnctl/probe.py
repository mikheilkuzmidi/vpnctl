"""Probe engine — RTT, jitter, packet loss, throughput, scoring.

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

from vpnctl.providers.base import ProbeResult

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


def _ping_target(host: str, count: int = _PING_COUNT) -> Optional[list[float]]:
    """Return list of RTT samples in ms, or None on complete failure."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-q", host],
            capture_output=True,
            text=True,
            timeout=count * 2 + 5,
            check=False,
        )
        if result.returncode != 0 and "Statistics" not in result.stdout:
            return None
        rtts: list[float] = []
        for line in result.stdout.splitlines():
            if "round-trip" in line or "rtt" in line:
                parts = line.split("=")[-1].strip().split("/")
                if len(parts) >= 2:
                    try:
                        rtts.append(float(parts[0].strip()))
                        rtts.append(float(parts[1].strip()))
                    except ValueError:
                        pass
        if rtts:
            return rtts
        rtts = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if "time=" in stripped:
                try:
                    t = stripped.split("time=")[1].split()[0]
                    rtts.append(float(t))
                except (IndexError, ValueError):
                    pass
        return rtts or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _parse_loss(host: str, count: int = _PING_COUNT) -> float:
    """Return packet loss % from a ping run (0-100)."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-q", host],
            capture_output=True,
            text=True,
            timeout=count * 2 + 5,
            check=False,
        )
        for line in result.stdout.splitlines():
            if "packet loss" in line:
                for tok in line.split():
                    if "%" in tok:
                        return float(tok.replace("%", ""))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return 100.0


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


def run_probe(provider_id: str) -> ProbeResult:
    """Run a full quality probe and return a ProbeResult.

    Never raises — errors are captured in ProbeResult.error.
    """
    all_rtts: list[float] = []
    loss_samples: list[float] = []

    for host in _PING_TARGETS:
        samples = _ping_target(host)
        if samples:
            all_rtts.extend(samples)
        loss_samples.append(_parse_loss(host))

    if not all_rtts:
        return ProbeResult(
            provider_id=provider_id,
            median_rtt_ms=9999.0,
            jitter_ms=9999.0,
            loss_pct=100.0,
            throughput_mbps=0.0,
            score=0.0,
            error="All ping targets unreachable — offline or captive portal?",
        )

    median_rtt = statistics.median(all_rtts)
    jitter = statistics.stdev(all_rtts) if len(all_rtts) > 1 else 0.0
    loss_pct = statistics.mean(loss_samples)
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
