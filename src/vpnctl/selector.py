"""Provider registry, benchmark orchestration, and selection logic.

build_providers()  - instantiate adapters from a loaded Config
run_benchmark()    - connect each enabled provider, probe, disconnect, rank
pick_winner()      - return the top-scored ProbeResult
should_switch()    - policy check: is a candidate meaningfully better?
save_results() / load_results() - persist last benchmark to TOML
"""

from __future__ import annotations

import tomllib
from typing import Optional

from vpnctl.config import Config, results_path
from vpnctl.transports import WstunnelSettings, build_transport
from vpnctl.providers.base import ProbeResult, ProviderAdapter
from vpnctl.providers.direct import DirectAdapter
from vpnctl.providers.warp_masque import WarpMasqueAdapter
from vpnctl.providers.warp_wireguard import WarpWireguardAdapter
from vpnctl.providers.wg_custom import WgCustomAdapter
from vpnctl.toml_utils import dumps as toml_dumps


def build_providers(cfg: Config) -> list[ProviderAdapter]:
    """Return the list of enabled provider adapters."""
    excludes = cfg.split_tunnel.excludes if cfg.split_tunnel.enabled else []
    # One transport, shared by the WireGuard providers: it describes the
    # network this machine is on, not the server it is dialling.
    transport_settings = WstunnelSettings(
        server=cfg.transport.server,
        local_port=cfg.transport.local_port,
        sni=cfg.transport.sni,
        path_prefix=cfg.transport.path_prefix,
        credentials=cfg.transport.credentials,
        verify_certificate=cfg.transport.verify_certificate,
    )
    providers: list[ProviderAdapter] = []
    if cfg.warp_masque.enabled:
        providers.append(WarpMasqueAdapter(excludes=excludes))
    if cfg.warp_wireguard.enabled:
        providers.append(
            WarpWireguardAdapter(
                excludes=excludes,
                transport=build_transport(cfg.transport.kind, transport_settings),
            )
        )
    if cfg.wg_custom.enabled:
        providers.append(
            WgCustomAdapter(
                endpoint=cfg.wg_custom.endpoint,
                public_key=cfg.wg_custom.public_key,
                interface=cfg.wg_custom.interface,
                key_file=cfg.wg_custom.key_file,
                address=cfg.wg_custom.address,
                dns=cfg.wg_custom.dns,
                allowed_ips=cfg.wg_custom.allowed_ips,
                excludes=excludes,
                transport=build_transport(cfg.transport.kind, transport_settings),
            )
        )
    if cfg.direct.enabled:
        providers.append(DirectAdapter())
    return providers


def run_benchmark(
    providers: list[ProviderAdapter],
    *,
    status_cb=None,
) -> list[ProbeResult]:
    """Sequentially benchmark each provider.

    For each provider:
      1. disconnect any active tunnel first
      2. prepare + connect
      3. probe
      4. disconnect
      5. record result

    status_cb(msg: str) is called with progress messages if provided.
    """

    def _log(msg: str) -> None:
        if status_cb:
            status_cb(msg)

    results: list[ProbeResult] = []

    for adapter in providers:
        pid = adapter.provider_id
        _log(f"[{pid}] disconnecting any active tunnel…")
        try:
            adapter.disconnect()
        except Exception:
            pass

        _log(f"[{pid}] connecting…")
        try:
            adapter.connect()
        except Exception as exc:
            _log(f"[{pid}] connect failed: {exc}")
            results.append(
                ProbeResult(
                    provider_id=pid,
                    median_rtt_ms=9999.0,
                    jitter_ms=9999.0,
                    loss_pct=100.0,
                    throughput_mbps=0.0,
                    score=0.0,
                    error=str(exc),
                )
            )
            continue

        _log(f"[{pid}] probing…")
        result = adapter.probe(lambda phase: _log(f"[{pid}] {phase}"))
        results.append(result)
        _log(f"[{pid}] {result}")

        _log(f"[{pid}] disconnecting…")
        try:
            adapter.disconnect()
        except Exception:
            pass

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def pick_winner(results: list[ProbeResult]) -> Optional[ProbeResult]:
    """Return the highest-scoring successful result, or None."""
    ranked = sorted(
        (r for r in results if r.ok), key=lambda r: r.score, reverse=True
    )
    return ranked[0] if ranked else None


def should_switch(
    current: ProbeResult,
    candidate: ProbeResult,
    min_rtt_improvement_ms: float,
    min_score_improvement_pct: float,
) -> bool:
    """Return True if candidate is materially better than current."""
    rtt_gain = current.median_rtt_ms - candidate.median_rtt_ms
    if current.score > 0:
        score_gain_pct = (candidate.score - current.score) / current.score * 100
    else:
        score_gain_pct = 100.0

    return (
        rtt_gain >= min_rtt_improvement_ms
        or score_gain_pct >= min_score_improvement_pct
    )


def save_results(results: list[ProbeResult]) -> None:
    """Persist benchmark results to ~/.config/vpnctl/last_benchmark.toml."""
    path = results_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "results": [
            {
                "provider_id": r.provider_id,
                "median_rtt_ms": r.median_rtt_ms,
                "jitter_ms": r.jitter_ms,
                "loss_pct": r.loss_pct,
                "throughput_mbps": r.throughput_mbps,
                "score": r.score,
                "error": r.error or "",
            }
            for r in results
        ]
    }
    path.write_text(toml_dumps(data))


def load_results() -> list[ProbeResult]:
    """Load last benchmark results from disk.  Returns [] if absent."""
    path = results_path()
    if not path.exists():
        return []
    try:
        raw = tomllib.loads(path.read_text())
        out = []
        for entry in raw.get("results", []):
            out.append(
                ProbeResult(
                    provider_id=entry["provider_id"],
                    median_rtt_ms=float(entry["median_rtt_ms"]),
                    jitter_ms=float(entry["jitter_ms"]),
                    loss_pct=float(entry["loss_pct"]),
                    throughput_mbps=float(entry["throughput_mbps"]),
                    score=float(entry["score"]),
                    error=entry.get("error") or None,
                )
            )
        return out
    except Exception:
        return []
