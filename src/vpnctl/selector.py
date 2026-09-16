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
from vpnctl.providers.direct import PROVIDER_ID as DIRECT_PROVIDER_ID, DirectAdapter
from vpnctl.providers.riseup import RiseupAdapter
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
    # A provider that cannot work on this OS is skipped rather than built:
    # it would otherwise be benchmarked, fail, and be reported as a fault.
    if cfg.warp_masque.enabled and WarpMasqueAdapter.supported():
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
    if cfg.riseup.enabled:
        providers.append(
            RiseupAdapter(
                cfg.riseup.provider,
                location=cfg.riseup.location,
                protocol=cfg.riseup.protocol,
                port=cfg.riseup.port,
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

    For each provider: connect it, probe it, disconnect it, record the result.

    Two things about the teardown, both learned the hard way.

    Every tunnel is taken down before the run starts, not just the one about
    to be measured. Otherwise a tunnel that was already up kept the default
    route while the first providers were probed, so their numbers were
    measured through it.

    And the teardown happens whether the connect succeeded or not. A connect
    that timed out used to be left alone, and a provider that came up a
    moment after its timeout stayed up for the rest of the run: every
    remaining provider was then probed through that tunnel, so the whole
    ranking, and the winner connect would later use, was measured wrong.

    status_cb(msg: str) is called with progress messages if provided.
    """

    def _log(msg: str) -> None:
        if status_cb:
            status_cb(msg)

    def _teardown(adapter: ProviderAdapter) -> None:
        try:
            adapter.disconnect()
        except Exception as exc:
            _log(f"[{adapter.provider_id}] could not disconnect: {exc}")

    results: list[ProbeResult] = []

    _log("clearing any active tunnel…")
    for adapter in providers:
        if not adapter.is_control:
            _teardown(adapter)

    for adapter in providers:
        pid = adapter.provider_id

        _log(f"[{pid}] connecting…")
        try:
            adapter.connect()
        except Exception as exc:
            _log(f"[{pid}] connect failed: {exc}")
            # Tear down regardless: a provider that comes up just after its
            # own timeout would otherwise carry every later measurement.
            _teardown(adapter)
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

        try:
            _log(f"[{pid}] probing…")
            result = adapter.probe(lambda phase: _log(f"[{pid}] {phase}"))
            results.append(result)
            _log(f"[{pid}] {result}")
        finally:
            _log(f"[{pid}] disconnecting…")
            _teardown(adapter)

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def control_provider_ids(providers: Optional[list[ProviderAdapter]] = None) -> set[str]:
    """The provider ids that measure rather than protect.

    Taken from the adapters when they are to hand, and from a default
    otherwise, so a caller that only has saved results still excludes them.
    """
    if providers is not None:
        return {p.provider_id for p in providers if p.is_control}
    return {DIRECT_PROVIDER_ID}


def pick_winner(
    results: list[ProbeResult],
    *,
    controls: Optional[set[str]] = None,
) -> Optional[ProbeResult]:
    """Return the highest-scoring successful tunnel, or None.

    Control rows are excluded. "direct" is the unprotected connection and is
    usually the fastest row in the table, having no encryption or extra hop
    to pay for, so ranking by score alone hands the win to the one option
    that provides no protection: connect would then report success while
    leaving the machine exactly as exposed as before.
    """
    excluded = control_provider_ids() if controls is None else controls
    ranked = sorted(
        (r for r in results if r.ok and r.provider_id not in excluded),
        key=lambda r: r.score,
        reverse=True,
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

    # A candidate has to be better overall, not merely quicker. Or-ing these
    # meant a provider the tool's own scoring rated three times worse, on
    # jitter, loss and throughput, was switched to because its median RTT
    # happened to be lower.
    if candidate.score < current.score:
        return False
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
