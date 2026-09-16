"""The network diagnosis, and the verdict it draws from a pattern of results."""

from __future__ import annotations

from vpnctl.netcheck import Check, NetworkReport


def _report(*checks: Check) -> NetworkReport:
    return NetworkReport(checks=list(checks))


def test_an_open_network_needs_no_transport():
    report = _report(
        Check("tls:ordinary:github.com:443", True, ""),
        Check("udp:stun:3478", True, ""),
        Check("tls:tunnel:a gateway", True, ""),
    )
    assert not report.filters_tunnels
    assert "carries tunnels directly" in report.verdict()
    assert "Nothing to change" in report.recommendation()


def test_the_filtering_pattern_is_recognised():
    """Ordinary destinations fine, every tunnel destination dead."""
    report = _report(
        Check("tls:ordinary:github.com:443", True, ""),
        Check("udp:stun:3478", True, ""),
        Check("tls:tunnel:Riseup's VPN API", False, "Connection reset by peer"),
        Check("tls:tunnel:a Riseup gateway", False, "timed out"),
        Check("tls:tunnel:the Tor Project", False, "Connection reset by peer"),
    )
    assert report.filters_tunnels
    verdict = report.verdict()
    assert "filters VPN destinations" in verdict
    # The UDP result is what says it is destination filtering, not protocol
    # inspection, so it belongs in the verdict.
    assert "where the traffic is going" in verdict
    assert "wstunnel" in report.recommendation()
    # And the advice has to say a public endpoint will not help.
    assert "server of your own" in report.recommendation()


def test_no_internet_is_not_reported_as_filtering():
    report = _report(
        Check("tls:ordinary:github.com:443", False, "timed out"),
        Check("tls:tunnel:a gateway", False, "timed out"),
    )
    assert not report.filters_tunnels
    assert "working internet" in report.verdict()


def test_partial_filtering_is_reported_as_such():
    report = _report(
        Check("tls:ordinary:github.com:443", True, ""),
        Check("tls:tunnel:one", True, ""),
        Check("tls:tunnel:two", False, "timed out"),
    )
    assert not report.filters_tunnels
    assert "Partly filtered" in report.verdict()
    assert "1 of 2" in report.verdict()


def test_nothing_measured_says_so():
    assert "Nothing was measured" in NetworkReport().verdict()


def test_warp_is_recommended_when_cloudflare_is_reachable():
    """Measured: a network resetting TLS to Riseup and Tor still carried WARP.

    Blocklisting a VPN provider's gateways is cheap. Blocklisting
    Cloudflare's anycast ranges breaks too much ordinary traffic for most
    networks to attempt, so WARP is worth trying even here.
    """
    report = _report(
        Check("tls:ordinary:github.com:443", True, ""),
        Check("tls:cloudflare:api.cloudflareclient.com", True, ""),
        Check("udp:stun:3478", True, ""),
        Check("tls:tunnel:Riseup's VPN API", False, "reset"),
        Check("tls:tunnel:the Tor Project", False, "reset"),
    )
    assert report.filters_tunnels
    assert report.cloudflare_reachable
    recommendation = report.recommendation()
    assert "warp-wireguard" in recommendation
    # The WARP advice comes first, because it is the one that needs no server.
    assert recommendation.index("warp-wireguard") < recommendation.index("wstunnel")


def test_without_cloudflare_only_the_transport_is_suggested():
    report = _report(
        Check("tls:ordinary:github.com:443", True, ""),
        Check("tls:cloudflare:api.cloudflareclient.com", False, "reset"),
        Check("tls:tunnel:Riseup's VPN API", False, "reset"),
    )
    assert report.filters_tunnels
    assert not report.cloudflare_reachable
    assert "warp-wireguard" not in report.recommendation()
    assert "wstunnel" in report.recommendation()
