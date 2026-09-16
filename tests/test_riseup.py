"""The free nonprofit provider: parsing, caching, and config generation.

The eip-service.json fixture is a real response from Riseup's API, trimmed to
three gateways. Keeping a real one matters: the shape of the transport list
is the part most likely to change under us.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from vpnctl import riseup
from vpnctl.providers.riseup import RiseupAdapter

FIXTURE = Path(__file__).parent / "fixtures" / "riseup-eip-service.json"

# Structurally valid PEM blocks. Nothing here is a real key.
_CA = "-----BEGIN CERTIFICATE-----\nQ0EK\n-----END CERTIFICATE-----"
_CLIENT = (
    "-----BEGIN RSA PRIVATE KEY-----\na2V5\n-----END RSA PRIVATE KEY-----\n"
    "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"
)


def _bundle(**overrides) -> riseup.Bundle:
    eip = json.loads(FIXTURE.read_text())
    fields = dict(
        provider="riseup",
        ca_pem=_CA,
        client_pem=_CLIENT,
        gateways=riseup._parse_gateways(eip),
        openvpn_options=eip["openvpn_configuration"],
        fetched_at=time.time(),
    )
    fields.update(overrides)
    return riseup.Bundle(**fields)


def test_the_transport_list_is_parsed_as_protocol_and_port_pairs():
    gateways = _bundle().gateways
    assert gateways
    first = gateways[0]
    # Riseup offers OpenVPN over both protocols on three ports.
    assert ("tcp", 1194) in first.openvpn
    assert ("tcp", 80) in first.openvpn
    assert ("tcp", 53) in first.openvpn
    assert ("udp", 1194) in first.openvpn
    # obfs4 is not OpenVPN and must not end up in this list.
    assert ("tcp", 443) not in first.openvpn


def test_picking_a_gateway_honours_protocol_and_port():
    bundle = _bundle()
    assert bundle.pick(protocol="tcp", port=80).openvpn
    with pytest.raises(riseup.RiseupError, match="No riseup gateway offers"):
        bundle.pick(protocol="tcp", port=9999)


def test_picking_an_unavailable_location_lists_the_real_ones():
    bundle = _bundle()
    with pytest.raises(riseup.RiseupError) as exc:
        bundle.pick(location="Atlantis")
    message = str(exc.value)
    assert "Atlantis" in message
    for location in bundle.locations():
        assert location in message


def test_a_bundle_goes_stale_but_an_old_one_still_beats_none(tmp_path):
    """A blocked API must not stop an already-working configuration."""
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(fetched_at=time.time() - 30 * 86400), path)
    stale = riseup.load("riseup", path)
    assert stale is not None and stale.stale

    with patch.object(riseup, "fetch", side_effect=riseup.RiseupError("blocked")):
        returned = riseup.load_or_fetch("riseup", path)
    assert returned.provider == "riseup"
    assert returned.gateways


def test_no_cache_and_no_network_is_an_error(tmp_path):
    with patch.object(riseup, "fetch", side_effect=riseup.RiseupError("blocked")):
        with pytest.raises(riseup.RiseupError, match="blocked"):
            riseup.load_or_fetch("riseup", tmp_path / "absent.json")


def test_the_bundle_is_written_at_0600(tmp_path):
    """It contains a private key."""
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(), path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_a_world_readable_bundle_is_refused(tmp_path):
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(), path)
    path.chmod(0o644)
    with pytest.raises(riseup.RiseupError, match="readable by others"):
        riseup.load("riseup", path)


def test_a_round_trip_preserves_the_transport_pairs(tmp_path):
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(), path)
    loaded = riseup.load("riseup", path)
    assert loaded is not None
    assert loaded.gateways[0].openvpn == _bundle().gateways[0].openvpn


def test_an_unknown_provider_is_refused():
    with pytest.raises(riseup.RiseupError, match="Unknown provider"):
        riseup.fetch("not-a-provider")


# -- config generation -------------------------------------------------------


def _adapter(tmp_path, **kwargs) -> RiseupAdapter:
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(), path)
    adapter = RiseupAdapter(bundle_path=path, **kwargs)
    with patch("vpnctl.providers.riseup.find_openvpn", return_value="/usr/sbin/openvpn"):
        adapter.prepare()
    return adapter


def test_the_generated_config_routes_everything_and_inlines_credentials(tmp_path):
    conf = _adapter(tmp_path).render_config()
    assert conf.startswith("client\n")
    assert "redirect-gateway def1" in conf     # the whole machine, not a split
    assert "remote-cert-tls server" in conf    # or any server could answer
    assert "<ca>" in conf and "<cert>" in conf and "<key>" in conf
    assert "RSA PRIVATE KEY" in conf
    # Provider options are passed through.
    assert "cipher AES-256-GCM" in conf
    assert "auth SHA512" in conf


def test_the_remote_line_uses_the_requested_protocol_and_port(tmp_path):
    conf = _adapter(tmp_path, protocol="tcp", port=80).render_config()
    remote = next(line for line in conf.splitlines() if line.startswith("remote "))
    assert remote.endswith(" 80 tcp")


def test_options_from_the_network_are_filtered_not_trusted(tmp_path):
    """The config is fetched over HTTP and becomes root's arguments."""
    path = tmp_path / "riseup-bundle.json"
    riseup.save(
        _bundle(
            openvpn_options={
                "cipher": "AES-256-GCM",
                "up": "/tmp/evil.sh",              # not allow-listed
                "script-security": "2",            # not allow-listed
                "auth": "SHA512; rm -rf /",        # allow-listed but not a sane value
            }
        ),
        path,
    )
    adapter = RiseupAdapter(bundle_path=path)
    with patch("vpnctl.providers.riseup.find_openvpn", return_value="/usr/sbin/openvpn"):
        adapter.prepare()
    conf = adapter.render_config()

    assert "cipher AES-256-GCM" in conf
    assert "/tmp/evil.sh" not in conf
    assert "script-security 2" not in conf
    assert "script-security 0" in conf
    assert "rm -rf" not in conf


def test_rendering_before_prepare_is_an_error(tmp_path):
    with pytest.raises(RuntimeError, match="prepare"):
        RiseupAdapter(bundle_path=tmp_path / "absent.json").render_config()


def test_doctor_does_not_fetch_anything(tmp_path):
    path = tmp_path / "riseup-bundle.json"
    with patch.object(riseup, "fetch", side_effect=AssertionError("fetched!")):
        with patch("vpnctl.providers.riseup.find_openvpn", return_value="/usr/sbin/openvpn"):
            result = RiseupAdapter(bundle_path=path).doctor()
    assert not path.exists()
    assert any("fetched automatically" in h for h in result.hints)


def test_doctor_reports_the_gateway_it_would_use(tmp_path):
    path = tmp_path / "riseup-bundle.json"
    riseup.save(_bundle(), path)
    with patch("vpnctl.providers.riseup.find_openvpn", return_value="/usr/sbin/openvpn"):
        result = RiseupAdapter(bundle_path=path, protocol="tcp", port=80).doctor()
    assert result.ok
    assert any("Would use" in h and "tcp/80" in h for h in result.hints)
