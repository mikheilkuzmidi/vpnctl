"""Values that arrive from a provider, before they reach a root process.

Both providers fetch their tunnel parameters over HTTP and render them into a
config handed to a program running as root. A newline is a directive
separator in both formats, so an unchecked field could add directives nobody
asked for: wg-quick honours PostUp as a root shell command, and OpenVPN has
plenty of root-capable options. These are the checks that stop that.
"""

from __future__ import annotations

import pytest

from vpnctl import validate


@pytest.mark.parametrize(
    "value",
    [
        "172.16.0.2/32\nPostUp = touch /tmp/pwned",
        "10.0.0.1/32\r\nPostUp = sh -c evil",
        "10.0.0.1/32\x00",
        " 10.0.0.1/32",
        "10.0.0.1/32 ",
    ],
)
def test_an_address_carrying_a_directive_is_refused(value):
    with pytest.raises(validate.InvalidValue):
        validate.ip_interface(value)


def test_a_gateway_address_carrying_a_directive_is_refused():
    """The OpenVPN remote line. This one bypassed the options allow-list."""
    with pytest.raises(validate.InvalidValue):
        validate.ip_address("204.13.164.252 1194 tcp\nINJECTED-DIRECTIVE arg")


def test_good_values_pass_through_unchanged():
    assert validate.ip_interface("172.16.0.2/32") == "172.16.0.2/32"
    assert validate.ip_address("204.13.164.252") == "204.13.164.252"
    assert validate.hostname("vpn01-sea.riseup.net") == "vpn01-sea.riseup.net"
    assert validate.endpoint("engage.cloudflareclient.com:2408") == (
        "engage.cloudflareclient.com:2408"
    )
    assert validate.wireguard_key("A" * 43 + "=") == "A" * 43 + "="
    assert validate.port("2408") == 2408


def test_an_ipv6_address_is_still_an_address():
    assert validate.ip_interface("2606:4700:110::1/128")
    assert validate.endpoint("[2606:4700:d0::a29f:c006]:2408")


@pytest.mark.parametrize(
    "value", ["not-a-key", "A" * 43, "A" * 44, "A" * 42 + "==", "A/B+c\nPostUp = x"]
)
def test_something_that_is_not_a_key_is_refused(value):
    with pytest.raises(validate.InvalidValue):
        validate.wireguard_key(value)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "http", None, "24 08"])
def test_an_impossible_port_is_refused(value):
    with pytest.raises(validate.InvalidValue):
        validate.port(value)


@pytest.mark.parametrize(
    "value", ["host", "host:", ":2408", "host:port", "host:0", "ho st:80"]
)
def test_something_that_is_not_host_and_port_is_refused(value):
    with pytest.raises(validate.InvalidValue):
        validate.endpoint(value)


def test_a_protocol_must_be_one_of_the_two():
    assert validate.one_of("tcp", {"tcp", "udp"}) == "tcp"
    with pytest.raises(validate.InvalidValue):
        validate.one_of("tcp\nINJECTED x", {"tcp", "udp"})


# -- the providers, at their boundaries --------------------------------------


def test_warp_refuses_a_response_that_would_inject_a_postup(monkeypatch):
    """wg-quick runs PostUp as root, so this is the whole point."""
    from vpnctl import warp

    payload = {
        "id": "abc",
        "token": "t" * 36,
        "config": {
            "interface": {
                "addresses": {"v4": "172.16.0.2/32\nPostUp = touch /tmp/pwned"}
            },
            "peers": [
                {
                    "public_key": "C" * 43 + "=",
                    "endpoint": {"host": "engage.cloudflareclient.com:2408",
                                 "v4": "162.159.192.2:0", "ports": [2408]},
                }
            ],
        },
    }
    monkeypatch.setattr(warp, "generate_keypair", lambda: ("A" * 43 + "=", "B" * 43 + "="))
    monkeypatch.setattr(warp, "_post_registration", lambda key, client: payload)
    monkeypatch.setattr(warp, "_activate", lambda *a, **k: None)

    with pytest.raises(warp.WarpError, match="unusable"):
        warp.register()


def test_riseup_drops_a_gateway_it_cannot_validate():
    """The remote line. A bad gateway is dropped, the good ones survive."""
    from vpnctl.riseup import _parse_gateways

    transport = {
        "type": "openvpn",
        "protocols": ["tcp"],
        "ports": ["1194"],
    }
    eip = {
        "gateways": [
            {
                "host": "vpn01-sea.riseup.net",
                "ip_address": "204.13.164.252",
                "location": "Seattle",
                "capabilities": {"transport": [transport]},
            },
            {
                "host": "evil.example.com",
                "ip_address": "204.13.164.252 1194 tcp\nINJECTED x",
                "location": "Nowhere",
                "capabilities": {"transport": [transport]},
            },
            "not even a dict",
        ]
    }
    gateways = _parse_gateways(eip)
    assert [g.ip_address for g in gateways] == ["204.13.164.252"]


def test_riseup_ignores_a_protocol_it_does_not_recognise():
    from vpnctl.riseup import _parse_gateways

    eip = {
        "gateways": [
            {
                "host": "vpn01-sea.riseup.net",
                "ip_address": "204.13.164.252",
                "location": "Seattle",
                "capabilities": {
                    "transport": [
                        {
                            "type": "openvpn",
                            "protocols": ["tcp", "sctp\nINJECTED x"],
                            "ports": ["1194"],
                        }
                    ]
                },
            }
        ]
    }
    assert _parse_gateways(eip)[0].openvpn == [("tcp", 1194)]
