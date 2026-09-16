"""Checking values that arrive from somewhere else.

Both providers fetch their tunnel parameters over HTTP and then render them
into a config file that is handed to a program running as root. Neither
checked what came back, and both config formats treat a newline as the start
of a new directive, so a single field containing one could add directives
nobody asked for: wg-quick honours PostUp as a root shell command, and
OpenVPN has plenty of root-capable options of its own.

The allow-list in the Riseup adapter covered the provider's options table and
was airtight for it. It did not cover the gateway address, which went
straight into the `remote` line, nor any of the WARP response fields.

So every value that crosses into a config goes through here first. The rule
is the same in each case: reject rather than escape. An address that is not
an address, or a key that is not a key, is not something to sanitise and use
anyway.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

#: A DNS name, optionally with a port. Deliberately strict.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

#: WireGuard keys are 32 bytes of base64: 43 characters and one '='.
_WG_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class InvalidValue(ValueError):
    """A value from outside is not usable, and will not be made usable."""


def _no_control_characters(value: str, what: str) -> str:
    # The whole class of problem in one check: a newline is a directive
    # separator in both config formats.
    if any(ch in value for ch in "\n\r\x00") or value != value.strip():
        raise InvalidValue(f"{what} contains a line break or stray whitespace")
    return value


def ip_address(value: str, what: str = "address") -> str:
    """An IPv4 or IPv6 address, with no prefix."""
    _no_control_characters(value, what)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise InvalidValue(f"{what} is not an IP address: {value!r}") from exc


def ip_interface(value: str, what: str = "address") -> str:
    """An address with an optional prefix, as a WireGuard Address line wants."""
    _no_control_characters(value, what)
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError as exc:
        raise InvalidValue(
            f"{what} is not an address or address/prefix: {value!r}"
        ) from exc


def hostname(value: str, what: str = "host") -> str:
    """A DNS name, or an IP address, with no port."""
    _no_control_characters(value, what)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not _HOSTNAME.match(value):
        raise InvalidValue(f"{what} is not a hostname: {value!r}")
    return value


def endpoint(value: str, what: str = "endpoint") -> str:
    """host:port, where the host is a name or an address and the port is real."""
    _no_control_characters(value, what)
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        raise InvalidValue(f"{what} is not host:port: {value!r}")
    number = int(port)
    if not 1 <= number <= 65535:
        raise InvalidValue(f"{what} has an impossible port: {value!r}")
    # A bracketed IPv6 literal, which rpartition leaves with its brackets.
    if host.startswith("[") and host.endswith("]"):
        ip_address(host[1:-1], what)
        return f"{host}:{number}"
    return f"{hostname(host, what)}:{number}"


def wireguard_key(value: str, what: str = "key") -> str:
    """A base64 WireGuard public or private key."""
    _no_control_characters(value, what)
    if not _WG_KEY.match(value):
        raise InvalidValue(f"{what} is not a WireGuard key")
    return value


def port(value, what: str = "port") -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise InvalidValue(f"{what} is not a number: {value!r}") from exc
    if not 1 <= number <= 65535:
        raise InvalidValue(f"{what} is out of range: {number}")
    return number


def one_of(value: str, allowed, what: str = "value") -> str:
    _no_control_characters(value, what)
    if value not in allowed:
        raise InvalidValue(
            f"{what} must be one of {', '.join(sorted(allowed))}, got {value!r}"
        )
    return value


def optional_ip_address(value: str, what: str = "address") -> Optional[str]:
    """For a field the provider may legitimately leave empty."""
    if not value:
        return ""
    return ip_address(value, what)
