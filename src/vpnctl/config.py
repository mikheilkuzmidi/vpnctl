"""Configuration loader and schema.

Config lives at ~/.config/vpnctl/config.toml.
A default file is written on first run.
Secrets (WireGuard private keys) live in separate files - never in config.toml.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vpnctl.toml_utils import dumps as toml_dumps

_CONFIG_DIR = Path.home() / ".config" / "vpnctl"
_CONFIG_FILE = _CONFIG_DIR / "config.toml"
_RESULTS_FILE = _CONFIG_DIR / "last_benchmark.toml"

_DEFAULT_CONFIG = """\
# vpnctl configuration - ~/.config/vpnctl/config.toml

[policy]
probe_interval_minutes     = 10
benchmark_interval_minutes = 30
consecutive_rounds_to_act  = 2
min_rtt_improvement_ms     = 15.0
min_score_improvement_pct  = 20.0

# ---------------------------------------------------------------------------
# Split tunnelling - route specific destinations via your normal internet
# connection instead of through the VPN.  Works for all providers:
#
#   WARP (masque / wireguard): uses warp-cli split-tunnel add/remove
#   wireguard-custom          : injects static macOS routes after wg-quick up
#
# Set enabled = true then list any CIDRs or host IPs you want to bypass.
# Example - keep the local network reachable while the tunnel is up:
#
# [split_tunnel]
# enabled = true
# excludes = [
#   "192.168.0.0/16",   # local LAN: printers, a NAS, the router itself
#   "10.0.0.0/8",
# ]
#
# Only private ranges belong here. Excluding a public range means traffic
# to it leaves on the plain connection with your real address while the VPN
# reports connected, which is the one failure a VPN is supposed to prevent.
# `vpnctl doctor` names any exclude that does this.
# ---------------------------------------------------------------------------
[split_tunnel]
enabled  = false
excludes = []

[providers.warp-masque]
enabled = true

[providers.warp-wireguard]
enabled = true

[providers.wireguard-custom]
enabled = false
# Uncomment and fill in once you have a self-hosted endpoint:
# endpoint   = "203.0.113.1:51820"
# public_key = "BASE64_PUBLIC_KEY_HERE"
# interface  = "wgcustom"
# key_file   = "~/.config/vpnctl/wg-custom.key"
# address    = "10.8.0.2/32"
# dns        = "1.1.1.1"
# allowed_ips = "0.0.0.0/0"
"""


@dataclass
class PolicyConfig:
    probe_interval_minutes: int = 10
    benchmark_interval_minutes: int = 30
    consecutive_rounds_to_act: int = 2
    min_rtt_improvement_ms: float = 15.0
    min_score_improvement_pct: float = 20.0


@dataclass
class WarpProviderConfig:
    enabled: bool = True


@dataclass
class SplitTunnelConfig:
    enabled: bool = False
    excludes: list = field(default_factory=list)


@dataclass
class WgCustomConfig:
    enabled: bool = False
    endpoint: str = ""
    public_key: str = ""
    interface: str = "wgcustom"
    key_file: Optional[str] = None
    address: str = "10.8.0.2/32"
    dns: str = "1.1.1.1"
    allowed_ips: str = "0.0.0.0/0"


@dataclass
class RiseupConfig:
    """A free nonprofit LEAP provider, reached over OpenVPN."""

    enabled: bool = False
    provider: str = "riseup"
    location: str = ""
    # TCP by default: the networks worth having a free VPN on are the ones
    # that treat UDP differently.
    protocol: str = "tcp"
    port: int = 1194


@dataclass
class TransportConfig:
    """How a tunnel's UDP gets to its server.

    "direct" sends it straight out, which is what works almost everywhere.
    "wstunnel" wraps it in a WebSocket over TLS, for a network that drops
    the direct attempt.
    """

    kind: str = "direct"
    server: str = ""
    local_port: int = 51820
    sni: str = ""
    path_prefix: str = ""
    credentials: str = ""
    verify_certificate: bool = False


@dataclass
class Config:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    warp_masque: WarpProviderConfig = field(default_factory=WarpProviderConfig)
    warp_wireguard: WarpProviderConfig = field(default_factory=WarpProviderConfig)
    wg_custom: WgCustomConfig = field(default_factory=WgCustomConfig)
    direct: WarpProviderConfig = field(default_factory=WarpProviderConfig)
    split_tunnel: SplitTunnelConfig = field(default_factory=SplitTunnelConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)
    riseup: RiseupConfig = field(default_factory=RiseupConfig)


def config_path() -> Path:
    return _CONFIG_FILE


def results_path() -> Path:
    return _RESULTS_FILE


def _ensure_config_dir() -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _write_default_config() -> None:
    _ensure_config_dir()
    _CONFIG_FILE.write_text(_DEFAULT_CONFIG)


def _load_raw_config() -> dict:
    if not _CONFIG_FILE.exists():
        _write_default_config()
    return tomllib.loads(_CONFIG_FILE.read_text())


def _save_raw_config(raw: dict) -> None:
    _ensure_config_dir()
    _CONFIG_FILE.write_text(toml_dumps(raw))


class ConfigProblem(ValueError):
    """The config file could not be read as written."""


def _coerce(raw: dict, key: str, kind, default):
    """One field, with the default when it is missing or the wrong shape.

    Every one of these used to be a bare int() or float() on whatever the
    file said, and there was no handler anywhere above, so one stray
    character in a hand-edited config produced a traceback from every
    command, including `doctor`, whose whole job is to tell you the config is
    wrong.
    """
    if not isinstance(raw, dict) or key not in raw:
        return default
    try:
        return kind(raw[key])
    except (TypeError, ValueError):
        return default


def _section(raw: dict, *path: str) -> dict:
    """A nested table, or an empty one if it is missing or not a table."""
    node = raw
    for part in path:
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def load_config() -> Config:
    """Load config from disk, creating defaults if absent.

    Never raises because of what the file contains. A field that cannot be
    read falls back to its default, so a broken config degrades to a working
    tool that can tell you about it rather than a traceback.
    """
    try:
        raw = _load_raw_config()
    except Exception:
        # tomllib raises TOMLDecodeError, and a truncated or unreadable file
        # raises OSError. Either way there is nothing to read.
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    policy_raw = _section(raw, "policy")
    policy = PolicyConfig(
        probe_interval_minutes=_coerce(policy_raw, "probe_interval_minutes", int, 10),
        benchmark_interval_minutes=_coerce(
            policy_raw, "benchmark_interval_minutes", int, 30
        ),
        consecutive_rounds_to_act=_coerce(
            policy_raw, "consecutive_rounds_to_act", int, 2
        ),
        min_rtt_improvement_ms=_coerce(
            policy_raw, "min_rtt_improvement_ms", float, 15.0
        ),
        min_score_improvement_pct=_coerce(
            policy_raw, "min_score_improvement_pct", float, 20.0
        ),
    )

    providers_raw = _section(raw, "providers")

    warp_masque = WarpProviderConfig(
        enabled=_coerce(_section(providers_raw, "warp-masque"), "enabled", bool, True)
    )
    warp_wireguard = WarpProviderConfig(
        enabled=_coerce(
            _section(providers_raw, "warp-wireguard"), "enabled", bool, True
        )
    )
    custom_raw = _section(providers_raw, "wireguard-custom")
    direct = WarpProviderConfig(
        enabled=_coerce(_section(providers_raw, "direct"), "enabled", bool, True)
    )

    wg_custom = WgCustomConfig(
        enabled=_coerce(custom_raw, "enabled", bool, False),
        endpoint=_coerce(custom_raw, "endpoint", str, ""),
        public_key=_coerce(custom_raw, "public_key", str, ""),
        interface=_coerce(custom_raw, "interface", str, "wgcustom"),
        key_file=custom_raw.get("key_file"),
        address=_coerce(custom_raw, "address", str, "10.8.0.2/32"),
        dns=_coerce(custom_raw, "dns", str, "1.1.1.1"),
        allowed_ips=_coerce(custom_raw, "allowed_ips", str, "0.0.0.0/0"),
    )

    riseup_raw = _section(providers_raw, "riseup")
    provider_name = _coerce(riseup_raw, "provider", str, "riseup")
    if provider_name not in ("riseup", "calyx"):
        # It is a path component and a pkill pattern, so an arbitrary string
        # is not something to pass along.
        provider_name = "riseup"
    riseup_cfg = RiseupConfig(
        enabled=_coerce(riseup_raw, "enabled", bool, False),
        provider=provider_name,
        location=_coerce(riseup_raw, "location", str, ""),
        protocol=_coerce(riseup_raw, "protocol", str, "tcp")
        if _coerce(riseup_raw, "protocol", str, "tcp") in ("tcp", "udp")
        else "tcp",
        port=_coerce(riseup_raw, "port", int, 1194),
    )

    tr_raw = _section(raw, "transport")
    transport = TransportConfig(
        kind=_coerce(tr_raw, "kind", str, "direct"),
        server=_coerce(tr_raw, "server", str, ""),
        local_port=_coerce(tr_raw, "local_port", int, 51820),
        sni=_coerce(tr_raw, "sni", str, ""),
        path_prefix=_coerce(tr_raw, "path_prefix", str, ""),
        credentials=_coerce(tr_raw, "credentials", str, ""),
        verify_certificate=_coerce(tr_raw, "verify_certificate", bool, True),
    )

    st_raw = _section(raw, "split_tunnel")
    raw_excludes = st_raw.get("excludes", [])
    if isinstance(raw_excludes, str):
        # A bare string used to be iterated into single characters, so ten
        # one-character "CIDRs" were handed to `route add` one at a time.
        raw_excludes = [raw_excludes]
    elif not isinstance(raw_excludes, list):
        raw_excludes = []
    split_tunnel = SplitTunnelConfig(
        enabled=_coerce(st_raw, "enabled", bool, False),
        excludes=[str(item) for item in raw_excludes],
    )

    return Config(
        policy=policy,
        warp_masque=warp_masque,
        direct=direct,
        warp_wireguard=warp_wireguard,
        wg_custom=wg_custom,
        split_tunnel=split_tunnel,
        transport=transport,
        riseup=riseup_cfg,
    )


def configure_wg_custom(
    *,
    endpoint: str,
    public_key: str,
    key_file: str,
    interface: str = "wgcustom",
    address: str = "10.8.0.2/32",
    dns: str = "1.1.1.1",
    allowed_ips: str = "0.0.0.0/0",
) -> Path:
    """Enable and configure the self-hosted WireGuard provider."""
    raw = _load_raw_config()
    providers = raw.setdefault("providers", {})
    custom = providers.setdefault("wireguard-custom", {})
    custom.update(
        {
            "enabled": True,
            "endpoint": endpoint,
            "public_key": public_key,
            "interface": interface,
            "key_file": key_file,
            "address": address,
            "dns": dns,
            "allowed_ips": allowed_ips,
        }
    )
    _save_raw_config(raw)
    return _CONFIG_FILE


def set_provider_enabled(provider_id: str, enabled: bool) -> Path:
    """Turn one provider on or off in the config file."""
    raw = _load_raw_config()
    providers = raw.setdefault("providers", {})
    providers.setdefault(provider_id, {})["enabled"] = enabled
    _save_raw_config(raw)
    return _CONFIG_FILE


def configure_transport(
    *,
    kind: str,
    server: str = "",
    local_port: int = 51820,
    sni: str = "",
    path_prefix: str = "",
    credentials: str = "",
    verify_certificate: bool = False,
) -> Path:
    """Write the transport section, for a network that blocks the direct path."""
    raw = _load_raw_config()
    raw["transport"] = {
        "kind": kind,
        "server": server,
        "local_port": local_port,
        "sni": sni,
        "path_prefix": path_prefix,
        "credentials": credentials,
        "verify_certificate": verify_certificate,
    }
    _save_raw_config(raw)
    return _CONFIG_FILE
