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
# Example - keep your IDE / AI assistant on the plain internet:
#
# [split_tunnel]
# enabled = true
# excludes = [
#   "34.107.0.0/16",    # Codeium / Windsurf API
#   "162.159.0.0/16",   # Cloudflare
#   "192.168.0.0/16",   # local LAN (always a good idea)
# ]
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
class Config:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    warp_masque: WarpProviderConfig = field(default_factory=WarpProviderConfig)
    warp_wireguard: WarpProviderConfig = field(default_factory=WarpProviderConfig)
    wg_custom: WgCustomConfig = field(default_factory=WgCustomConfig)
    split_tunnel: SplitTunnelConfig = field(default_factory=SplitTunnelConfig)


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


def load_config() -> Config:
    """Load config from disk, creating defaults if absent."""
    raw = _load_raw_config()

    policy_raw = raw.get("policy", {})
    policy = PolicyConfig(
        probe_interval_minutes=int(
            policy_raw.get("probe_interval_minutes", 10)
        ),
        benchmark_interval_minutes=int(
            policy_raw.get("benchmark_interval_minutes", 30)
        ),
        consecutive_rounds_to_act=int(
            policy_raw.get("consecutive_rounds_to_act", 2)
        ),
        min_rtt_improvement_ms=float(
            policy_raw.get("min_rtt_improvement_ms", 15.0)
        ),
        min_score_improvement_pct=float(
            policy_raw.get("min_score_improvement_pct", 20.0)
        ),
    )

    providers_raw = raw.get("providers", {})

    masque_raw = providers_raw.get("warp-masque", {})
    warp_masque = WarpProviderConfig(enabled=bool(masque_raw.get("enabled", True)))

    wg_raw = providers_raw.get("warp-wireguard", {})
    warp_wireguard = WarpProviderConfig(enabled=bool(wg_raw.get("enabled", True)))

    custom_raw = providers_raw.get("wireguard-custom", {})
    wg_custom = WgCustomConfig(
        enabled=bool(custom_raw.get("enabled", False)),
        endpoint=str(custom_raw.get("endpoint", "")),
        public_key=str(custom_raw.get("public_key", "")),
        interface=str(custom_raw.get("interface", "wgcustom")),
        key_file=custom_raw.get("key_file"),
        address=str(custom_raw.get("address", "10.8.0.2/32")),
        dns=str(custom_raw.get("dns", "1.1.1.1")),
        allowed_ips=str(custom_raw.get("allowed_ips", "0.0.0.0/0")),
    )

    st_raw = raw.get("split_tunnel", {})
    split_tunnel = SplitTunnelConfig(
        enabled=bool(st_raw.get("enabled", False)),
        excludes=list(st_raw.get("excludes", [])),
    )

    return Config(
        policy=policy,
        warp_masque=warp_masque,
        warp_wireguard=warp_wireguard,
        wg_custom=wg_custom,
        split_tunnel=split_tunnel,
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
