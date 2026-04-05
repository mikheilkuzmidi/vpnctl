# vpnctl — Zero-Cost VPN Selector for macOS

`vpnctl` benchmarks and connects to the fastest available free VPN tunnel from
your MacBook.  The permanent free baseline is **Cloudflare WARP** in both
`MASQUE` and `WireGuard` modes.  An optional self-hosted WireGuard endpoint can
be added later without any code changes.

---

## Requirements

| Tool | Install |
|------|---------|
| Python ≥ 3.11 | `brew install python` |
| Cloudflare WARP | `brew install --cask cloudflare-warp` |
| wireguard-tools *(optional)* | `brew install wireguard-tools` |

Run `vpnctl doctor` after installation — it explains every missing piece.

---

## Install

```bash
python3 -m pip install --user .
# or, for editable dev mode:
python3 -m pip install --user -e .
```

After install the `vpnctl` binary is on your PATH.

---

## Quick start

```bash
# Check dependencies
vpnctl doctor

# Benchmark all enabled providers and store result
vpnctl benchmark

# Connect to the top-ranked provider
vpnctl connect

# Show current tunnel and last benchmark
vpnctl status

# Periodic watch mode (recommend only)
vpnctl watch

# Periodic watch mode (auto-apply reconnects)
vpnctl watch --apply

# Disconnect whatever is active
vpnctl disconnect

# Bootstrap a VPS WireGuard node over SSH without connecting to it yet
vpnctl bootstrap-wireguard-vps \
  --ssh-target ubuntu@203.0.113.10 \
  --identity-file ./vps.pem

# Validate the VPS tunnel inside Docker without touching host routing
vpnctl docker-smoke-test
```

---

## Configuration

Config lives at `~/.config/vpnctl/config.toml`.  A default file is written on
first run.  All settings are documented inline.

```toml
[policy]
probe_interval_minutes   = 10   # light RTT probe on active tunnel
benchmark_interval_minutes = 30 # full cross-provider benchmark
consecutive_rounds_to_act  = 2  # rounds an alternative must win before action
min_rtt_improvement_ms     = 15 # min median-RTT gain to consider switching
min_score_improvement_pct  = 20 # min total-score gain to consider switching

[providers.warp-masque]
enabled = true

[providers.warp-wireguard]
enabled = true

[providers.wireguard-custom]
enabled = false
# endpoint = "203.0.113.1:51820"
# public_key = "..."
# interface = "wgcustom"
# key_file = "~/.config/vpnctl/wg-custom.key"  # chmod 600, never committed
```

---

## Adding a self-hosted WireGuard endpoint

Fast path:

```bash
vpnctl bootstrap-wireguard-vps \
  --ssh-target ubuntu@YOUR_VPS_HOST \
  --identity-file ./vps.pem
```

This will:
- generate or reuse `~/.config/vpnctl/wg-custom.key`
- upload and run `setup_server.sh` on the VPS
- enable `[providers.wireguard-custom]` in `~/.config/vpnctl/config.toml`

Then run:

```bash
vpnctl doctor
vpnctl benchmark
vpnctl connect wireguard-custom
```

Manual verification without shell comments:

```bash
vpnctl doctor
vpnctl connect wireguard-custom
vpnctl status
sudo wg show
curl -4 https://ifconfig.me
vpnctl disconnect
```

If you are pasting commands directly into interactive `zsh`, avoid lines that
start with `#` unless you have enabled `setopt interactivecomments`.

## Docker smoke test

`vpnctl docker-smoke-test` starts the configured `wireguard-custom` tunnel
inside an isolated Docker container. This verifies the VPS endpoint, keys,
and WireGuard handshake path without changing the Mac's routes or interfaces.

It is a server-side validation tool, not a replacement for the native macOS
client path.

---

## Architecture

```
vpnctl/
├── cli.py          — Click entry-point, all user-facing commands
├── config.py       — TOML config loader + schema defaults
├── probe.py        — Probe engine: RTT, jitter, loss, throughput, scoring
├── bootstrap.py    — Safe VPS bootstrap over SSH for self-hosted WireGuard
├── selector.py     — Ranks providers, enforces policy, picks winner
├── watch.py        — Periodic background loop (probe + full benchmark)
└── providers/
    ├── base.py          — Abstract ProviderAdapter contract
    ├── warp_masque.py   — WARP MASQUE adapter
    ├── warp_wireguard.py— WARP WireGuard adapter
    └── wg_custom.py     — Self-hosted WireGuard adapter
```

Every provider implements the same five-method contract:
`prepare() → connect() → disconnect() → status() → probe()`.
The selector and watch loop are provider-agnostic.
