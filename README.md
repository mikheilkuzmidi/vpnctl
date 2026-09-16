# vpnctl - VPN Management Toolkit for macOS

`vpnctl` manages VPN tunnels from your Mac. The primary use-case is a
self-hosted **Tailscale exit node** on a cloud VPS - one command sets it up
from scratch. The free baseline of **Cloudflare WARP** and a legacy
**WireGuard** path are also supported.

---

## Tailscale Exit Node - One-Command Setup

This is the recommended, production-grade path. All traffic routes through
your own VPS, appearing to originate from its public IP.

### Requirements

| Tool | Install |
|------|---------|
| Python ≥ 3.11 | `brew install python` |
| Tailscale (Mac) | `brew install --cask tailscale` |
| SSH + SCP | pre-installed on macOS |

### Install vpnctl

```bash
# editable dev install (recommended)
pip install -e .
```

### Bootstrap a new VPS

```bash
vpnctl bootstrap-tailscale-exit-node \
  --ssh-target ubuntu@YOUR_VPS_IP \
  --identity-file ./LightsailDefaultKey-eu-central-1.pem \
  --hostname frankfurt-exit \
  --auth-key tskey-auth-XXXXXXXX        # optional but enables fully automated setup
```

Generate an auth key at https://login.tailscale.com/admin/settings/keys
(use type **Reusable**, no expiry recommended for long-lived servers).

**What this command does on the VPS:**
- Installs Tailscale (idempotent - safe to re-run)
- Enables IPv4 + IPv6 forwarding persistently via `sysctl`
- Applies UDP GRO optimisation (`ethtool`) for maximum throughput
- Starts Tailscale advertising itself as an exit node with `--accept-routes=false`

**Without `--auth-key`:** the command prints a browser URL. Visit it, then
approve the exit node in the Tailscale admin console.

### Firewall rules (AWS Lightsail)

In the Lightsail **Networking** tab:

| Action | Protocol | Port | Source |
|--------|----------|------|--------|
| **Delete** | TCP | 80 | Any IPv4 + IPv6 |
| **Keep** | TCP | 22 | Any IPv4 + IPv6 |
| **Add** | UDP | **41641** | Any IPv4 + IPv6 |

UDP 41641 enables direct peer connections. Without it traffic routes through
Tailscale DERP relays (~2× higher latency).

### Approve the exit node

1. Go to https://login.tailscale.com/admin/machines
2. Find the new node → **Edit route settings** → enable **Use as exit node**

### Activate on the Mac

```bash
tailscale set --exit-node=<TAILSCALE_IP>
```

### Verify

```bash
curl https://ifconfig.me             # must show VPS public IP
tailscale ping <TAILSCALE_IP>        # must say "via <IP>:41641" (not DERP)
```

---

## Cloudflare WARP (Free Baseline)

### Requirements

| Tool | Install |
|------|---------|
| Python ≥ 3.11 | `brew install python` |
| Cloudflare WARP | `brew install --cask cloudflare-warp` |

### Quick start

```bash
vpnctl doctor       # check all dependencies
vpnctl benchmark    # measure + rank all enabled providers
vpnctl connect      # connect top-ranked provider
vpnctl status       # show current tunnel + last benchmark
vpnctl tui          # live RTT / jitter / loss / speed monitor
vpnctl watch        # periodic probe loop (recommend only)
vpnctl watch --apply  # periodic probe loop (auto-switch)
vpnctl disconnect   # tear down active tunnel
```

### Configuration

Config lives at `~/.config/vpnctl/config.toml` (written on first run):

```toml
[policy]
probe_interval_minutes     = 10
benchmark_interval_minutes = 30
consecutive_rounds_to_act  = 2
min_rtt_improvement_ms     = 15.0
min_score_improvement_pct  = 20.0

[providers.warp-masque]
enabled = true

[providers.warp-wireguard]
enabled = true

[providers.wireguard-custom]
enabled = false
```

### Split tunnelling

```bash
vpnctl split-tunnel list
vpnctl split-tunnel add 10.0.0.0/8
vpnctl split-tunnel enable
```

CIDRs in the exclusion list bypass the VPN and go via your normal internet
connection. Works for both WARP and wireguard-custom providers.

---

## Self-Hosted WireGuard (Legacy)

```bash
vpnctl bootstrap-wireguard-vps \
  --ssh-target ubuntu@YOUR_VPS_IP \
  --identity-file ./vps.pem

vpnctl doctor
vpnctl connect wireguard-custom
curl -4 https://ifconfig.me
```

For smoke-testing the WireGuard tunnel inside Docker without touching host
routing:

```bash
vpnctl docker-smoke-test
```

---

## Architecture

```
src/vpnctl/
├── cli.py                  - Click entry-point, all user-facing commands
├── tailscale_bootstrap.py  - Tailscale exit-node VPS provisioning over SSH
├── bootstrap.py            - WireGuard VPS provisioning over SSH
├── config.py               - TOML config loader + schema defaults
├── probe.py                - RTT, jitter, loss, throughput, scoring
├── selector.py             - Ranks providers, enforces policy, picks winner
├── watch.py                - Periodic background loop
├── tui.py                  - Live Rich TUI monitor
├── split_tunnel.py         - macOS split-tunnel helpers
├── docker_smoke.py         - Docker-isolated WireGuard smoke test
├── toml_utils.py           - TOML writer shim
└── providers/
    ├── base.py             - Abstract ProviderAdapter contract
    ├── warp_masque.py      - WARP MASQUE adapter
    ├── warp_wireguard.py   - WARP WireGuard adapter
    └── wg_custom.py        - Self-hosted WireGuard adapter

setup_tailscale_exit_node.sh  - VPS-side Tailscale setup script
```
