#!/usr/bin/env bash
# Runs on the VPS — installs Tailscale and configures it as a pure exit node.
#
# Usage:
#   setup_tailscale_exit_node.sh [--hostname NAME] [--auth-key KEY]
#
# Options:
#   --hostname NAME   Tailscale node hostname (default: current hostname)
#   --auth-key  KEY   Tailscale auth key for unattended setup.
#                     Generate one at https://login.tailscale.com/admin/settings/keys
#                     If omitted the script prints a browser URL you must visit.
#
# Output markers (parsed by vpnctl bootstrap-tailscale-exit-node):
#   TAILSCALE_AUTH_URL=https://...   when manual browser auth is needed
#   TAILSCALE_IP=100.x.x.x          after successful authentication
#   TAILSCALE_STATUS=Running|needs-auth|error
#
# The script is idempotent — safe to run multiple times.
set -euo pipefail

HOSTNAME_ARG="${HOSTNAME:-$(hostname -s)}"
AUTH_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
    --auth-key)  AUTH_KEY="$2";     shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── 1. Install Tailscale (skip if already present) ───────────────────────────
install_tailscale() {
  if command -v tailscale >/dev/null 2>&1; then
    return
  fi
  curl -fsSL https://tailscale.com/install.sh | sh
}

# ── 2. Enable IP forwarding (persistent across reboots) ──────────────────────
enable_ip_forwarding() {
  printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' \
    | sudo tee /etc/sysctl.d/99-tailscale.conf > /dev/null
  sudo sysctl -p /etc/sysctl.d/99-tailscale.conf -q
}

# ── 3. UDP GRO forwarding optimisation (improves throughput) ─────────────────
apply_udp_gro() {
  local iface
  iface=$(ip route get 8.8.8.8 \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' \
    | head -1)
  [[ -z "$iface" ]] && return

  if ! command -v ethtool >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ethtool -qq 2>/dev/null || return
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y ethtool -q 2>/dev/null || return
    else
      return
    fi
  fi

  sudo ethtool -K "$iface" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true

  sudo tee /etc/systemd/system/ethtool-tune.service > /dev/null <<EOF
[Unit]
Description=Tailscale UDP GRO forwarding optimisation
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ethtool -K ${iface} rx-udp-gro-forwarding on rx-gro-list off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now ethtool-tune.service 2>/dev/null || true
}

# ── 4. Start Tailscale as exit node ──────────────────────────────────────────
start_tailscale() {
  sudo systemctl enable --now tailscaled 2>/dev/null || true

  local up_args=(
    "--advertise-exit-node"
    "--accept-routes=false"
    "--hostname=${HOSTNAME_ARG}"
  )
  [[ -n "$AUTH_KEY" ]] && up_args+=("--auth-key=${AUTH_KEY}")

  local tmpfile exit_code
  tmpfile=$(mktemp)
  exit_code=0

  timeout 20 sudo tailscale up "${up_args[@]}" >"$tmpfile" 2>&1 || exit_code=$?

  echo ""
  echo "===VPNCTL==="

  if [[ $exit_code -eq 0 ]]; then
    local ip
    ip=$(sudo tailscale ip -4 2>/dev/null || echo "")
    echo "TAILSCALE_IP=${ip}"
    echo "TAILSCALE_STATUS=Running"
  elif [[ $exit_code -eq 124 ]]; then
    local auth_url
    auth_url=$(grep -o 'https://login\.tailscale\.com/a/[a-z0-9]*' "$tmpfile" 2>/dev/null \
      | head -1 || true)
    if [[ -n "$auth_url" ]]; then
      echo "TAILSCALE_AUTH_URL=${auth_url}"
      echo "TAILSCALE_STATUS=needs-auth"
    else
      echo "TAILSCALE_STATUS=error"
      cat "$tmpfile" >&2
    fi
  else
    echo "TAILSCALE_STATUS=error"
    cat "$tmpfile" >&2
  fi

  rm -f "$tmpfile"
}

install_tailscale
enable_ip_forwarding
apply_udp_gro
start_tailscale
