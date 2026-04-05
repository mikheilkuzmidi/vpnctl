#!/usr/bin/env bash
set -euo pipefail

CONF_PATH="${1:-/config/wgsmoke.conf}"
export WG_QUICK_USERSPACE_IMPLEMENTATION="${WG_QUICK_USERSPACE_IMPLEMENTATION:-wireguard-go}"

cleanup() {
  wg-quick down "$CONF_PATH" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[smoke] bringing up $CONF_PATH"
wg-quick up "$CONF_PATH"

REAL_IF="$(wg show interfaces | awk '{print $1}')"
echo "[smoke] interface=${REAL_IF}"
ip addr show "$REAL_IF"
echo "[smoke] routes"
ip route
echo "[smoke] wg show"
wg show
PUBLIC_IP="$(curl -4fsS https://ifconfig.me)"
echo "PUBLIC_IP=${PUBLIC_IP}"
echo "[smoke] ping"
ping -c 3 1.1.1.1
