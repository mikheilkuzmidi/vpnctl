#!/usr/bin/env bash
# The OpenVPN half of the sandbox test.
#
# Same contract as the WireGuard entrypoint: bring the tunnel up inside this
# container, report the egress address and whether DNS works, and print
# nothing that could be mistaken for success if it did not.
set -euo pipefail

CONF_PATH="${1:-/config/openvpn.conf}"
READY="Initialization Sequence Completed"
LOG=/tmp/openvpn.log

echo "[smoke] bringing up $CONF_PATH"

# --script-security stays at its default of 0, so no config can ask openvpn to
# run a program. The config is fetched over the network, so that matters.
openvpn --config "$CONF_PATH" --log "$LOG" --daemon
trap 'pkill -TERM openvpn >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 "${SMOKE_READY_TIMEOUT:-60}"); do
  if grep -qF "$READY" "$LOG" 2>/dev/null; then
    break
  fi
  if ! pgrep -x openvpn >/dev/null 2>&1; then
    echo "NO_TUNNEL=1"
    echo "[smoke] openvpn exited before the tunnel came up." >&2
    tail -20 "$LOG" >&2 || true
    exit 3
  fi
  sleep 1
done

if ! grep -qF "$READY" "$LOG" 2>/dev/null; then
  echo "NO_TUNNEL=1"
  echo "[smoke] openvpn never finished its initialisation sequence." >&2
  tail -20 "$LOG" >&2 || true
  exit 3
fi

echo "[smoke] tunnel up"
ip -4 addr show dev tun0 2>/dev/null || true

# Over an IP literal, for the same reason as the WireGuard path: the tunnel
# carries DNS too, so resolving a name here would conflate two questions.
TRACE="$(curl -4fsS --max-time 25 https://1.1.1.1/cdn-cgi/trace || true)"
if [ -z "$TRACE" ]; then
  echo "NO_EGRESS=1"
  echo "[smoke] the tunnel came up but no traffic came back through it." >&2
  exit 4
fi

printf '%s\n' "$TRACE" | awk -F= '$1 == "ip"   { print "PUBLIC_IP=" $2 }'
printf '%s\n' "$TRACE" | awk -F= '$1 == "warp" { print "WARP=" $2 }'
printf '%s\n' "$TRACE" | awk -F= '$1 == "loc"  { print "LOC=" $2 }'

echo "[smoke] dns"
if getent hosts one.one.one.one >/dev/null 2>&1; then
  echo "DNS=ok"
else
  echo "DNS=failed"
fi
