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
# Wait for the peer to answer before touching the network.
#
# AllowedIPs is 0.0.0.0/0, so once the interface is up every packet including
# DNS goes into the tunnel. If the peer never replies, the first thing to fail
# is name resolution, and the test used to report
# "curl: (6) Could not resolve host: ifconfig.me" for a dead VPS: a DNS error
# for a problem that has nothing to do with DNS. Check the handshake itself.
echo "[smoke] waiting for a handshake"
handshake=0
for _ in $(seq 1 "${SMOKE_HANDSHAKE_TIMEOUT:-15}"); do
  handshake="$(wg show "$REAL_IF" latest-handshakes | awk '{ if ($2 > max) max = $2 } END { print max + 0 }')"
  [ "$handshake" -gt 0 ] && break
  sleep 1
done

if [ "$handshake" -eq 0 ]; then
  echo "NO_HANDSHAKE=1"
  echo "[smoke] the peer never answered." >&2
  echo "[smoke] the interface is up and packets are being sent, so the config" >&2
  echo "[smoke] is well formed: the endpoint, its UDP port, or the peer entry" >&2
  echo "[smoke] on the server is what to look at." >&2
  exit 3
fi

echo "[smoke] handshake ok"

# Ask over an IP literal, not a hostname.
#
# AllowedIPs is 0.0.0.0/0, so DNS goes into the tunnel too, and the container's
# resolver does not. Resolving a name here made the check fail for a reason
# that has nothing to do with whether the tunnel carries traffic. 1.1.1.1
# serves a valid certificate for its own address, and its trace endpoint
# reports the egress address and, usefully, whether Cloudflare sees the
# request arriving over WARP.
TRACE="$(curl -4fsS --max-time 25 https://1.1.1.1/cdn-cgi/trace || true)"
if [ -z "$TRACE" ]; then
  echo "NO_EGRESS=1"
  echo "[smoke] handshake succeeded but no traffic came back through the tunnel." >&2
  exit 4
fi

PUBLIC_IP="$(printf '%s\n' "$TRACE" | awk -F= '$1 == "ip" { print $2 }')"
echo "PUBLIC_IP=${PUBLIC_IP}"
printf '%s\n' "$TRACE" | awk -F= '$1 == "warp" { print "WARP=" $2 }'
printf '%s\n' "$TRACE" | awk -F= '$1 == "loc"  { print "LOC="  $2 }'

# DNS is a separate question, and the one that leaks. wg-quick's DNS= needs
# resolvconf or systemd-resolved, neither of which works in a container, so
# point the resolver at the tunnel's own server and check a name resolves
# through it.
echo "[smoke] dns"
if [ -n "${SMOKE_DNS:-}" ]; then
  printf 'nameserver %s\n' "$SMOKE_DNS" > /etc/resolv.conf 2>/dev/null || true
fi
if getent hosts one.one.one.one >/dev/null 2>&1; then
  echo "DNS=ok"
else
  echo "DNS=failed"
fi

echo "[smoke] ping"
# Not a pass criterion: plenty of VPN egresses drop ICMP, and this
# is the last command under set -e, so its status was the
# container's and a working tunnel was reported as a failure.
ping -c 3 1.1.1.1 || true
