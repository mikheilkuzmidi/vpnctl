#!/usr/bin/env bash
# The near end: prove a tunnel can be established when its UDP port is
# unreachable and only TCP 443 gets through.
set -euo pipefail

SERVER_HOST="${1:?server host}"
CLIENT_PRIV="$(cat /keys/client.key)"
SERVER_PUB="$(cat /keys/server.pub)"

echo "[client] baseline egress: $(ip route get 1.1.1.1 | head -1)"

# First, show the direct path really is closed, so a later success cannot be
# explained by the block not being there.
cat > /etc/wireguard/direct.conf <<CONF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.9.0.2/32

[Peer]
PublicKey = ${SERVER_PUB}
AllowedIPs = 10.9.0.0/24
Endpoint = ${SERVER_HOST}:51820
PersistentKeepalive = 25
CONF
chmod 600 /etc/wireguard/direct.conf
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
wg-quick up direct >/dev/null 2>&1
sleep 6
DIRECT_HS="$(wg show direct latest-handshakes | awk '{ if ($2 > m) m = $2 } END { print m + 0 }')"
wg-quick down direct >/dev/null 2>&1
if [ "$DIRECT_HS" -gt 0 ]; then
  echo "DIRECT=reachable"
  echo "[client] the direct path was not blocked, so this proves nothing" >&2
  exit 3
fi
echo "DIRECT=blocked"

# Now the same tunnel, carried over TCP 443.
echo "[client] starting wstunnel to ${SERVER_HOST}"
wstunnel client -L "udp://127.0.0.1:51820:127.0.0.1:51820" "ws://${SERVER_HOST}:443" &
WSPID=$!
for _ in $(seq 1 40); do
  ss -lun 2>/dev/null | grep -q "127.0.0.1:51820" && break
  sleep 0.25
done

cat > /etc/wireguard/bypass.conf <<CONF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.9.0.2/32

[Peer]
PublicKey = ${SERVER_PUB}
AllowedIPs = 10.9.0.0/24
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
CONF
chmod 600 /etc/wireguard/bypass.conf
wg-quick up bypass

for _ in $(seq 1 40); do
  HS="$(wg show bypass latest-handshakes | awk '{ if ($2 > m) m = $2 } END { print m + 0 }')"
  [ "$HS" -gt 0 ] && break
  sleep 1
done

if [ "${HS:-0}" -eq 0 ]; then
  echo "TUNNELLED=no"
  wg show bypass
  kill $WSPID 2>/dev/null || true
  exit 4
fi
echo "TUNNELLED=yes"

# And it carries traffic, not just a handshake.
if ping -c 3 -W 3 10.9.0.1 >/dev/null 2>&1; then
  echo "TRAFFIC=yes"
else
  echo "TRAFFIC=no"
fi
wg show bypass | grep -E "transfer|latest handshake" || true
kill $WSPID 2>/dev/null || true
