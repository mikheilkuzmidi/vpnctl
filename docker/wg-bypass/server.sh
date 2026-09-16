#!/usr/bin/env bash
# The far end of the bypass: a WireGuard server that is deliberately
# unreachable except through the wstunnel relay.
set -euo pipefail

SERVER_PRIV="$(cat /keys/server.key)"
CLIENT_PUB="$(cat /keys/client.pub)"

cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${SERVER_PRIV}
Address = 10.9.0.1/24
ListenPort = 51820

[Peer]
PublicKey = ${CLIENT_PUB}
AllowedIPs = 10.9.0.2/32
CONF
chmod 600 /etc/wireguard/wg0.conf

export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
wg-quick up wg0

# Route the tunnel's traffic out of the container, so a client that arrives
# through it can actually reach something.
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i wg0 -j ACCEPT

# The point of the exercise: WireGuard's own port is not reachable from the
# network. Anything that wants this tunnel has to come in over TCP 443, which
# is what a restrictive network leaves open.
iptables -A INPUT -i eth0 -p udp --dport 51820 -j DROP
echo "[server] udp/51820 blocked on eth0; only tcp/443 is open"

echo "[server] starting wstunnel on tcp/443"
exec wstunnel server --restrict-to 127.0.0.1:51820 ws://0.0.0.0:443
