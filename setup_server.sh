#!/usr/bin/env bash
# Turn a fresh Debian or Ubuntu VPS into a WireGuard server, and optionally
# into a relay that carries the tunnel over TCP 443.
#
# Run by `vpnctl bootstrap-wireguard-vps`, which copies it over and executes
# it. Safe to run more than once: server keys are generated only if absent,
# and every write is idempotent.
#
#   setup_server.sh CLIENT_PUBLIC_KEY [PORT] [WITH_WSTUNNEL]
#
# Prints SERVER_PUBKEY= and SERVER_ENDPOINT= for the caller to parse, plus
# WSTUNNEL= when the relay was installed.
#
# Why the relay matters: some networks let ordinary HTTPS through and drop
# every known VPN endpoint, so a WireGuard server on its own is unreachable
# from them no matter which UDP port it uses. wstunnel carries the same UDP
# inside a WebSocket over TLS on 443, which such networks do carry.
set -euo pipefail

CLIENT_PUBKEY="${1:?client public key required}"
WG_PORT="${2:-51820}"
WITH_WSTUNNEL="${3:-no}"

WG_DIR=/etc/wireguard
WG_CONF="$WG_DIR/wg0.conf"
SERVER_KEY="$WG_DIR/server.key"
SERVER_PUB="$WG_DIR/server.pub"
TUNNEL_NET="10.8.0.0/24"
SERVER_ADDR="10.8.0.1/24"
CLIENT_ADDR="10.8.0.2/32"
WSTUNNEL_VERSION="10.7.1"

if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq wireguard-tools iptables curl >/dev/null

$SUDO mkdir -p "$WG_DIR"
$SUDO chmod 700 "$WG_DIR"

# Keys are generated once. Regenerating them would silently invalidate every
# client already configured against this server.
# Keys are generated once, but the public half is derived whenever it is
# missing. Gating both on the private key meant a run that died between the
# two steps left the script aborting under set -e on every later attempt,
# with no way to recover, despite the header promising it is re-runnable.
if [ ! -s "$SERVER_KEY" ]; then
  umask 077
  wg genkey | $SUDO tee "$SERVER_KEY" >/dev/null
  $SUDO chmod 600 "$SERVER_KEY"
fi
if [ ! -s "$SERVER_PUB" ]; then
  $SUDO sh -c "wg pubkey < '$SERVER_KEY' > '$SERVER_PUB'"
fi

SERVER_PRIVATE="$($SUDO cat "$SERVER_KEY")"
SERVER_PUBLIC="$($SUDO cat "$SERVER_PUB")"

# The interface traffic leaves by, whatever it is called on this host.
# Read the word after "dev", not field five. On a host whose default route
# is "default dev eth0 scope link", field five is the word "scope", which
# then went into the MASQUERADE rule and made wg-quick abort on every start.
EGRESS_IF="$(ip -4 route show default \
  | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit } }')"
EGRESS_IF="${EGRESS_IF:-eth0}"

$SUDO tee "$WG_CONF" >/dev/null <<CONF
[Interface]
Address = ${SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE}
PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${TUNNEL_NET} -o ${EGRESS_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${TUNNEL_NET} -o ${EGRESS_IF} -j MASQUERADE

[Peer]
PublicKey = ${CLIENT_PUBKEY}
AllowedIPs = ${CLIENT_ADDR}
CONF
$SUDO chmod 600 "$WG_CONF"

echo "net.ipv4.ip_forward=1" | $SUDO tee /etc/sysctl.d/99-vpnctl.conf >/dev/null
$SUDO sysctl -q -p /etc/sysctl.d/99-vpnctl.conf

$SUDO systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
# Restart rather than start, so a re-run picks up a changed peer list.
$SUDO systemctl restart wg-quick@wg0

if [ "$WITH_WSTUNNEL" = "yes" ]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)  WS_ARCH=amd64 ;;
    aarch64) WS_ARCH=arm64 ;;
    *) echo "WSTUNNEL=unsupported-arch-$ARCH" ; WS_ARCH="" ;;
  esac

  if [ -n "$WS_ARCH" ]; then
    if [ ! -x /usr/local/bin/wstunnel ]; then
      # Into a private directory, not a predictable path in a shared /tmp:
      # curl runs unprivileged and tar ran as root, so a local user who
      # pre-created that path chose what root extracted into /usr/local/bin.
      STAGE="$(mktemp -d)"
      chmod 700 "$STAGE"
      trap 'rm -rf "$STAGE"' EXIT
      curl -fsSL \
        "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${WS_ARCH}.tar.gz" \
        -o "$STAGE/wstunnel.tar.gz"
      tar -xzf "$STAGE/wstunnel.tar.gz" -C "$STAGE" wstunnel
      $SUDO install -m 0755 -o root -g root "$STAGE/wstunnel" /usr/local/bin/wstunnel
    fi

    # --restrict-to is not optional. Without it the relay will forward to any
    # host and port a client names, which is an open proxy on port 443.
    $SUDO tee /etc/systemd/system/wstunnel.service >/dev/null <<UNIT
[Unit]
Description=wstunnel relay for vpnctl
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/wstunnel server --restrict-to 127.0.0.1:${WG_PORT} wss://0.0.0.0:443
Restart=always
RestartSec=2
# Without a burst limit an always-restart unit crash loops unbounded.
StartLimitBurst=5
StartLimitIntervalSec=60
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
# DynamicUser already implies ProtectSystem, ProtectHome and PrivateTmp.
# What a public facing daemon actually wants, and did not have:
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
UNIT
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable wstunnel >/dev/null 2>&1 || true
    $SUDO systemctl restart wstunnel
    echo "WSTUNNEL=listening-on-443"
  fi
fi

PUBLIC_IP="$(curl -4fsS --max-time 10 https://1.1.1.1/cdn-cgi/trace | awk -F= '$1=="ip"{print $2}' || true)"

echo "SERVER_PUBKEY=${SERVER_PUBLIC}"
if [ -n "$PUBLIC_IP" ]; then
  echo "SERVER_ENDPOINT=${PUBLIC_IP}:${WG_PORT}"
fi
