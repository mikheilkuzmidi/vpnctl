FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iputils-ping \
        openvpn \
        resolvconf \
        wireguard-tools \
        wireguard-go \
    && rm -rf /var/lib/apt/lists/*

COPY docker/wg-smoke/entrypoint.sh /usr/local/bin/vpnctl-wg-smoke
COPY docker/wg-smoke/openvpn.sh /usr/local/bin/vpnctl-openvpn-smoke

RUN chmod +x /usr/local/bin/vpnctl-wg-smoke /usr/local/bin/vpnctl-openvpn-smoke

ENTRYPOINT ["/usr/local/bin/vpnctl-wg-smoke"]
