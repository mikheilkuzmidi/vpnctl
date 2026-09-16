# A WireGuard server and a wstunnel relay in one image, used from both ends of
# the bypass test: one container runs as the server, another as the client.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ARG WSTUNNEL_VERSION=10.7.1
ARG TARGETARCH=arm64

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iputils-ping \
        wireguard-tools \
        wireguard-go \
    && curl -fsSL \
        "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/wstunnel_${WSTUNNEL_VERSION}_linux_${TARGETARCH}.tar.gz" \
        -o /tmp/wstunnel.tar.gz \
    && tar -xzf /tmp/wstunnel.tar.gz -C /usr/local/bin wstunnel \
    && chmod +x /usr/local/bin/wstunnel \
    && rm -rf /tmp/wstunnel.tar.gz /var/lib/apt/lists/*

COPY docker/wg-bypass/server.sh /usr/local/bin/bypass-server
COPY docker/wg-bypass/client.sh /usr/local/bin/bypass-client
RUN chmod +x /usr/local/bin/bypass-server /usr/local/bin/bypass-client
