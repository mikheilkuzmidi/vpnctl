# vpnctl running as root on Linux, for the recorded demo.
#
# `connect` moves the default route, which needs root. On a Mac that means an
# interactive sudo prompt, which a recording cannot answer, so the demo would
# either skip the one command the tool exists for or put a password prompt on
# camera. As root in a container it just works, and the connect is real: a
# real handshake, the container's whole default route moved onto the tunnel.
#
# This is also the image that proves vpnctl runs on Linux at all.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iputils-ping \
        python3 \
        python3-pip \
        wireguard-tools \
        wireguard-go \
        zsh \
    && rm -rf /var/lib/apt/lists/*

# --break-system-packages because this image is the environment, so there is
# nothing for a virtualenv to isolate it from.
COPY pyproject.toml README.md /src/
COPY src /src/src
RUN pip3 install --no-cache-dir --break-system-packages /src

# Only the free provider is enabled. The demo does not benchmark, so nothing
# needs the others, and a provider that cannot work here would show up in
# doctor as noise.
RUN mkdir -p /root/.config/vpnctl \
    && printf '%s\n' \
        '[providers.warp-wireguard]' \
        'enabled = true' \
        '' \
        '[providers.warp-masque]' \
        'enabled = false' \
        '' \
        '[providers.direct]' \
        'enabled = true' \
        '' \
        '[split_tunnel]' \
        'enabled = false' \
        > /root/.config/vpnctl/config.toml

# The recorded prompt, matching the other demos in the set.
RUN printf '%s\n' \
        'unsetopt ZLE' \
        'unsetopt PROMPT_SP PROMPT_CR' \
        "PROMPT='%F{6}~%f \$ '" \
        > /root/.zshrc

WORKDIR /root
ENTRYPOINT ["/usr/bin/zsh", "-i"]
