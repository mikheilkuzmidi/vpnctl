# vpnctl

A VPN client for macOS that works the moment you clone it. No account, no
payment, no server of your own, and nothing to configure.

```bash
git clone https://github.com/mikheilkuzmidi/vpnctl && cd vpnctl
pip install -e .
vpnctl
```

That opens a menu. Pick "Free VPN, set up for me" and it registers an
anonymous Cloudflare WARP device, then `vpnctl connect` routes the whole
machine through it.

It also measures the providers it can reach and ranks them, tests a tunnel in
a container before touching your routing, and carries the tunnel over TLS on
port 443 when the network you are on refuses to pass a VPN at all.

## What it connects to

| Provider | Account | Cost | Notes |
|----------|---------|------|-------|
| `warp-wireguard` | none | free | Cloudflare WARP. Anonymous device registration, unlimited, fastest to set up. One large company carries your traffic. |
| `riseup` | none | free | A privacy nonprofit, over OpenVPN. Also anonymous. Slower, and sometimes busy. Offers TCP on 53, 80 and 1194, which some restrictive networks pass. |
| `wireguard-custom` | yours | your VPS | Your own WireGuard server. The only option where nobody else sees your traffic. `vpnctl bootstrap-wireguard-vps` sets one up. |
| `direct` | n/a | n/a | Not a VPN. The unprotected connection, measured as the control every tunnel is ranked against. |

Nothing personal is sent to any of them. WARP is told a freshly generated
public key, a random install id, the string "PC" and a locale. Riseup issues a
short-lived client certificate to anyone who asks; its own API reports
`allow_anonymous: true` and `allow_registration: false`. Private keys are
generated locally and never leave the machine, and every file holding one is
created at mode 0600 rather than chmod-ed afterwards.

## Requirements

| Tool | Install | Needed for |
|------|---------|------------|
| Python 3.11 or newer | `brew install python` | everything |
| wireguard-tools | `brew install wireguard-tools` | the WireGuard providers |
| openvpn | `brew install openvpn` | Riseup |
| Docker | Docker Desktop | the container tests only |
| wstunnel | `brew install wstunnel` | the bypass transport only |

`vpnctl setup` installs wireguard-tools for you if Homebrew is present.
Bringing a tunnel up moves the default route, which needs root, so `connect`
and `disconnect` ask for your password. Nothing else does.

## Everyday use

```bash
vpnctl                  # the menu: everything below, by arrow key
vpnctl setup            # choose a provider, once
vpnctl doctor           # what is missing, per provider, with the fix
vpnctl benchmark        # connect each provider in turn, measure it, rank it
vpnctl connect          # route this machine through the best one
vpnctl status           # current tunnel and the last benchmark
vpnctl tui              # live RTT, jitter, loss and throughput
vpnctl disconnect
```

`benchmark` runs a real probe against each provider: ping to three hosts for
median RTT, jitter and loss, then a throughput measurement. Nothing is
simulated, and the unprotected connection is one of the rows so the numbers
mean something.

## When the network blocks VPNs

Plenty of networks do, and they rarely say so. What you see instead is a
tunnel that comes up and then carries nothing.

```bash
vpnctl diagnose
```

This changes no routing. It measures what the network actually allows and
says which of them applies. On the university network this was developed
against, it reports:

```
  dns                                     ok   resolves
  tls:ordinary:github.com:443             ok   TLS TLSv1.3
  tls:cloudflare:api.cloudflareclient.com ok   TLS TLSv1.3
  udp:stun.cloudflare.com:3478            ok   replied, 32 bytes
  tls:tunnel:Riseup's VPN API             no   ConnectionResetError
  tls:tunnel:a Riseup gateway             no   timed out
  tls:tunnel:the Tor Project              no   ConnectionResetError

This network filters VPN destinations. Ordinary HTTPS works, but none of the
3 tunnel endpoints tested would even complete a TLS handshake. Outbound UDP
itself is fine, so the block is about where the traffic is going, not what it
looks like.

Try warp-wireguard first. Cloudflare's network is reachable from here, and a
network that blocklists VPN providers usually cannot afford to blocklist
Cloudflare.
```

Two things worth taking from that. The network is filtering destinations
rather than recognising protocols, so disguising WireGuard's packets is not
the fix; sending them somewhere nobody has blacklisted is. And "this network
blocks VPNs" is too coarse a conclusion to act on: blocklisting one
provider's gateways is cheap, while blocklisting Cloudflare's anycast ranges
breaks too much ordinary traffic for most networks to attempt.

On the university network this was developed against, `warp-wireguard`
connects and carries traffic while Riseup and Tor are both dead. So reach for
the free hosted provider first, and for a transport only when that is
blocked too.

### The transport

A tunnel can be carried over something ordinary instead of dialled directly:

```
WireGuard  ->  127.0.0.1:51820  ->  wstunnel  ->  TLS 443  ->  your server
```

To the network this is an HTTPS connection to an ordinary host, because that
is what it is.

```bash
# one command: provision the server and point this machine at it
vpnctl bootstrap-wireguard-vps \
  --ssh-target ubuntu@YOUR_VPS_IP \
  --identity-file ./your-ssh-key.pem \
  --with-wstunnel

vpnctl transport show
vpnctl transport test      # prove it, in containers
vpnctl connect
```

It has to be your own server. The filtering is by destination, so a public
endpoint stays blocked however the traffic is shaped. That is also why the
transport is the second thing to try rather than the first: if WARP works,
nothing needs disguising.

One detail that breaks everything when missed: once the tunnel owns the
default route, the transport's own connection to the server would be routed
into the tunnel it is carrying. vpnctl resolves the server to a literal while
DNS still works and pins a host route for it before handing over the default
route.

## Testing without risking your connection

Two commands prove a tunnel works without touching this machine's routing.
Both run in containers with their own network namespace: no `--net=host`, no
`--privileged`.

```bash
vpnctl docker-smoke-test --provider warp-wireguard
```

```
✓ warp-wireguard works.
  egress without the tunnel  203.0.113.7
  egress through the tunnel  104.28.200.73
  Cloudflare reports WARP    on
  DNS inside the tunnel      resolves
```

It checks the things worth checking: that the egress address actually changed,
that Cloudflare agrees the traffic arrived over WARP, and that DNS resolves
inside the tunnel rather than leaking to the local network.

```bash
vpnctl transport test
```

```
  direct path blocked   yes
  tunnel through 443    yes
  carried real traffic  yes
```

This one builds both ends and blocks the direct path itself: the server drops
inbound UDP on the WireGuard port so only TCP 443 is open. It shows a direct
tunnel getting no handshake, then the same tunnel succeeding through the
relay. The first half is what makes the second half mean anything, so if the
direct path turns out to be reachable the test reports an error rather than a
pass.

## Split tunnelling

Addresses that should bypass the tunnel and use the plain connection:

```bash
vpnctl split-tunnel list
vpnctl split-tunnel add 192.168.0.0/16
vpnctl split-tunnel remove 192.168.0.0/16
vpnctl split-tunnel enable
```

These become host routes via the gateway that was default before the tunnel
connected. A longer prefix wins over the tunnel's `0.0.0.0/0`, which is what
makes them take effect.

## Tailscale exit node

An alternative to the WireGuard providers: run your own exit node and route
through it.

```bash
vpnctl bootstrap-tailscale-exit-node \
  --ssh-target ubuntu@YOUR_VPS_IP \
  --identity-file ./your-ssh-key.pem \
  --hostname my-exit \
  --auth-key tskey-auth-XXXXXXXX
```

Generate an auth key at https://login.tailscale.com/admin/settings/keys,
type Reusable. The command installs Tailscale, enables IPv4 and IPv6
forwarding persistently, and advertises the node as an exit node. Approve it
in the admin console, then on the Mac:

```bash
tailscale set --exit-node=my-exit
tailscale set --exit-node=        # release it
```

Worth knowing: Tailscale falls back to relaying over TCP 443 when UDP is
blocked, which is why it often works on networks where a plain WireGuard
tunnel does not.

## Configuration

`~/.config/vpnctl/config.toml`, written by `vpnctl setup` and editable by
hand.

```toml
[providers.warp-wireguard]
enabled = true

[providers.riseup]
enabled = false
provider = "riseup"     # or "calyx"
location = ""           # "" for any; see vpnctl doctor for the list
protocol = "tcp"        # tcp is the one that gets through more networks
port = 1194             # 53 and 80 are also offered

[providers.wireguard-custom]
enabled = false
endpoint = "vpn.example.com:51820"
public_key = "..."
key_file = "~/.config/vpnctl/wg-custom.key"
address = "10.8.0.2/32"
dns = "1.1.1.1"

[transport]
kind = "direct"         # or "wstunnel"
server = ""             # wss://your-host:443
local_port = 51820
sni = ""                # the TLS name to present

[split_tunnel]
enabled = false
excludes = ["192.168.0.0/16"]

[policy]
probe_interval_minutes = 10
benchmark_interval_minutes = 30
```

Credentials live beside it, all at 0600: `warp-device.json`,
`riseup-bundle.json`, `wg-custom.key`. None of them is in this repository and
none should be.

## Architecture

```
cli.py           commands, and the arrow-key menu they share
menu.py          single-select menu on termios and rich, no extra dependency
setup_wizard.py  first run: one question, then a working provider
selector.py      builds the enabled providers, benchmarks, ranks, saves
probe.py         one ping run per host for RTT, jitter and loss, then throughput
providers/       base.py defines the contract; one module per provider
transports.py    direct, or wstunnel for a network that blocks tunnels
netcheck.py      what this network allows, measured, changing nothing
warp.py          anonymous WARP device registration
riseup.py        LEAP provider API and its cached bundle
docker_smoke.py  bring one provider up in a container and check it
bypass.py        block the direct path in a container, then defeat the block
tui.py           live monitor
watch.py         periodic probe and re-benchmark
```

A provider implements `prepare`, `connect`, `disconnect`, `status`, `probe`
and `doctor`. The benchmark engine, the selector and the watch loop only ever
call those, so adding a provider does not touch them.

`connect` waits for a handshake before reporting success. The interface
existing is not the same as the tunnel working, and by that point the default
route has already moved onto it: reporting success without a handshake hands
back a machine with no internet.

## Development

```bash
pip install -e '.[dev]'
pytest                 # 151 tests, no network access
```

Tests never reach the network and never change routing. The Riseup fixture is
a real API response, trimmed, because the shape of its transport list is the
part most likely to change.

## Licence

MIT. See LICENSE.
