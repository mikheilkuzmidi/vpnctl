"""What the menu offers, and what each entry means.

Kept apart from cli.py for two reasons. The detail copy is a few hundred
words, which does not belong in the middle of a command module. And a menu
that is plain data can be walked by a test: that every action resolves to a
real command, and that no entry invokes a command with a required argument it
does not supply. Both of those were previously only true by inspection.

Order is deliberate. Connect is first because it is what the tool is for.
The four things anyone does regularly stay on the top level, and the rest
goes behind three named groups rather than a flat list of twelve where the
important entry is as prominent as the seldom-used one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from vpnctl.menu import MenuEntry


@dataclass(frozen=True)
class MenuFacts:
    """A snapshot of live state, taken once when the menu opens.

    Deliberately a snapshot rather than a live read. Provider status shells
    out to `wg show` and, on macOS, `warp-cli status`; asking on every
    keypress would be several subprocesses per arrow key, which is how a menu
    comes to feel broken. It is refreshed after each action instead, which is
    free, because an action has just run.
    """

    status_line: str = "not connected"
    provider: str = ""
    transport: str = "direct"
    split_tunnel: str = "disabled"


def snapshot() -> MenuFacts:
    """Read the state the menu header and detail panes want to show."""
    from vpnctl.config import load_config
    from vpnctl.selector import build_providers
    from vpnctl.providers.base import ProviderStatus

    try:
        cfg = load_config()
        providers = build_providers(cfg)
    except Exception:
        # A menu that cannot draw itself because the config is unreadable is
        # worse than a menu with a vague header.
        return MenuFacts()

    connected = [
        p.provider_id
        for p in providers
        if not p.is_control and p.status() == ProviderStatus.CONNECTED
    ]
    tunnels = [p.provider_id for p in providers if not p.is_control]

    excludes = cfg.split_tunnel.excludes if cfg.split_tunnel.enabled else []
    return MenuFacts(
        status_line=(
            f"{connected[0]}, connected" if connected else "not connected"
        ),
        provider=connected[0] if connected else (tunnels[0] if tunnels else ""),
        transport=cfg.transport.kind,
        split_tunnel=(
            f"enabled, {len(excludes)} excluded" if excludes else "disabled"
        ),
    )


def build(facts: Optional[MenuFacts] = None) -> list[MenuEntry]:
    """The menu tree, with the live facts folded into the detail text."""
    facts = facts or MenuFacts()
    provider = facts.provider or "no provider configured yet"

    return [
        MenuEntry(
            "Connect",
            "connect",
            "route this machine through the VPN",
            "Routes every connection on this machine through the VPN, not "
            "just a browser.\n\n"
            f"Provider: {provider}.\n\n"
            "Asks for your password. Moving the default route needs root, "
            "and nothing else in the tool does.",
        ),
        MenuEntry(
            "Disconnect",
            "disconnect",
            "tear down the active tunnel",
            "Removes the tunnel and puts the original route back, so traffic "
            "returns to the plain connection.\n\n"
            "Safe to run when nothing is connected.",
        ),
        MenuEntry(
            "Status",
            "status",
            "what is up, and the last benchmark",
            "Which providers are up, and the ranked results of the last "
            "benchmark.\n\n"
            f"Transport: {facts.transport}. Split tunnel: {facts.split_tunnel}.",
        ),
        MenuEntry(
            "Live monitor",
            "tui",
            "RTT, jitter, loss and throughput as they change",
            "A live view of the connection: latency, jitter, packet loss and "
            "download speed, measured continuously.\n\n"
            "Ctrl-C returns here.",
        ),
        MenuEntry(
            "Providers",
            None,
            "set up, benchmark, check prerequisites",
            "Choosing who carries your traffic, and measuring how well they "
            "do it.\n\n"
            "Your own server is set up from the command line, because it "
            "needs an SSH target and a key file:\n\n"
            "  vpnctl bootstrap-wireguard-vps --ssh-target user@host "
            "--identity-file ./key.pem --with-wstunnel",
            children=[
                MenuEntry(
                    "Set up a provider",
                    "setup",
                    "choose between a free VPN and your own server",
                    "One question: use a free provider, or point vpnctl at a "
                    "server of your own.\n\n"
                    "The free options need no account and no payment.",
                ),
                MenuEntry(
                    "Benchmark all providers",
                    "benchmark",
                    "connect each in turn, measure it, and rank them",
                    "Connects each provider in turn, measures latency, "
                    "jitter, loss and throughput, and ranks them.\n\n"
                    "The unprotected connection is measured too, as the "
                    "control every tunnel is compared against. It is never "
                    "offered as something to connect to.\n\n"
                    "Takes a couple of minutes and asks for your password.",
                ),
                MenuEntry(
                    "Check prerequisites",
                    "doctor",
                    "what is missing, per provider, with the fix",
                    "Checks each provider's dependencies and says what is "
                    "missing and how to install it.\n\n"
                    "Also reports whether any split-tunnel range would leave "
                    "traffic unprotected.",
                ),
            ],
        ),
        MenuEntry(
            "Diagnostics",
            None,
            "what this network allows, and proof a tunnel works",
            "Working out whether a problem is your configuration or the "
            "network you are on.\n\n"
            "Nothing in here changes this machine's routing.",
            children=[
                MenuEntry(
                    "Diagnose this network",
                    "diagnose",
                    "what this network will and will not carry",
                    "Measures what this network allows: DNS, ordinary HTTPS, "
                    "arbitrary UDP, and whether known VPN endpoints are "
                    "reachable at all.\n\n"
                    "Plenty of networks block VPNs without saying so. This "
                    "tells them apart from a broken config, and says which "
                    "provider to try.",
                ),
                MenuEntry(
                    "Test a tunnel in a sandbox",
                    "docker-smoke-test",
                    "prove a tunnel works without touching this machine",
                    "Brings a tunnel up inside a container and checks the "
                    "egress address actually changes and that DNS resolves "
                    "inside it.\n\n"
                    "This machine keeps its own routing throughout, so it is "
                    "safe to run on a connection you are relying on.",
                ),
                MenuEntry(
                    "Test the bypass transport",
                    "transport test",
                    "block the tunnel's own port, then get through anyway",
                    "Builds both ends in containers, blocks the tunnel's own "
                    "UDP port so only TCP 443 is open, and checks that a "
                    "tunnel which fails directly succeeds through the "
                    "relay.\n\n"
                    "The blocked half is what makes the result mean "
                    "something.",
                ),
            ],
        ),
        MenuEntry(
            "Advanced",
            None,
            "split tunnel, transport, automatic switching",
            "Settings that change how traffic is routed once a tunnel is up, "
            "and how the tunnel reaches its server.",
            children=[
                MenuEntry(
                    "Split tunnel",
                    None,
                    "the ranges that bypass the tunnel",
                    "Addresses that should use the plain connection instead "
                    "of the tunnel.\n\n"
                    "Local ranges are excluded as a matter of course, or the "
                    "printer and the router become unreachable. Excluding a "
                    "public range means traffic to it is not protected.\n\n"
                    f"Currently {facts.split_tunnel}.",
                    children=[
                        MenuEntry(
                            "Show the exclusion list",
                            "split-tunnel list",
                            "what currently bypasses the tunnel",
                        ),
                        MenuEntry(
                            "Add a range",
                            "split-tunnel add",
                            "exclude a CIDR from the tunnel",
                            "Traffic to this range will use the plain "
                            "connection and will not be protected.",
                            prompt=("cidr", "CIDR to exclude"),
                        ),
                        MenuEntry(
                            "Remove a range",
                            "split-tunnel remove",
                            "send a CIDR back through the tunnel",
                            prompt=("cidr", "CIDR to stop excluding"),
                        ),
                        MenuEntry(
                            "Enable split tunnelling",
                            "split-tunnel enable",
                            "start honouring the exclusion list",
                        ),
                        MenuEntry(
                            "Disable split tunnelling",
                            "split-tunnel disable",
                            "send everything through the tunnel",
                        ),
                    ],
                ),
                MenuEntry(
                    "Transport",
                    None,
                    "how the tunnel reaches its server",
                    "Some networks carry ordinary HTTPS but drop anything "
                    "that looks like a VPN. A transport wraps the tunnel in "
                    "something they do carry.\n\n"
                    f"Currently: {facts.transport}.",
                    children=[
                        MenuEntry(
                            "Show the transport",
                            "transport show",
                            "what is configured now",
                        ),
                        MenuEntry(
                            "Send it straight out",
                            "transport set",
                            "the default: dial the server directly",
                            "Dials the server directly. Right almost "
                            "everywhere.",
                            kwargs={"kind": "direct"},
                        ),
                        MenuEntry(
                            "Carry it over TLS 443",
                            "transport set",
                            "wrap the tunnel in a WebSocket over TLS",
                            "Hands the tunnel's UDP to a relay that carries "
                            "it inside a WebSocket over TLS on port 443, "
                            "which looks like ordinary HTTPS.\n\n"
                            "Needs a relay on your own server. A public "
                            "endpoint stays blocked however the traffic is "
                            "shaped, because the filtering is by "
                            "destination.",
                            kwargs={"kind": "wstunnel"},
                            prompt=("server", "Relay URL, for example wss://host:443"),
                        ),
                    ],
                ),
                MenuEntry(
                    "Watch and recommend",
                    "watch",
                    "probe periodically and say when a switch is worth it",
                    "Probes the active tunnel on a timer, re-benchmarks "
                    "occasionally, and reports when another provider would "
                    "be materially better.\n\n"
                    "Recommends only: it will not switch anything by itself. "
                    "Ctrl-C returns here.",
                    kwargs={"do_apply": False},
                ),
            ],
        ),
        MenuEntry("Exit", "exit", "leave the menu"),
    ]


def walk(entries: list[MenuEntry]):
    """Every entry in the tree, depth first. Used by the tests."""
    for entry in entries:
        yield entry
        if entry.children:
            yield from walk(entry.children)
