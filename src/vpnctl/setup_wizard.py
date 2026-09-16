"""First-run setup.

The goal is that cloning the repo and running `vpnctl` is enough: no account
to create, no key to paste, no server to rent. So setup asks one question,
whether the user already has a WireGuard server of their own, and if not it
registers a free anonymous Cloudflare WARP device and enables it.

Setup is re-runnable. Nothing here is destructive: it writes provider entries
into ~/.config/vpnctl/config.toml and leaves everything else alone.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from vpnctl import menu, riseup, warp
from vpnctl.providers.riseup import find_openvpn
from vpnctl.config import config_path, configure_wg_custom, set_provider_enabled

_REQUIRED_TOOLS = ("wg", "wg-quick")


def _missing_tools() -> list[str]:
    return [tool for tool in _REQUIRED_TOOLS if not shutil.which(tool)]


def _install_wireguard_tools(console: Console) -> bool:
    """Offer to install wireguard-tools, which needs no admin password."""
    if not shutil.which("brew"):
        console.print(
            "[warn]wireguard-tools is missing and Homebrew is not installed."
            "[/warn]\n  See https://www.wireguard.com/install/ for your system."
        )
        return False

    console.print(
        "[muted]wireguard-tools is missing. Installing it with Homebrew.[/muted]"
    )
    result = subprocess.run(
        ["brew", "install", "wireguard-tools"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        console.print(
            "[bad]brew install wireguard-tools failed.[/bad]\n"
            f"[muted]{result.stderr.strip()[:400]}[/muted]"
        )
        return False
    return not _missing_tools()


def _ask_provider(console: Console) -> Optional[str]:
    """Which provider to set up: "warp", "riseup", "own", or None to abort."""
    # select() reads single keypresses, which only works with the terminal in
    # cbreak mode. Without this the arrows were line buffered and echoed, so
    # the menu did not respond to them at all.
    with menu.raw_mode():
        choice = menu.select(
            console,
            "vpnctl setup",
            [
                (
                    "Free VPN, set up for me",
                    "An anonymous Cloudflare WARP device. No account, no "
                    "payment, unlimited. Fastest to set up.",
                ),
                (
                    "Free VPN run by a nonprofit",
                    "Riseup, over OpenVPN. No account either, and not one "
                    "large company, but slower and sometimes busy.",
                ),
                (
                    "My own WireGuard server",
                    "Point vpnctl at your own endpoint and keys. The only "
                    "option where nobody else carries your traffic.",
                ),
            ],
            subtitle="nothing is sent anywhere until you choose",
        )
    if choice is None:
        return None
    return ("warp", "riseup", "own")[choice]


def _configure_own_server(console: Console) -> bool:
    """Collect the four things a WireGuard client needs and write them out."""
    console.print(
        "\n[bold]Your WireGuard server[/bold]\n"
        "[muted]These come from the [Peer] section your server generated for "
        "this device.[/muted]"
    )
    endpoint = click.prompt("  Endpoint (host:port)", type=str).strip()
    if ":" not in endpoint:
        console.print(
            "[bad]An endpoint needs a port, for example "
            "vpn.example.com:51820.[/bad]"
        )
        return False

    public_key = click.prompt("  Server public key", type=str).strip()
    address = click.prompt(
        "  This device's tunnel address", default="10.8.0.2/32", type=str
    ).strip()
    private_key = click.prompt(
        "  This device's private key", type=str, hide_input=True
    ).strip()

    key_file = config_path().parent / "wg-custom.key"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    # Created at 0600 rather than chmod-ed afterwards: a world readable
    # window, however brief, is still a window.
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(private_key + "\n")

    configure_wg_custom(
        endpoint=endpoint,
        public_key=public_key,
        key_file=str(key_file),
        address=address,
    )
    console.print(f"[ok]✓[/ok] Saved. Key written to {key_file} (0600).")
    return True


def _configure_warp(console: Console) -> bool:
    """Register a free anonymous device and enable it."""
    console.print(
        "\n[bold]Registering a free Cloudflare WARP device[/bold]\n"
        "[muted]Cloudflare is told a freshly generated public key, a random id, "
        "and the word 'PC'. No name, no email, no payment. The private key "
        "stays on this machine.[/muted]"
    )
    try:
        with console.status("[muted]registering…[/muted]", spinner="dots"):
            device = warp.load_or_register()
    except warp.WarpError as exc:
        console.print(f"[bad]{exc}[/bad]")
        return False

    set_provider_enabled("warp-wireguard", True)
    console.print(
        f"[ok]✓[/ok] Registered. Tunnel address {device.address_v4}, "
        f"peer {device.endpoint()}."
    )
    console.print(f"[muted]  Cached at {warp.device_path()} (0600).[/muted]")
    return True


def _configure_riseup(console: Console) -> bool:
    """Fetch Riseup's gateway list and an anonymous client certificate."""
    console.print(
        "\n[bold]Fetching Riseup's configuration[/bold]\n"
        "[muted]Riseup is a nonprofit. Its own API reports allow_anonymous and "
        "allow_free, so there is nothing to sign up for: vpnctl asks for a "
        "short-lived client certificate and caches it.[/muted]"
    )
    if find_openvpn() is None:
        console.print(
            "[warn]Riseup speaks OpenVPN, which is not installed.[/warn]\n"
            "  brew install openvpn"
        )
        return False

    try:
        with console.status("[muted]fetching gateways…[/muted]", spinner="dots"):
            bundle = riseup.load_or_fetch("riseup")
    except riseup.RiseupError as exc:
        console.print(f"[bad]{exc}[/bad]")
        return False

    set_provider_enabled("riseup", True)
    console.print(
        f"[ok]✓[/ok] {len(bundle.gateways)} gateways cached "
        f"({', '.join(bundle.locations())})."
    )
    console.print(f"[muted]  Cached at {riseup.bundle_path('riseup')} (0600).[/muted]")
    return True


def needs_setup() -> bool:
    """Whether this machine has been through setup yet."""
    return not config_path().exists()


def run_setup(console: Console) -> int:
    """Walk a new user from a fresh clone to a provider that can connect."""
    console.print("[bold]vpnctl setup[/bold]\n")

    if _missing_tools() and not _install_wireguard_tools(console):
        return 2
    console.print("[ok]✓[/ok] wireguard-tools present.")

    try:
        choice = _ask_provider(console)
    except menu.NotATerminal:
        console.print(
            "Setup needs a terminal. Run `vpnctl setup` directly, or configure "
            "~/.config/vpnctl/config.toml by hand."
        )
        return 2

    if choice is None:
        console.print("[muted]Nothing changed.[/muted]")
        return 0

    configure = {
        "warp": _configure_warp,
        "riseup": _configure_riseup,
        "own": _configure_own_server,
    }[choice]
    if not configure(console):
        return 1

    console.print(
        "\n[bold]Ready.[/bold]\n"
        "  [accent]vpnctl docker-smoke-test[/accent]  prove the tunnel works, "
        "without touching this machine's routing\n"
        "  [accent]vpnctl connect[/accent]            route this machine through it "
        "[muted](asks for your password: moving the default route needs root)[/muted]\n"
        "  [accent]vpnctl diagnose[/accent]           if connecting fails, what this "
        "network is actually blocking\n"
        "  [accent]vpnctl[/accent]                    the menu"
    )
    return 0
