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

from vpnctl import menu, warp
from vpnctl.config import config_path, configure_wg_custom, set_provider_enabled

_REQUIRED_TOOLS = ("wg", "wg-quick")


def _missing_tools() -> list[str]:
    return [tool for tool in _REQUIRED_TOOLS if not shutil.which(tool)]


def _install_wireguard_tools(console: Console) -> bool:
    """Offer to install wireguard-tools, which needs no admin password."""
    if not shutil.which("brew"):
        console.print(
            "[yellow]wireguard-tools is missing and Homebrew is not installed."
            "[/yellow]\n  See https://www.wireguard.com/install/ for your system."
        )
        return False

    console.print("[dim]wireguard-tools is missing. Installing it with Homebrew.[/dim]")
    result = subprocess.run(
        ["brew", "install", "wireguard-tools"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        console.print(
            "[red]brew install wireguard-tools failed.[/red]\n"
            f"[dim]{result.stderr.strip()[:400]}[/dim]"
        )
        return False
    return not _missing_tools()


def _ask_self_hosted(console: Console) -> Optional[bool]:
    """True for their own server, False for the free providers, None to abort."""
    # select() reads single keypresses, which only works with the terminal in
    # cbreak mode. Without this the arrows were line buffered and echoed, so
    # the menu did not respond to them at all.
    with menu.raw_mode():
        choice = menu.select(
            console,
            "vpnctl setup",
            [
                (
                    "Use a free VPN, set up for me",
                    "Registers an anonymous Cloudflare WARP device. "
                    "No account, no payment.",
                ),
                (
                    "I have my own WireGuard server",
                    "Point vpnctl at your own endpoint and keys.",
                ),
            ],
            subtitle="nothing is sent anywhere until you choose",
        )
    if choice is None:
        return None
    return choice == 1


def _configure_own_server(console: Console) -> bool:
    """Collect the four things a WireGuard client needs and write them out."""
    console.print(
        "\n[bold]Your WireGuard server[/bold]\n"
        "[dim]These come from the [Peer] section your server generated for "
        "this device.[/dim]"
    )
    endpoint = click.prompt("  Endpoint (host:port)", type=str).strip()
    if ":" not in endpoint:
        console.print("[red]An endpoint needs a port, for example vpn.example.com:51820.[/red]")
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
    console.print(f"[green]✓[/green] Saved. Key written to {key_file} (0600).")
    return True


def _configure_warp(console: Console) -> bool:
    """Register a free anonymous device and enable it."""
    console.print(
        "\n[bold]Registering a free Cloudflare WARP device[/bold]\n"
        "[dim]Cloudflare is told a freshly generated public key, a random id, "
        "and the word 'PC'. No name, no email, no payment. The private key "
        "stays on this machine.[/dim]"
    )
    try:
        with console.status("[dim]registering…[/dim]", spinner="dots"):
            device = warp.load_or_register()
    except warp.WarpError as exc:
        console.print(f"[red]{exc}[/red]")
        return False

    set_provider_enabled("warp-wireguard", True)
    console.print(
        f"[green]✓[/green] Registered. Tunnel address {device.address_v4}, "
        f"peer {device.endpoint()}."
    )
    console.print(f"[dim]  Cached at {warp.device_path()} (0600).[/dim]")
    return True


def needs_setup() -> bool:
    """Whether this machine has been through setup yet."""
    return not config_path().exists()


def run_setup(console: Console) -> int:
    """Walk a new user from a fresh clone to a provider that can connect."""
    console.print("[bold]vpnctl setup[/bold]\n")

    if _missing_tools() and not _install_wireguard_tools(console):
        return 2
    console.print("[green]✓[/green] wireguard-tools present.")

    try:
        self_hosted = _ask_self_hosted(console)
    except menu.NotATerminal:
        console.print(
            "Setup needs a terminal. Run `vpnctl setup` directly, or configure "
            "~/.config/vpnctl/config.toml by hand."
        )
        return 2

    if self_hosted is None:
        console.print("[dim]Nothing changed.[/dim]")
        return 0

    ok = _configure_own_server(console) if self_hosted else _configure_warp(console)
    if not ok:
        return 1

    console.print(
        "\n[bold]Ready.[/bold]\n"
        "  [cyan]vpnctl docker-smoke-test[/cyan]  prove the tunnel works, "
        "without touching this machine's routing\n"
        "  [cyan]vpnctl connect[/cyan]            route this machine through it "
        "[dim](asks for your password: moving the default route needs root)[/dim]\n"
        "  [cyan]vpnctl[/cyan]                    the menu"
    )
    return 0
