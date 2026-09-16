"""vpnctl CLI - entry-point for all user-facing commands.

Commands:
  doctor      Pre-flight dependency check for all enabled providers.
  benchmark   Connect each provider, measure quality, rank, save results.
  connect     Connect the top-ranked (or a named) provider.
  status      Show current tunnel state and last benchmark results.
  watch       Periodic background loop: probe + benchmark + policy.
  disconnect  Tear down whatever tunnel is active.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.table import Table

from vpnctl.bootstrap import bootstrap_wireguard_vps
from vpnctl.tailscale_bootstrap import bootstrap_tailscale_exit_node
from vpnctl import menu
from vpnctl.config import config_path, load_config
from vpnctl.docker_smoke import run_docker_smoke
from vpnctl.providers.base import ProviderStatus
from vpnctl.selector import (
    build_providers,
    load_results,
    pick_winner,
    run_benchmark,
    save_results,
)
from vpnctl.split_tunnel import list_warp_excludes
from vpnctl.toml_utils import dumps as toml_dumps
from vpnctl.tui import run_tui
from vpnctl.watch import run_watch

console = Console()
err_console = Console(stderr=True, style="bold red")


def _status_badge(s: ProviderStatus) -> str:
    mapping = {
        ProviderStatus.CONNECTED: "[green]connected[/green]",
        ProviderStatus.DISCONNECTED: "[dim]disconnected[/dim]",
        ProviderStatus.CONNECTING: "[yellow]connecting…[/yellow]",
        ProviderStatus.ERROR: "[red]error[/red]",
        ProviderStatus.UNKNOWN: "[dim]unknown[/dim]",
    }
    return mapping.get(s, str(s))


@click.group(invoke_without_command=True)
@click.version_option(package_name="vpnctl")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Zero-cost VPN selector for macOS.

    Run with no arguments for the menu; every action is also a subcommand, so
    scripts and the menu drive exactly the same code.
    """
    if ctx.invoked_subcommand is None:
        ctx.exit(run_menu(ctx))


@main.command()
def doctor() -> None:
    """Check all dependencies and provider configurations."""
    cfg = load_config()
    providers = build_providers(cfg)

    if not providers:
        console.print("[yellow]No providers are enabled.[/yellow]")
        console.print(
            f"Edit [bold]{config_path()}[/bold] to enable providers."
        )
        sys.exit(1)

    all_ok = True
    for adapter in providers:
        result = adapter.doctor()
        if result.ok:
            console.print(f"[green]✓[/green] {result.provider_id}")
        else:
            all_ok = False
            console.print(f"[red]✗[/red] {result.provider_id}")
            for issue in result.issues:
                console.print(f"    [red]issue:[/red] {issue}")
            for hint in result.hints:
                console.print(f"    [cyan]hint:[/cyan]  {hint}")

    if all_ok:
        console.print("\n[green]All checks passed.[/green]")
    else:
        console.print("\n[yellow]Some checks failed - see hints above.[/yellow]")
        sys.exit(1)


@main.command()
def benchmark() -> None:
    """Benchmark all enabled providers and save ranked results."""
    cfg = load_config()
    providers = build_providers(cfg)

    if not providers:
        err_console.print("No providers enabled.")
        sys.exit(1)

    console.print(
        f"[bold]Benchmarking {len(providers)} provider(s)…[/bold]  "
        "[dim](this connects each one in sequence)[/dim]"
    )

    # A probe pings three hosts and then measures throughput, which takes tens
    # of seconds. This used to print one static "probing…" line and then say
    # nothing at all until the table appeared, so the command looked hung. The
    # spinner carries the current phase; lines that are findings rather than
    # progress are printed permanently above it.
    def _is_finding(msg: str) -> bool:
        return "rtt=" in msg or "failed" in msg

    with console.status("[dim]starting…[/dim]", spinner="dots") as spinner:

        def _log(msg: str) -> None:
            if _is_finding(msg):
                console.print(f"  {msg}")
            else:
                spinner.update(f"[dim]{msg}[/dim]")

        results = run_benchmark(providers, status_cb=_log)

    save_results(results)

    console.print()
    _print_results_table(results)

    winner = pick_winner(results)
    if winner:
        console.print(
            f"\n[bold green]Winner:[/bold green] {winner.provider_id}  "
            f"score={winner.score:.2f}"
        )


@main.command()
@click.argument("provider", required=False)
def connect(provider: Optional[str]) -> None:
    """Connect the top-ranked provider (or a named one).

    PROVIDER  Optional provider ID, e.g. warp-masque, warp-wireguard,
              wireguard-custom.  Defaults to the top-ranked result.
    """
    cfg = load_config()
    providers = build_providers(cfg)

    if not providers:
        err_console.print("No providers enabled.")
        sys.exit(1)

    if provider:
        target = next(
            (p for p in providers if p.provider_id == provider), None
        )
        if target is None:
            err_console.print(
                f"Unknown provider '{provider}'. "
                f"Enabled: {[p.provider_id for p in providers]}"
            )
            sys.exit(1)
    else:
        results = load_results()
        winner = pick_winner(results)
        if winner is None:
            console.print(
                "[yellow]No cached benchmark results.[/yellow] "
                "Running benchmark first…"
            )

            def _log(msg: str) -> None:
                console.print(f"  {msg}")

            results = run_benchmark(providers, status_cb=_log)
            save_results(results)
            winner = pick_winner(results)

        if winner is None:
            err_console.print("All providers failed - cannot connect.")
            sys.exit(1)

        target = next(
            (p for p in providers if p.provider_id == winner.provider_id),
            None,
        )
        if target is None:
            err_console.print(
                f"Winner '{winner.provider_id}' not found in provider list."
            )
            sys.exit(1)

    for adapter in providers:
        if adapter is target:
            continue
        try:
            if adapter.status() == ProviderStatus.CONNECTED:
                console.print(
                    f"Disconnecting [bold]{adapter.provider_id}[/bold] first…"
                )
                adapter.disconnect()
        except Exception:
            pass

    console.print(f"Connecting [bold]{target.provider_id}[/bold]…")
    try:
        target.connect()
        console.print(f"[green]✓[/green] {target.provider_id} connected.")
    except RuntimeError as exc:
        err_console.print(f"Connect failed: {exc}")
        console.print("Rolling back - disconnecting…")
        try:
            target.disconnect()
        except Exception:
            pass
        sys.exit(1)


@main.command()
def status() -> None:
    """Show current tunnel state and last benchmark results."""
    cfg = load_config()
    providers = build_providers(cfg)

    console.print("[bold]Provider status[/bold]")
    for adapter in providers:
        s = adapter.status()
        console.print(f"  {adapter.provider_id}  {_status_badge(s)}")

    results = load_results()
    if results:
        console.print("\n[bold]Last benchmark[/bold]")
        _print_results_table(results)
    else:
        console.print(
            "\n[dim]No benchmark results yet. Run:[/dim] vpnctl benchmark"
        )


@main.command()
def tui() -> None:
    """Live TUI monitor: real-time RTT, jitter, loss, and download speed."""
    run_tui()


@main.command()
@click.option(
    "--apply",
    "do_apply",
    is_flag=True,
    default=False,
    help="Automatically switch to a better provider when policy is met.",
)
def watch(do_apply: bool) -> None:
    """Periodic watch loop: probe active tunnel + full benchmark + policy.

    Without --apply, recommendations are printed but no switch is made.
    With --apply, the switch is performed automatically.
    """
    cfg = load_config()

    def _log(msg: str) -> None:
        console.print(msg)

    try:
        run_watch(cfg, apply=do_apply, log_cb=_log)
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


@main.command()
def disconnect() -> None:
    """Disconnect all active tunnels."""
    cfg = load_config()
    providers = build_providers(cfg)

    any_disconnected = False
    for adapter in providers:
        s = adapter.status()
        if s == ProviderStatus.CONNECTED:
            console.print(f"Disconnecting [bold]{adapter.provider_id}[/bold]…")
            adapter.disconnect()
            console.print(f"[green]✓[/green] {adapter.provider_id} disconnected.")
            any_disconnected = True

    if not any_disconnected:
        console.print("[dim]No active tunnels.[/dim]")


@main.command("docker-smoke-test")
@click.option(
    "--rebuild",
    is_flag=True,
    default=False,
    help="Rebuild the Docker smoke-test image before running it.",
)
def docker_smoke_test(rebuild: bool) -> None:
    """Validate wireguard-custom inside Docker without touching host routing."""
    cfg = load_config()
    console.print(
        "[bold]Running Docker WireGuard smoke test…[/bold] "
        "[dim](host network stays untouched)[/dim]"
    )
    try:
        result = run_docker_smoke(cfg, rebuild=rebuild)
    except RuntimeError as exc:
        err_console.print(str(exc))
        sys.exit(1)

    console.print(f"[green]✓[/green] Docker tunnel public IP: {result.public_ip}")


@main.command("bootstrap-wireguard-vps")
@click.option(
    "--ssh-target",
    required=True,
    help="SSH target for the VPS, e.g. ubuntu@203.0.113.10",
)
@click.option(
    "--identity-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="SSH private key for the VPS, e.g. ./vps.pem",
)
@click.option(
    "--endpoint-host",
    default=None,
    help="Public host/IP the Mac should use for WireGuard. Defaults to the SSH host.",
)
@click.option(
    "--port",
    default=51820,
    show_default=True,
    type=int,
    help="WireGuard UDP port to configure on the VPS.",
)
@click.option(
    "--key-file",
    default="~/.config/vpnctl/wg-custom.key",
    show_default=True,
    help="Local path where the WireGuard client private key should live.",
)
def bootstrap_wireguard_vps_cmd(
    ssh_target: str,
    identity_file: str,
    endpoint_host: Optional[str],
    port: int,
    key_file: str,
) -> None:
    """Provision a VPS WireGuard server over SSH and update local config.

    This command does not connect the VPN. It only prepares the VPS,
    generates or reuses the local client key, and enables wireguard-custom
    in ~/.config/vpnctl/config.toml.
    """
    console.print(
        f"Bootstrapping [bold]{ssh_target}[/bold] for WireGuard on UDP {port}…"
    )
    try:
        result = bootstrap_wireguard_vps(
            ssh_target=ssh_target,
            identity_file=identity_file,
            endpoint_host=endpoint_host,
            port=port,
            key_file=key_file,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "no stderr"
        stdout = exc.stdout.strip() if exc.stdout else "no stdout"
        err_console.print("Bootstrap failed.")
        err_console.print(f"stdout: {stdout}")
        err_console.print(f"stderr: {stderr}")
        sys.exit(exc.returncode or 1)
    except RuntimeError as exc:
        err_console.print(str(exc))
        sys.exit(1)

    console.print("[green]✓[/green] VPS bootstrap complete.")
    console.print(f"Endpoint: [bold]{result.endpoint}[/bold]")
    console.print(f"Key file: [bold]{result.key_file}[/bold]")
    console.print(f"Config:   [bold]{result.config_file}[/bold]")
    console.print(
        "\nNext steps:\n"
        "  1. vpnctl doctor\n"
        "  2. vpnctl benchmark\n"
        "  3. vpnctl connect wireguard-custom"
    )


@main.command("bootstrap-tailscale-exit-node")
@click.option(
    "--ssh-target",
    required=True,
    help="SSH target for the VPS, e.g. ubuntu@203.0.113.10",
)
@click.option(
    "--identity-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="SSH private key, e.g. ./vps.pem",
)
@click.option(
    "--hostname",
    default="exit-node",
    show_default=True,
    help="Tailscale node hostname shown in the admin console.",
)
@click.option(
    "--auth-key",
    default="",
    help=(
        "Tailscale auth key for unattended setup. "
        "Generate at https://login.tailscale.com/admin/settings/keys"
    ),
)
def bootstrap_tailscale_exit_node_cmd(
    ssh_target: str,
    identity_file: str,
    hostname: str,
    auth_key: str,
) -> None:
    """Install Tailscale on a VPS and configure it as a pure exit node.

    For fully-automated setup provide --auth-key (generate a reusable auth
    key at https://login.tailscale.com/admin/settings/keys).

    Without --auth-key the command prints a browser URL you must visit to
    authenticate the node, after which you must approve it as an exit node
    at https://login.tailscale.com/admin/machines.
    """
    console.print(
        f"Bootstrapping [bold]{ssh_target}[/bold] as Tailscale exit node…"
    )
    try:
        result = bootstrap_tailscale_exit_node(
            ssh_target=ssh_target,
            identity_file=identity_file,
            hostname=hostname,
            auth_key=auth_key,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "no stderr"
        stdout = exc.stdout.strip() if exc.stdout else "no stdout"
        err_console.print("Bootstrap failed.")
        err_console.print(f"stdout: {stdout}")
        err_console.print(f"stderr: {stderr}")
        sys.exit(exc.returncode or 1)
    except RuntimeError as exc:
        err_console.print(str(exc))
        sys.exit(1)

    console.print("[green]✓[/green] Tailscale installed and configured on VPS.")

    if result.auth_url:
        console.print(
            f"\n[bold yellow]Action required:[/bold yellow] "
            f"Authenticate this node by visiting:\n\n  {result.auth_url}\n"
        )
        console.print(
            "After authenticating, approve the exit node at:\n"
            "  https://login.tailscale.com/admin/machines\n"
            f"  → find [bold]{hostname}[/bold]\n"
            "  → Edit route settings → Enable [bold]Use as exit node[/bold]"
        )
    else:
        console.print(f"Tailscale IP: [bold]{result.tailscale_ip}[/bold]")
        console.print(
            f"\n[bold yellow]Action required:[/bold yellow] "
            "Approve the exit node at:\n"
            "  https://login.tailscale.com/admin/machines\n"
            f"  → find [bold]{hostname}[/bold]\n"
            "  → Edit route settings → Enable [bold]Use as exit node[/bold]"
        )

    ts_ip = result.tailscale_ip or "<tailscale-ip>"
    console.print(
        f"\nTo use this exit node from your Mac:\n"
        f"  tailscale set --exit-node={ts_ip}\n"
        "To verify:\n"
        "  curl https://ifconfig.me          # should show VPS public IP\n"
        f"  tailscale ping {ts_ip}  # should say via <IP>:41641 (direct)"
    )


# ---------------------------------------------------------------------------
# split-tunnel command group
# ---------------------------------------------------------------------------

@main.group(name="split-tunnel")
def split_tunnel_group() -> None:
    """Manage split-tunnel exclusions (CIDRs that bypass the VPN)."""


def _load_raw_config() -> dict:
    cp = config_path()
    if not cp.exists():
        return {}
    return tomllib.loads(cp.read_text())


def _save_raw_config(raw: dict) -> None:
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_bytes(toml_dumps(raw).encode())


@split_tunnel_group.command(name="list")
def split_tunnel_list() -> None:
    """Show the current split-tunnel exclusion list."""
    raw = _load_raw_config()
    enabled = raw.get("split_tunnel", {}).get("enabled", False)
    excludes: list[str] = raw.get("split_tunnel", {}).get("excludes", [])

    badge = "[green]enabled[/green]" if enabled else "[dim]disabled[/dim]"
    console.print(f"Split tunnel: {badge}")

    if excludes:
        console.print("\n[bold]Configured excludes[/bold] (bypass VPN):")
        for cidr in excludes:
            console.print(f"  {cidr}")
    else:
        console.print("[dim]No excludes configured.[/dim]")

    warp_live = list_warp_excludes()
    if warp_live:
        console.print("\n[bold]WARP live excludes[/bold] (warp-cli split-tunnel list):")
        for entry in warp_live:
            console.print(f"  {entry}")


@split_tunnel_group.command(name="add")
@click.argument("cidr")
def split_tunnel_add(cidr: str) -> None:
    """Add CIDR to the split-tunnel exclusion list in config.

    CIDR  IP address or CIDR block to route via normal internet, e.g. 10.0.0.0/8
    """
    raw = _load_raw_config()
    st = raw.setdefault("split_tunnel", {})
    excludes: list[str] = list(st.get("excludes", []))
    if cidr in excludes:
        console.print(f"[dim]{cidr} is already in the exclusion list.[/dim]")
        return
    excludes.append(cidr)
    st["excludes"] = excludes
    _save_raw_config(raw)
    console.print(f"[green]✓[/green] Added {cidr} to split-tunnel excludes.")
    console.print(
        "[dim]Re-run [bold]vpnctl connect[/bold] for the change to take effect.[/dim]"
    )


@split_tunnel_group.command(name="remove")
@click.argument("cidr")
def split_tunnel_remove(cidr: str) -> None:
    """Remove CIDR from the split-tunnel exclusion list in config.

    CIDR  IP address or CIDR block to remove.
    """
    raw = _load_raw_config()
    st = raw.setdefault("split_tunnel", {})
    excludes: list[str] = list(st.get("excludes", []))
    if cidr not in excludes:
        console.print(f"[dim]{cidr} is not in the exclusion list.[/dim]")
        return
    excludes.remove(cidr)
    st["excludes"] = excludes
    _save_raw_config(raw)
    console.print(f"[green]✓[/green] Removed {cidr} from split-tunnel excludes.")


@split_tunnel_group.command(name="enable")
def split_tunnel_enable() -> None:
    """Enable split tunnelling (set split_tunnel.enabled = true in config)."""
    raw = _load_raw_config()
    raw.setdefault("split_tunnel", {})["enabled"] = True
    _save_raw_config(raw)
    console.print("[green]✓[/green] Split tunnel enabled.")
    console.print(
        "[dim]Re-run [bold]vpnctl connect[/bold] for the change to take effect.[/dim]"
    )


@split_tunnel_group.command(name="disable")
def split_tunnel_disable() -> None:
    """Disable split tunnelling (set split_tunnel.enabled = false in config)."""
    raw = _load_raw_config()
    raw.setdefault("split_tunnel", {})["enabled"] = False
    _save_raw_config(raw)
    console.print("[green]✓[/green] Split tunnel disabled.")


def _print_results_table(results) -> None:
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Rank", style="dim", width=5)
    table.add_column("Provider", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("RTT ms", justify="right")
    table.add_column("Jitter ms", justify="right")
    table.add_column("Loss %", justify="right")
    table.add_column("DL Mbps", justify="right")
    table.add_column("Status")

    for i, r in enumerate(results, 1):
        if not r.ok:
            table.add_row(
                str(i),
                r.provider_id,
                "-",
                "-",
                "-",
                "-",
                "-",
                f"[red]{r.error}[/red]",
            )
        else:
            rank_marker = "🏆" if i == 1 else str(i)
            table.add_row(
                rank_marker,
                r.provider_id,
                f"{r.score:.2f}",
                f"{r.median_rtt_ms:.1f}",
                f"{r.jitter_ms:.1f}",
                f"{r.loss_pct:.1f}",
                f"{r.throughput_mbps:.2f}",
                "[green]ok[/green]",
            )

    console.print(table)


# --- interactive menu -------------------------------------------------------

_MENU: list[tuple[str, str, str]] = [
    ("Check dependencies", "doctor", "Every provider's prerequisites, with hints for what is missing"),
    ("Benchmark providers", "benchmark", "Connect each in turn, measure it, and rank them"),
    ("Connect the best provider", "connect", "Uses the last benchmark; runs one first if there is none"),
    ("Live monitor", "tui", "RTT, jitter, loss and throughput as they change"),
    ("Show status", "status", "Current tunnel and the last benchmark result"),
    ("Split tunnel", "split-tunnel-list", "The CIDRs that bypass the tunnel"),
    ("Disconnect", "disconnect", "Tear down any active tunnel"),
    ("Exit", "exit", ""),
]


def run_menu(ctx: click.Context) -> int:
    """Drive the tool from an arrow-key menu.

    Every entry invokes the same command a user could have typed, so there is
    one implementation of each action rather than a menu copy that drifts.
    """
    try:
        while True:
            with menu.raw_mode():
                choice = menu.select(
                    console,
                    "vpnctl",
                    [(label, hint) for label, _, hint in _MENU],
                    subtitle="zero-cost VPN selector",
                )
            if choice is None:
                return 0

            _, action, _ = _MENU[choice]
            if action == "exit":
                console.clear()
                return 0

            console.clear()
            try:
                # Nested subcommand, so it cannot be looked up on main by name.
                if action == "split-tunnel-list":
                    ctx.invoke(split_tunnel_list)
                else:
                    ctx.invoke(main.get_command(ctx, action))
            except SystemExit as exc:
                # A subcommand calling sys.exit must not take the menu with it.
                if exc.code not in (0, None):
                    err_console.print(f"[yellow]{action} exited with {exc.code}[/yellow]")
            except KeyboardInterrupt:
                console.print("\n[dim]interrupted[/dim]")

            console.print("\n[dim]press any key to return to the menu[/dim]")
            with menu.raw_mode():
                menu.read_key()

    except menu.NotATerminal:
        err_console.print(
            "vpnctl's menu needs a terminal. Run a subcommand directly, "
            "or see `vpnctl --help`."
        )
        return 2
