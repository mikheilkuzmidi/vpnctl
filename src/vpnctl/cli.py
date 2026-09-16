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
from vpnctl import menu, menu_model, render
from vpnctl.config import config_path, configure_transport, load_config
from vpnctl.docker_smoke import (
    SANDBOXABLE,
    NoHandshake,
    NotConfigured,
    run_docker_smoke,
)
from vpnctl.providers.base import ProviderStatus
from vpnctl.selector import (
    build_providers,
    load_results,
    control_provider_ids,
    pick_winner,
    run_benchmark,
    save_results,
)
from vpnctl.bypass import BypassError, run_bypass_test
from vpnctl.netcheck import run_checks
from vpnctl.setup_wizard import needs_setup, run_setup
from vpnctl.split_tunnel import list_warp_excludes, public_excludes
from vpnctl.toml_utils import dumps as toml_dumps
from vpnctl.tui import run_tui
from vpnctl.watch import run_watch

console = Console()
# No base style: rich applies one underneath markup, so with style="bold red"
# every err_console.print("[yellow]...") came out red and a warning was
# indistinguishable from a failure. Callers say which they mean.
err_console = Console(stderr=True)


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
        # Hints are printed whether or not the check passed. Several of them
        # say something a passing provider still needs to hear, like which
        # gateway it would use or that its credential has not been fetched
        # yet, and suppressing those made a ready provider and an unused one
        # look identical.
        for hint in result.hints:
            console.print(f"    [cyan]hint:[/cyan]  {hint}")

    # A config-level check rather than a provider one: it is about what the
    # tunnel is asked to carry, not whether a provider can be reached.
    if cfg.split_tunnel.enabled:
        leaking = public_excludes(cfg.split_tunnel.excludes)
        if leaking:
            console.print(
                f"\n[yellow]Split tunnel sends {len(leaking)} public range(s) "
                "outside the tunnel:[/yellow]"
            )
            for cidr in leaking:
                console.print(f"    {cidr}")
            console.print(
                "[dim]  Traffic to those addresses is not protected. Private "
                "ranges are excluded as a matter of course, so they are not "
                "listed; these are public. Remove one with: "
                "vpnctl split-tunnel remove CIDR[/dim]"
            )

    if all_ok:
        console.print("\n[green]All checks passed.[/green]")
        console.print(
            "[dim]If a connection still fails, `vpnctl diagnose` measures "
            "what this network is blocking.[/dim]"
        )
    else:
        console.print("\n[yellow]Some checks failed - see hints above.[/yellow]")
        sys.exit(1)


@main.command()
def benchmark() -> None:
    """Benchmark all enabled providers and save ranked results."""
    cfg = load_config()
    providers = build_providers(cfg)

    if not providers:
        err_console.print("[red]No providers enabled.[/red]")
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

    winner = pick_winner(results, controls=control_provider_ids(providers))
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
        err_console.print("[red]No providers enabled.[/red]")
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
        controls = control_provider_ids(providers)
        winner = pick_winner(load_results(), controls=controls)
        tunnels = [p for p in providers if not p.is_control]

        if not tunnels:
            err_console.print(
                "[red]No VPN provider is enabled, so there is nothing to "
                "connect to.[/red] Run `vpnctl setup`."
            )
            sys.exit(1)

        target = None
        if winner is not None:
            target = next(
                (p for p in providers if p.provider_id == winner.provider_id),
                None,
            )

        if target is None:
            # Connect connects. It used to run a full benchmark when there
            # was nothing cached, which meant the first thing a new user
            # asked for took a couple of minutes and a password prompt per
            # provider before anything happened. Benchmarking is a separate
            # thing you choose to do; without a ranking, take the first
            # enabled provider and go.
            target = tunnels[0]
            if len(tunnels) > 1:
                console.print(
                    f"[dim]No benchmark yet, so using {target.provider_id}. "
                    "`vpnctl benchmark` ranks them.[/dim]"
                )

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

    tunnelled = False
    rows: list[tuple[str, str]] = []
    for adapter in providers:
        state = adapter.status()
        badge = _status_badge(state)
        if adapter.is_control:
            # The control always reports connected, because the unprotected
            # path is always there. Saying so plainly matters: read as a
            # provider row it looks like "you are on a VPN", which is the one
            # thing it is not.
            rows.append(
                (
                    adapter.provider_id,
                    f"{badge}  [dim]the plain connection, measured as a "
                    "control[/dim]",
                )
            )
            continue
        rows.append((adapter.provider_id, badge))
        if state == ProviderStatus.CONNECTED:
            tunnelled = True

    render.header(
        console,
        "vpnctl status",
        "protected" if tunnelled else "not protected",
    )
    render.rows(console, rows)

    if not tunnelled:
        render.verdict(
            console,
            "No tunnel is up, so this machine's traffic is not protected.",
            ok=False,
        )

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


@main.command("diagnose")
def diagnose() -> None:
    """Work out what this network will carry, without changing any routing."""
    console.print(
        "[bold]Measuring what this network allows…[/bold] "
        "[dim](nothing is connected or rerouted)[/dim]\n"
    )
    with console.status("[dim]probing…[/dim]", spinner="dots"):
        report = run_checks()

    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Check", style="bold")
    table.add_column("Result", width=6)
    table.add_column("Detail", style="dim")
    for check in report.checks:
        table.add_row(
            check.name,
            "[green]ok[/green]" if check.ok else "[red]no[/red]",
            check.detail,
        )
    console.print(table)

    console.print(f"\n[bold]{report.verdict()}[/bold]\n")
    console.print(report.recommendation())


@main.group(name="transport")
def transport_group() -> None:
    """Carry the tunnel through a network that blocks tunnels."""


@transport_group.command(name="show")
def transport_show() -> None:
    """Print the configured transport."""
    cfg = load_config()
    render.header(console, "vpnctl transport", cfg.transport.kind)
    rows = [("kind", cfg.transport.kind)]
    if cfg.transport.kind != "direct":
        rows.append(("server", cfg.transport.server or "[dim]not set[/dim]"))
        rows.append(("local port", str(cfg.transport.local_port)))
        if cfg.transport.sni:
            rows.append(("TLS name", cfg.transport.sni))
    render.rows(console, rows)


@transport_group.command(name="set")
@click.argument("kind", type=click.Choice(["direct", "wstunnel"]))
@click.option("--server", default="", help="wstunnel server URL, e.g. wss://host:443")
@click.option("--local-port", default=51820, show_default=True, type=int)
@click.option(
    "--sni",
    default="",
    help="TLS server name to present, so the connection looks like ordinary HTTPS.",
)
@click.option("--path-prefix", default="", help="HTTP upgrade path prefix.")
@click.option("--credentials", default="", help="USER[:PASS] for the HTTP upgrade.")
@click.option("--verify-certificate", is_flag=True, default=False)
def transport_set(
    kind: str,
    server: str,
    local_port: int,
    sni: str,
    path_prefix: str,
    credentials: str,
    verify_certificate: bool,
) -> None:
    """Choose how the tunnel reaches its server."""
    if kind == "wstunnel" and not server:
        err_console.print(
            "[yellow]wstunnel needs --server, the URL of the relay running on "
            "your server, for example wss://vpn.example.com:443[/yellow]"
        )
        sys.exit(2)
    path = configure_transport(
        kind=kind,
        server=server,
        local_port=local_port,
        sni=sni,
        path_prefix=path_prefix,
        credentials=credentials,
        verify_certificate=verify_certificate,
    )
    console.print(f"[green]✓[/green] transport = {kind}. Written to {path}.")
    if kind == "wstunnel":
        console.print(
            "[dim]  Run `vpnctl transport test` to prove the mechanism, then "
            "`vpnctl connect`.[/dim]"
        )


@transport_group.command(name="test")
@click.option("--rebuild", is_flag=True, default=False, help="Rebuild the test image.")
def transport_test(rebuild: bool) -> None:
    """Prove the obfuscated transport defeats a blocked port, in containers.

    Builds both ends, blocks the tunnel's own UDP port so only TCP 443 is
    open, and checks that a tunnel which fails directly succeeds through the
    transport. The first half is what makes the second half mean anything.
    """
    console.print(
        "[bold]Testing the transport against a blocked port…[/bold] "
        "[dim](two containers; this machine is not touched)[/dim]"
    )
    with console.status("[dim]building both ends…[/dim]", spinner="dots"):
        try:
            result = run_bypass_test(rebuild=rebuild)
        except BypassError as exc:
            err_console.print(f"[red]{exc}[/red]")
            sys.exit(1)

    def mark(ok: bool) -> str:
        return "[green]yes[/green]" if ok else "[red]no[/red]"

    render.rows(
        console,
        [
            ("direct path blocked", mark(result.direct_blocked)),
            ("tunnel through 443", mark(result.tunnelled)),
            ("carried real traffic", mark(result.carried_traffic)),
        ],
    )
    if result.ok:
        console.print(
            "\n[green]✓[/green] The transport works: a tunnel that cannot "
            "reach its own port still came up over TCP 443."
        )
    else:
        err_console.print("\n[red]The transport did not get through.[/red]")
        err_console.print(f"[dim]{result.output[-1200:]}[/dim]")
        sys.exit(1)


@main.command("setup")
def setup() -> None:
    """Get this machine ready to connect: one question, then done."""
    sys.exit(run_setup(console))


@main.command("docker-smoke-test")
@click.option(
    "--provider",
    type=click.Choice(SANDBOXABLE),
    default="warp-wireguard",
    show_default=True,
    help="Which tunnel to bring up inside the container.",
)
@click.option(
    "--rebuild",
    is_flag=True,
    default=False,
    help="Rebuild the Docker smoke-test image before running it.",
)
def docker_smoke_test(provider: str, rebuild: bool) -> None:
    """Prove a tunnel works inside Docker, without touching this machine."""
    cfg = load_config()
    console.print(
        f"[bold]Testing {provider} inside Docker…[/bold] "
        "[dim](this machine keeps its own default route throughout)[/dim]"
    )
    # The first run builds an Ubuntu image, which is the slow part and looks
    # like a hang without saying so.
    with console.status("[dim]preparing the container…[/dim]", spinner="dots"):
        try:
            result = run_docker_smoke(cfg, provider_id=provider, rebuild=rebuild)
        except NotConfigured as exc:
            err_console.print(f"[yellow]{exc}[/yellow]")
            sys.exit(2)
        except NoHandshake as exc:
            err_console.print(f"[red]No handshake.[/red] {exc}")
            sys.exit(1)
        except RuntimeError as exc:
            err_console.print(f"[red]{exc}[/red]")
            sys.exit(1)

    rows = [
        ("egress without the tunnel", f"[dim]{result.baseline_ip}[/dim]"),
        ("egress through the tunnel", f"[bold]{result.public_ip}[/bold]"),
    ]
    if result.warp:
        rows.append(("Cloudflare reports WARP", f"[bold]{result.warp}[/bold]"))
    rows.append(
        (
            "DNS inside the tunnel",
            "[green]resolves[/green]"
            if result.dns_ok
            else "[red]does not resolve[/red]",
        )
    )
    render.rows(console, rows)
    render.verdict(console, f"{provider} works.")


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
@click.option(
    "--with-wstunnel",
    is_flag=True,
    default=False,
    help=(
        "Also install the relay that carries the tunnel over TCP 443, and "
        "point this machine's transport at it. Needed on networks that drop "
        "WireGuard but carry HTTPS."
    ),
)
def bootstrap_wireguard_vps_cmd(
    ssh_target: str,
    identity_file: str,
    endpoint_host: Optional[str],
    port: int,
    key_file: str,
    with_wstunnel: bool,
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
            with_wstunnel=with_wstunnel,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "no stderr"
        stdout = exc.stdout.strip() if exc.stdout else "no stdout"
        err_console.print("Bootstrap failed.")
        err_console.print(f"stdout: {stdout}")
        err_console.print(f"stderr: {stderr}")
        sys.exit(exc.returncode or 1)
    except RuntimeError as exc:
        err_console.print(f"[red]{exc}[/red]")
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
        err_console.print(f"[red]{exc}[/red]")
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
            # The rank is a plain number, and the winner is the bold row. An
            # emoji used to mark first place, but terminals disagree about how
            # many columns one occupies, and rich had already padded the cell
            # for two: wherever the terminal rendered it as one, every column
            # to its right in that row sat a cell left of the header.
            table.add_row(
                str(i),
                r.provider_id,
                f"{r.score:.2f}",
                f"{r.median_rtt_ms:.1f}",
                f"{r.jitter_ms:.1f}",
                f"{r.loss_pct:.1f}",
                f"{r.throughput_mbps:.2f}",
                "[green]ok[/green]",
                style="bold" if i == 1 else None,
            )

    console.print(table)


# --- interactive menu -------------------------------------------------------



def resolve_action(ctx: click.Context, path: str) -> Optional[click.Command]:
    """Find a command from a space-separated path like "split-tunnel list".

    This replaces two special cases. A nested subcommand cannot be looked up
    on `main` by name, so `split-tunnel list` and `transport test` each had a
    hand-written branch in the dispatch, and every further nested action
    would have needed another one. Walking the path handles all of them.
    """
    node: Optional[click.Command] = main
    for part in path.split():
        if not isinstance(node, click.Group):
            return None
        node = node.get_command(ctx, part)
        if node is None:
            return None
    return node


def _dispatch(ctx: click.Context, entry: menu.MenuEntry) -> None:
    """Run one menu entry's command, asking for any value it needs first."""
    command = resolve_action(ctx, entry.action or "")
    if command is None:
        err_console.print(f"[red]No such command: {entry.action}[/red]")
        return

    kwargs = dict(entry.kwargs)
    if entry.prompt is not None:
        param, question = entry.prompt
        # ctx.invoke fills in defaults but does not enforce required=True, so
        # a required argument left unasked arrives as None and fails deep
        # inside the command rather than here.
        kwargs[param] = click.prompt(f"  {question}", type=str).strip()

    ctx.invoke(command, **kwargs)


def run_menu(ctx: click.Context) -> int:
    """Drive the tool from an arrow-key menu.

    Every entry invokes the same command a user could have typed, so there is
    one implementation of each action rather than a menu copy that drifts.

    The navigation stack lives here because dispatch does. menu.select draws
    one level and reports whether the user chose something, went up, or quit.
    """
    try:
        # A fresh clone has no config, so the menu would open onto a tool with
        # nothing enabled but the control. Setup first, once.
        if needs_setup():
            code = run_setup(console)
            if code != 0:
                return code
            console.print("\n[dim]press any key for the menu[/dim]")
            with menu.raw_mode():
                menu.read_key()

        facts = menu_model.snapshot()
        # One entry per level we have descended into, so leaving a submenu
        # returns to where the cursor was rather than to the top.
        stack: list[list[menu.MenuEntry]] = [menu_model.build(facts)]
        crumbs: list[str] = []

        while True:
            level = stack[-1]
            title = " / ".join(["vpnctl", *crumbs])
            with menu.raw_mode():
                choice = menu.select(
                    console,
                    title,
                    level,
                    status=facts.status_line,
                    allow_back=len(stack) > 1,
                )

            if choice is None:
                console.clear()
                return 0
            if choice == menu.BACK:
                stack.pop()
                crumbs.pop()
                continue

            entry = level[choice]
            if entry.is_submenu:
                stack.append(entry.children)
                crumbs.append(entry.label)
                continue
            if entry.action == "exit":
                console.clear()
                return 0

            console.clear()
            try:
                _dispatch(ctx, entry)
            except SystemExit as exc:
                # A subcommand calling sys.exit must not take the menu with it.
                if exc.code not in (0, None):
                    err_console.print(
                        f"[yellow]{entry.action} exited with {exc.code}[/yellow]"
                    )
            except KeyboardInterrupt:
                console.print("\n[dim]interrupted[/dim]")
            except click.Abort:
                console.print("\n[dim]cancelled[/dim]")

            console.print("\n[dim]press any key to return to the menu[/dim]")
            with menu.raw_mode():
                menu.read_key()

            # Free to refresh here, since an action just ran and may well have
            # changed what the header says.
            facts = menu_model.snapshot()
            stack[0] = menu_model.build(facts)

    except menu.NotATerminal:
        err_console.print(
            "[red]vpnctl's menu needs a terminal.[/red] Run a subcommand "
            "directly, or see `vpnctl --help`."
        )
        return 2
