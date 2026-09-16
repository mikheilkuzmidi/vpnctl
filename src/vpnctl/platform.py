"""The only module that knows which operating system this is.

Until this existed, the macOS assumptions were not marked as assumptions:
they were spelled into command syntax scattered across the providers, so
running on Linux failed in five different places with three different kinds
of error, the first of them an uncaught FileNotFoundError from a `route`
binary Debian does not ship.

Three rules hold here:

- Nothing in this module raises because a command is missing. A caller
  deciding what to do about a missing tool is fine; a caller crashing because
  it shelled out to something that is not there is not.
- Every function answers a question about the host, not about a provider.
- macOS behaviour is the behaviour that already shipped. Where the two
  platforms differ, Darwin keeps exactly what it had.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# macOS prints "    gateway: 192.168.1.1" inside a block of fields.
_DARWIN_GATEWAY = re.compile(r"gateway:\s+(\S+)")
# Linux prints "default via 192.168.1.1 dev en0 ..." on one line.
_LINUX_GATEWAY = re.compile(r"\bdefault\s+via\s+(\S+)")


def run(args: list[str], *, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    """Run a command, turning a missing binary into a normal failed result.

    subprocess.run(check=False) protects against a non-zero exit but not
    against the executable being absent: that is a FileNotFoundError at exec
    time. Every caller in this package treats a failed command as a value, so
    a missing one should be a value too.
    """
    try:
        return subprocess.run(
            args, capture_output=True, text=True, check=False, timeout=timeout
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            args, 127, "", f"{args[0]}: command not found"
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, 124, "", f"{args[0]}: timed out"
        )


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def sudo_prefix(*, noninteractive: bool = False) -> list[str]:
    """What to put in front of a command that needs root.

    Empty when we are already root, which is the case inside a container and
    is also what makes the recorded demo possible: there is no password to
    type. Empty too when sudo is simply not installed, because prefixing a
    command with a binary that does not exist replaces a useful permission
    error with a confusing "command not found".

    noninteractive adds -n, and which calls get it is not cosmetic. Bringing
    a tunnel up may reasonably ask for a password. A status read may not:
    status() is polled twice a second by the live monitor and again by every
    connect, so an interactive sudo there would hang the interface on a
    prompt nobody is watching for. Reads pass noninteractive=True and accept
    failing instead.
    """
    if is_root():
        return []
    if shutil.which("sudo") is None:
        return []
    return ["sudo", "-n"] if noninteractive else ["sudo"]


def default_gateway() -> Optional[str]:
    """The current IPv4 default gateway, before any tunnel changes it.

    Returns None rather than raising, on either platform, for any reason.
    Callers use it to pin routes outside the tunnel and already treat None as
    "cannot do that part".
    """
    if IS_MACOS:
        result = run(["route", "-n", "get", "default"])
        pattern = _DARWIN_GATEWAY
    else:
        # `ip` is in iproute2, which is present on effectively every Linux
        # system including minimal containers. `route` is net-tools, which is
        # not, and has no `get` verb even when it is.
        result = run(["ip", "-4", "route", "show", "default"])
        pattern = _LINUX_GATEWAY

    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        found = pattern.search(line)
        if found:
            return found.group(1)
    return None


def add_host_routes(cidrs: list[str], gateway: str) -> None:
    """Route these destinations via gateway, bypassing any tunnel.

    A longer prefix beats the tunnel's 0.0.0.0/0, which is what makes both
    split tunnelling and the wstunnel transport work.
    """
    if not cidrs or not gateway:
        return
    for cidr in cidrs:
        if IS_MACOS:
            run([*sudo_prefix(), "route", "-q", "add", "-net", cidr, gateway])
        else:
            # `ip route` is idempotent-hostile: adding an existing route is an
            # error. Replace says what we mean and succeeds either way.
            run([*sudo_prefix(), "ip", "route", "replace", cidr, "via", gateway])


def remove_host_routes(cidrs: list[str]) -> None:
    """Delete routes added by add_host_routes. Safe if they are already gone."""
    if not cidrs:
        return
    for cidr in cidrs:
        if IS_MACOS:
            run([*sudo_prefix(), "route", "-q", "delete", "-net", cidr])
        else:
            run([*sudo_prefix(), "ip", "route", "del", cidr])


def dns_is_manageable() -> bool:
    """Whether wg-quick's `DNS =` line will actually work here.

    wg-quick implements DNS by piping into resolvconf. On macOS it uses
    networksetup and always works. On Linux resolvconf is usually a symlink to
    resolvectl, which needs systemd's D-Bus: in a container that is absent, so
    `wg-quick up` fails with "sd_bus_open_system: No such file or directory"
    and its EXIT trap tears the interface straight back down. The tunnel never
    comes up at all, which is a confusing way to learn about a resolver.

    When this returns False the caller omits the DNS line and sets the
    resolver itself. Deliberately conservative: anywhere resolvconf genuinely
    works we leave it alone rather than writing /etc/resolv.conf behind the
    system's back.
    """
    if IS_MACOS:
        return True

    resolvconf = shutil.which("resolvconf") or shutil.which("resolvectl")
    if resolvconf is None:
        return False

    # openresolv and systemd both claim the name `resolvconf`. Only the
    # systemd one needs a bus, so the question is which of them this is.
    if Path(resolvconf).resolve().name == "resolvectl":
        return Path("/run/dbus/system_bus_socket").exists() or Path(
            "/var/run/dbus/system_bus_socket"
        ).exists()
    return True


def set_resolver(nameserver: str) -> bool:
    """Point /etc/resolv.conf at one nameserver. Returns whether it worked.

    Only for the case dns_is_manageable() rejects. Docker bind-mounts
    /etc/resolv.conf, so the contents are writable while the inode cannot be
    replaced: writing in place is the one approach that works there, and
    happens to be the least invasive anywhere else.
    """
    try:
        Path("/etc/resolv.conf").write_text(f"nameserver {nameserver}\n")
        return True
    except OSError:
        return False
