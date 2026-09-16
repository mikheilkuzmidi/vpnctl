"""The menu as data, checked by walking it.

The point of keeping the tree as plain data rather than code is that these
assertions are possible at all. Two of them cover things that were previously
true only by inspection, and one covers a failure mode click will not catch
for us.
"""

from __future__ import annotations

import click
import pytest

from vpnctl.cli import main, resolve_action
from vpnctl.menu_model import build, snapshot, walk


def _ctx() -> click.Context:
    return click.Context(main)


def test_connect_is_the_first_entry():
    """It is what the tool is for."""
    assert build()[0].label == "Connect"
    assert build()[0].action == "connect"


def test_every_action_resolves_to_a_real_command():
    """Replaces two hand-written special cases, and prevents a third.

    `split-tunnel list` and `transport test` are nested, so they cannot be
    looked up on main by name and each used to need its own branch in the
    dispatch. Walking the path handles any depth; this makes sure every path
    in the tree actually resolves.
    """
    ctx = _ctx()
    for entry in walk(build()):
        if entry.action and entry.action != "exit":
            assert resolve_action(ctx, entry.action) is not None, entry.action


def test_no_entry_invokes_a_command_missing_a_required_argument():
    """The failure click will not catch for us.

    ctx.invoke fills in defaults but does not enforce required=True, so a
    required argument that the menu does not supply arrives as None and fails
    deep inside the command instead of at the menu. Either the entry passes
    it in kwargs, or it asks for it.
    """
    ctx = _ctx()
    for entry in walk(build()):
        if not entry.action or entry.action == "exit":
            continue
        command = resolve_action(ctx, entry.action)
        supplied = set(entry.kwargs)
        if entry.prompt:
            supplied.add(entry.prompt[0])
        for param in command.params:
            needs_value = getattr(param, "required", False) and param.default is None
            if needs_value:
                assert param.name in supplied, (
                    f"{entry.label!r} invokes {entry.action!r} without "
                    f"{param.name!r}, which click will pass as None"
                )


def test_the_provisioning_commands_stay_off_the_menu():
    """They need an SSH target and a key file path.

    Typing a filesystem path into a full-screen menu is worse than typing it
    in a shell, and they are one-time server setup rather than everyday use.
    The Providers detail pane prints the command to copy instead.
    """
    actions = {e.action for e in walk(build())}
    assert "bootstrap-wireguard-vps" not in actions
    assert "bootstrap-tailscale-exit-node" not in actions

    providers = next(e for e in build() if e.label == "Providers")
    assert "bootstrap-wireguard-vps" in providers.detail


def test_watch_is_offered_without_apply():
    """It should recommend, not switch tunnels on its own from a menu."""
    watch = next(e for e in walk(build()) if e.action == "watch")
    assert watch.kwargs == {"do_apply": False}


def test_every_leaf_explains_itself_and_every_group_has_children():
    for entry in walk(build()):
        if entry.is_submenu:
            assert entry.children
            assert entry.hint, f"{entry.label} has no summary"
        elif entry.action != "exit":
            assert entry.explanation(), f"{entry.label} explains nothing"


def test_the_detail_text_carries_live_facts():
    """The detail pane is where "which provider, and will it ask for a
    password" gets answered, which is the question that prompted the
    redesign."""
    from vpnctl.menu_model import MenuFacts

    entries = build(MenuFacts(provider="warp-wireguard", transport="wstunnel"))
    connect = entries[0]
    assert "warp-wireguard" in connect.detail
    assert "password" in connect.detail
    status = next(e for e in entries if e.label == "Status")
    assert "wstunnel" in status.detail


def test_snapshot_survives_an_unreadable_config(monkeypatch):
    """A menu that will not draw because the config is broken is worse than a
    menu with a vague header."""
    monkeypatch.setattr(
        "vpnctl.config.load_config", lambda: (_ for _ in ()).throw(ValueError("bad"))
    )
    facts = snapshot()
    assert facts.status_line == "not connected"


def test_no_action_appears_twice_with_different_arguments_by_accident():
    """transport set appears twice on purpose, as two safe fixed choices."""
    ctx = _ctx()
    seen: dict[str, list[dict]] = {}
    for entry in walk(build()):
        if entry.action and entry.action != "exit":
            seen.setdefault(entry.action, []).append(entry.kwargs)
    duplicated = {a: k for a, k in seen.items() if len(k) > 1}
    assert set(duplicated) == {"transport set"}
    # And the two differ, or one of them is pointless.
    assert duplicated["transport set"][0] != duplicated["transport set"][1]
