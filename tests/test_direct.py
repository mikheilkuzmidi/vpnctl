"""The baseline provider needs no privileges and cannot fail to connect."""

from __future__ import annotations

from vpnctl.config import Config
from vpnctl.providers.base import ProviderStatus
from vpnctl.providers.direct import DirectAdapter
from vpnctl.selector import build_providers


def test_identifier_is_stable() -> None:
    assert DirectAdapter().provider_id == "direct"


def test_lifecycle_is_a_no_op_and_needs_no_root() -> None:
    adapter = DirectAdapter()
    # None of these shell out, so none of them can prompt for a password.
    adapter.prepare()
    adapter.connect()
    adapter.disconnect()
    assert adapter.status() is ProviderStatus.CONNECTED


def test_doctor_always_passes() -> None:
    result = DirectAdapter().doctor()
    assert result.ok
    assert result.issues == []


def test_enabled_by_default_so_a_benchmark_always_has_a_control() -> None:
    providers = build_providers(Config())
    assert [p.provider_id for p in providers if p.provider_id == "direct"] == ["direct"]


def test_can_be_switched_off() -> None:
    cfg = Config()
    cfg.direct.enabled = False
    assert "direct" not in [p.provider_id for p in build_providers(cfg)]
