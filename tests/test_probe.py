"""Probe trust-boundary tests (T-203): loopback-only, fail closed."""

from __future__ import annotations

import pytest

from mcpscan.discovery.probe import NonLoopbackProbeError, probe_endpoint
from mcpscan.discovery.sockets import is_loopback


def test_is_loopback() -> None:
    assert is_loopback("127.0.0.1")
    assert is_loopback("::1")
    assert is_loopback("localhost")
    assert not is_loopback("0.0.0.0")  # noqa: S104
    assert not is_loopback("192.168.1.10")
    assert not is_loopback("example.com")


def test_probe_refuses_non_loopback() -> None:
    # The probe must NEVER reach out beyond loopback — fail closed.
    with pytest.raises(NonLoopbackProbeError):
        probe_endpoint("192.168.1.10", 8000, "/mcp")
    with pytest.raises(NonLoopbackProbeError):
        probe_endpoint("0.0.0.0", 8000, "/mcp")  # noqa: S104


def test_probe_loopback_closed_port_returns_false() -> None:
    # Nothing listening on this loopback port -> False, no exception.
    assert probe_endpoint("127.0.0.1", 1, "/mcp", timeout=0.2) is False
