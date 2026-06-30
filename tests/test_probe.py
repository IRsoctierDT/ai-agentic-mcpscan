"""Probe trust-boundary tests (T-203): loopback-only, fail closed."""

from __future__ import annotations

import pytest

from mcpscan.discovery import probe
from mcpscan.discovery.probe import NonLoopbackProbeError, probe_endpoint
from mcpscan.discovery.sockets import is_loopback


class _FakeResponse:
    def read(self) -> bytes:
        return b"ok"


class _FakeConn:
    """A loopback HTTP connection that answers — no real socket opened."""

    def __init__(self, *_: object, **__: object) -> None:
        pass

    def request(self, method: str, path: str) -> None:
        pass

    def getresponse(self) -> _FakeResponse:
        return _FakeResponse()

    def close(self) -> None:
        pass


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


def test_probe_loopback_responding_endpoint_returns_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A responding loopback endpoint -> True (bare GET, no creds).
    monkeypatch.setattr(probe.http.client, "HTTPConnection", _FakeConn)
    assert probe_endpoint("127.0.0.1", 8000, "/mcp") is True


def test_looks_like_mcp_true_when_any_path_responds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe.http.client, "HTTPConnection", _FakeConn)
    assert probe.looks_like_mcp("127.0.0.1", 8000) is True
