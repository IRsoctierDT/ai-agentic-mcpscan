"""Enumeration logic tests via a psutil mock (T-201, FR-D1)."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from mcpscan.discovery import sockets
from mcpscan.domain import Severity


class _Addr:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port

    def __bool__(self) -> bool:  # mimic populated namedtuple truthiness
        return True


def _fake_psutil(
    connections: list[Any],
    *,
    raise_access: bool = False,
    raise_proc_error: bool = False,
) -> types.ModuleType:
    mod = types.ModuleType("psutil")
    mod.CONN_LISTEN = "LISTEN"  # type: ignore[attr-defined]

    class AccessDenied(Exception):
        pass

    class Error(Exception):
        pass

    def net_connections(kind: str = "inet") -> list[Any]:
        if raise_access:
            raise AccessDenied()
        return connections

    class Process:
        def __init__(self, pid: int) -> None:
            self._pid = pid

        def name(self) -> str:
            if raise_proc_error:
                raise Error()
            return f"proc{self._pid}"

    mod.AccessDenied = AccessDenied  # type: ignore[attr-defined]
    mod.Error = Error  # type: ignore[attr-defined]
    mod.net_connections = net_connections  # type: ignore[attr-defined]
    mod.Process = Process  # type: ignore[attr-defined]
    return mod


def _conn(ip: str, port: int, status: str = "LISTEN", pid: int | None = 100) -> Any:
    return types.SimpleNamespace(status=status, laddr=_Addr(ip, port), pid=pid)


def test_enumerates_listening_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "psutil", _fake_psutil([_conn("127.0.0.1", 8000)]))
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].ip == "127.0.0.1"
    assert result.sockets[0].proc_name == "proc100"
    assert result.inspection_incomplete is False


def test_skips_non_listen_and_empty_laddr(monkeypatch: pytest.MonkeyPatch) -> None:
    conns = [
        _conn("127.0.0.1", 1, status="ESTABLISHED"),
        types.SimpleNamespace(status="LISTEN", laddr=(), pid=1),
    ]
    monkeypatch.setitem(sys.modules, "psutil", _fake_psutil(conns))
    assert sockets.enumerate_listening().sockets == ()


def test_access_denied_degrades_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "psutil", _fake_psutil([], raise_access=True))
    result = sockets.enumerate_listening()
    assert result.sockets == ()
    assert result.inspection_incomplete is True


def test_per_process_error_keeps_socket_but_flags_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FR-D1: if naming one process is denied, keep the socket, drop the name,
    # and flag the scan incomplete — never raise.
    fake = _fake_psutil([_conn("127.0.0.1", 8000)], raise_proc_error=True)
    monkeypatch.setitem(sys.modules, "psutil", fake)
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].proc_name is None
    assert result.inspection_incomplete is True


def test_classify_exposure_branches() -> None:
    # Loopback -> no exposure; wildcard/routable -> CRITICAL; unparseable -> HIGH.
    assert sockets.classify_exposure("127.0.0.1") is None
    assert sockets.classify_exposure("0.0.0.0") is Severity.CRITICAL  # noqa: S104
    assert sockets.classify_exposure("192.168.1.10") is Severity.CRITICAL
    assert sockets.classify_exposure("not-an-ip") is Severity.HIGH
