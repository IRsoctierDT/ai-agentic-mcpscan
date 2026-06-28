"""Enumeration logic tests via a psutil mock (T-201, FR-D1).

The ``psutil`` stand-in lives in ``conftest.py`` (``fake_psutil`` / ``make_conn``
fixtures) so it can be shared with the engine integration tests.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Callable

import pytest

from mcpscan.discovery import sockets


def test_enumerates_listening_socket(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil([make_conn("127.0.0.1", 8000)]))
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].ip == "127.0.0.1"
    assert result.sockets[0].proc_name == "proc100"
    assert result.inspection_incomplete is False


def test_skips_non_listen_and_empty_laddr(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    conns = [
        make_conn("127.0.0.1", 1, status="ESTABLISHED"),
        types.SimpleNamespace(status="LISTEN", laddr=(), pid=1),
    ]
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil(conns))
    assert sockets.enumerate_listening().sockets == ()


def test_access_denied_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
) -> None:
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil([], raise_access=True))
    result = sockets.enumerate_listening()
    assert result.sockets == ()
    assert result.inspection_incomplete is True


def test_proc_name_denied_marks_incomplete_but_keeps_socket(
    monkeypatch: pytest.MonkeyPatch,
    fake_psutil: Callable[..., types.ModuleType],
    make_conn: Callable[..., Any],
) -> None:
    # Per-process introspection can be denied even when enumeration succeeds:
    # the socket is still reported, with proc_name=None and incomplete=True (FR-D1).
    fake = fake_psutil([make_conn("127.0.0.1", 8000, pid=100)], raise_proc_access=True)
    monkeypatch.setitem(sys.modules, "psutil", fake)
    result = sockets.enumerate_listening()
    assert len(result.sockets) == 1
    assert result.sockets[0].proc_name is None
    assert result.inspection_incomplete is True
