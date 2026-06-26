"""Listening-socket enumeration + exposure classification (T-201, T-202).

Enumeration uses psutil (the only portable way to observe a process's bind
address, which is what the ``0.0.0.0`` exposure check requires — ADR-12). The
pure classification helpers contain no I/O and are fully unit-tested; the psutil
call degrades gracefully when the OS denies introspection (FR-D1).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from ..domain import Severity

_LOOPBACK_NAMES = {"localhost"}


@dataclass(frozen=True)
class ListeningSocket:
    """A socket observed in the LISTEN state."""

    ip: str
    port: int
    pid: int | None
    proc_name: str | None


@dataclass(frozen=True)
class EnumerationResult:
    """Enumerated sockets plus whether introspection was complete."""

    sockets: tuple[ListeningSocket, ...]
    inspection_incomplete: bool = False


def is_loopback(host: str) -> bool:
    """True if ``host`` is a loopback address or name."""
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_wildcard(host: str) -> bool:
    # We are detecting a wildcard bind in scanned software, never binding here.
    return host in {"0.0.0.0", "::", ""}  # noqa: S104  # nosec B104


def classify_exposure(ip: str) -> Severity | None:
    """Classify a bind address's exposure.

    Returns ``None`` for loopback (no exposure), else the severity of binding to
    a non-loopback interface. A wildcard or routable bind is reachable beyond the
    host and is treated as ``CRITICAL``.
    """
    if is_loopback(ip):
        return None
    if _is_wildcard(ip):
        return Severity.CRITICAL
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return Severity.HIGH  # unparseable bind addr — flag conservatively
    if addr.is_loopback:
        return None
    return Severity.CRITICAL


def enumerate_listening() -> EnumerationResult:
    """Enumerate listening sockets via psutil, degrading on permission limits.

    Never raises: if psutil is unavailable or access is denied, returns whatever
    was gathered with ``inspection_incomplete=True`` (FR-D1).
    """
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a declared dependency
        return EnumerationResult(sockets=(), inspection_incomplete=True)

    incomplete = False
    found: list[ListeningSocket] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        return EnumerationResult(sockets=(), inspection_incomplete=True)

    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        # psutil types laddr as `addr | tuple[()]`; the guard above proves it is
        # a populated addr here.
        laddr: Any = conn.laddr
        proc_name: str | None = None
        if conn.pid is not None:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.Error, OSError):
                incomplete = True
        found.append(
            ListeningSocket(
                ip=laddr.ip,
                port=laddr.port,
                pid=conn.pid,
                proc_name=proc_name,
            )
        )

    return EnumerationResult(sockets=tuple(found), inspection_incomplete=incomplete)
