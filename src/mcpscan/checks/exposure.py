# Copyright 2026 IRsoctierDT
# SPDX-License-Identifier: Apache-2.0
"""Exposure check: bind-address reachability (ticket T-202).

Pure transform from an observed socket bind address to a finding.
"""

from __future__ import annotations

from ..discovery.sockets import ListeningSocket, classify_exposure
from ..domain import Dimension, Finding, Location, Severity


def check_socket_exposure(sock: ListeningSocket) -> list[Finding]:
    """Return an exposure finding if the socket binds beyond loopback."""
    severity = classify_exposure(sock.ip)
    if severity is None:
        return []
    return [
        Finding(
            id="EXPOSE-BIND",
            dimension=Dimension.EXPOSURE,
            severity=severity,
            title=f"MCP server reachable beyond loopback ({sock.ip}:{sock.port})",
            location=Location(path=f"{sock.ip}:{sock.port}"),
            remediation=(
                "Bind the server to 127.0.0.1 (loopback) instead of "
                f"{sock.ip}. Only expose it on a network interface behind "
                "authentication if remote access is genuinely required."
            ),
            rationale=(
                "A non-loopback bind makes the server — and its tools — reachable "
                "from other hosts, often without authentication."
            ),
        )
    ]


__all__ = ["Severity", "check_socket_exposure"]
