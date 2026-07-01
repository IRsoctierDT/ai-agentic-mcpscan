# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Loopback-only MCP confirmation probe (ticket T-203).

Hard trust boundary (ARCHITECTURE R2 + review F3): this probe targets **loopback
only** and sends a **bare GET** — no auth headers, no body, no credentials. It
raises rather than ever contacting a non-loopback address, so it can never be
turned into an egress or LAN-scanning primitive.
"""

from __future__ import annotations

import http.client

from .sockets import is_loopback

MCP_PATHS = ("/mcp", "/sse")


class NonLoopbackProbeError(ValueError):
    """Raised if a probe target is not a loopback address (must never happen)."""


def probe_endpoint(host: str, port: int, path: str, *, timeout: float = 2.0) -> bool:
    """Probe one path on a loopback host. Returns True if it responds.

    Raises:
        NonLoopbackProbeError: if ``host`` is not loopback (fail closed).
    """
    if not is_loopback(host):
        raise NonLoopbackProbeError(f"refusing to probe non-loopback host {host!r}")

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)  # bare GET: no headers, no body, no creds
        resp = conn.getresponse()
        resp.read()
        return True
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def looks_like_mcp(host: str, port: int, *, timeout: float = 2.0) -> bool:
    """True if any known MCP endpoint responds on this loopback host:port."""
    return any(probe_endpoint(host, port, path, timeout=timeout) for path in MCP_PATHS)
