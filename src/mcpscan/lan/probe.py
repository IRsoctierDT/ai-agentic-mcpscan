# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Exact-target exposure probe for LAN assessment (LAN proposal §2, §3.5).

This is a *separate* probe from the loopback-only ``discovery.probe`` (which
refuses non-loopback hosts by design). It is reachable only through the
authorization gate in :mod:`.runner`. It does the least-intrusive thing that
answers "is an MCP server listening here?": a TCP connect for reachability, then
a single bare ``GET`` on the known MCP paths — no auth, no body, no payloads, no
port sweeping. Any response bytes are sanitized before they leave this module.

The prober is a plain callable so :mod:`.runner` can inject a fake in tests and
never touch the network.
"""

from __future__ import annotations

import http.client
import socket
from collections.abc import Callable
from dataclasses import dataclass

from .sanitize import sanitize_remote

MCP_PATHS = ("/mcp", "/sse")

# (host, port, timeout) -> ProbeResult
Prober = Callable[[str, int, float], "ProbeResult"]


@dataclass(frozen=True)
class ProbeResult:
    """The outcome of probing one host:port."""

    host: str
    port: int
    reachable: bool
    looks_like_mcp: bool
    evidence: str | None  # sanitized, e.g. "[untrusted remote data] HTTP 200", or None


def tcp_probe(host: str, port: int, timeout: float = 1.5) -> ProbeResult:
    """Probe one host:port: TCP reachability, then a bare GET on MCP paths."""
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError:
        return ProbeResult(host, port, reachable=False, looks_like_mcp=False, evidence=None)

    for path in MCP_PATHS:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path)  # bare GET: no headers, no body, no creds
            resp = conn.getresponse()
            evidence = sanitize_remote(f"HTTP {resp.status}", max_len=64)
            return ProbeResult(host, port, reachable=True, looks_like_mcp=True, evidence=evidence)
        except (OSError, http.client.HTTPException):
            continue
        finally:
            conn.close()

    return ProbeResult(host, port, reachable=True, looks_like_mcp=False, evidence=None)
