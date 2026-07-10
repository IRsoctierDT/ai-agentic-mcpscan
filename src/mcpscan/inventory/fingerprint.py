# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Loopback-only endpoint fingerprinting for asset classification (Tier 1).

Same hard trust boundary as ``discovery.probe`` (ARCHITECTURE R2): targets
**loopback only**, sends a **bare GET** — no auth headers, no body, no
credentials — and raises rather than ever contacting a non-loopback address, so
it can never become an egress or LAN-scanning primitive.

The response is treated as hostile input (same stance as ``lan.sanitize``): at
most ``_MAX_BYTES`` are read, the body is reduced to printable characters, and
callers use it **only** to test for known product markers — raw remote bytes
never reach an :class:`~mcpscan.inventory.model.Asset` or a report.
"""

from __future__ import annotations

import http.client
import string

from ..discovery.probe import NonLoopbackProbeError
from ..discovery.sockets import is_loopback

_MAX_BYTES = 4096
_PRINTABLE = set(string.printable)


def _sanitize(raw: bytes) -> str:
    """Reduce an untrusted response body to lowercase printable text."""
    text = raw.decode("utf-8", errors="replace")
    return "".join(ch for ch in text if ch in _PRINTABLE).lower()


def fetch_snippet(
    host: str, port: int, path: str, *, timeout: float = 2.0
) -> tuple[int, str] | None:
    """GET one path on a loopback host; return ``(status, sanitized body snippet)``.

    The status code matters to classification: a ``404`` proves the path does
    not exist on that server, which is *negative* evidence (see the MCP rule in
    ``classify``). Returns ``None`` when the endpoint doesn't respond (or
    errors), so a probe failure can never distort classification — it just
    yields no evidence.

    Raises:
        NonLoopbackProbeError: if ``host`` is not loopback (fail closed).
    """
    if not is_loopback(host):
        raise NonLoopbackProbeError(f"refusing to fingerprint non-loopback host {host!r}")

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)  # bare GET: no headers, no body, no creds
        resp = conn.getresponse()
        body = resp.read(_MAX_BYTES)
        return resp.status, _sanitize(body)
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()
