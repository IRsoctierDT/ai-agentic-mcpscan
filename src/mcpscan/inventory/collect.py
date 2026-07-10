# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Inventory collection: discover → classify → assemble (Tier 1 orchestration).

Walks the exact same discovery surfaces as ``engine.scan`` — user-level and
project host configs via the adapter seam, listening sockets via psutil — but
classifies what it finds instead of auditing it. Read-only, offline, and the
only network touched is the loopback fingerprint probe (disable with
``probe=False``).
"""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..discovery.sockets import EnumerationResult, enumerate_listening
from ..engine import _adapters
from ..io_safe import SafeReadError, safe_read_text
from .classify import SnippetFetch, agent_host_asset, classify_declared, classify_socket
from .model import INVENTORY_SCHEMA_VERSION, Asset, Inventory


def _read(path: Path) -> str | None:
    try:
        return safe_read_text(path, root=path.parent)
    except SafeReadError:
        return None


def _default_fetch(host: str, port: int, path: str) -> tuple[int, str] | None:
    from .fingerprint import fetch_snippet

    return fetch_snippet(host, port, path)


def collect_inventory(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    enumerate_sockets: bool = True,
    probe: bool = True,
    snippet_fetch: SnippetFetch | None = None,
) -> Inventory:
    """Collect and classify the machine's AI/MCP assets into an Inventory.

    Args:
        roots: Project roots to scan for host configs (defaults to cwd).
        system: ``platform.system()`` override (for testing).
        env: Environment mapping override (for testing).
        enumerate_sockets: When False, skips psutil enumeration (used in tests).
        probe: When False, no loopback fingerprinting — classification falls
            back to process names and port hints only.
        snippet_fetch: Inject a fetcher (tests); defaults to the real
            loopback-only fingerprint probe when ``probe`` is True.
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    fetch: SnippetFetch | None = None
    if probe:
        fetch = snippet_fetch if snippet_fetch is not None else _default_fetch

    assets: list[Asset] = []

    # --- config surfaces: agent hosts + their declared MCP servers ---
    for adapter in _adapters():
        candidates = [Path(str(c)) for c in adapter.default_config_paths(system, env)]
        for root in roots:
            candidates.extend(adapter.project_config_paths(root))
        for path in candidates:
            if not path.exists() or not path.is_file():
                continue
            raw = _read(path)
            if raw is None:
                continue
            cfg = adapter.parse(str(path), raw)
            assets.append(agent_host_asset(cfg.path, adapter.name))
            for decl in cfg.servers:
                assets.append(classify_declared(decl, cfg.path, adapter.name))

    # --- socket surface: running services, classified ---
    incomplete = False
    if enumerate_sockets:
        result: EnumerationResult = enumerate_listening()
        incomplete = result.inspection_incomplete
        seen: set[tuple[int, int | None]] = set()
        for sock in result.sockets:
            key = (sock.port, sock.pid)
            if key in seen:  # dual-stack (v4+v6) binds of the same service
                continue
            seen.add(key)
            asset = classify_socket(sock, fetch)
            if asset is not None:
                assets.append(asset)

    return Inventory(
        schema_version=INVENTORY_SCHEMA_VERSION,
        assets=tuple(_sorted(assets)),
        inspection_incomplete=incomplete,
    )


def _sorted(assets: list[Asset]) -> list[Asset]:
    """Deterministic order: kind, then product, then location."""
    return sorted(assets, key=lambda a: (a.kind.value, a.product.lower(), a.location))
