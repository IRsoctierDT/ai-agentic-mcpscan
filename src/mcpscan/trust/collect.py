# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Collect trust profiles across every discovered host config (Tier 4 wiring).

Walks the same config surfaces as ``engine.scan`` — user-level and project host
configs via the adapter seam — parses each, and trust-profiles its servers.
Read-only and offline; no network, no writes.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..engine import _adapters
from ..io_safe import SafeReadError, safe_read_text
from .analyze import analyze_config, build_trust_report
from .model import TrustProfile, TrustReport


def _read(path: Path) -> str | None:
    try:
        return safe_read_text(path, root=path.parent)
    except SafeReadError:
        return None


def collect_trust(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
) -> TrustReport:
    """Discover host configs and produce a trust report over their MCP servers."""
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    profiles: list[TrustProfile] = []
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
            profiles.extend(analyze_config(adapter.parse(str(path), raw), adapter.name))

    return build_trust_report(profiles)
