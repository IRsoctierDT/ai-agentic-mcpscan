# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Report renderers: terminal, JSON, and self-contained HTML.

All renderers consume only the pure ``domain`` model. Secrets are already
fingerprinted before a Report exists (R1), so no renderer can leak a raw value.
``RenderOptions`` controls path privacy (FR-R7) and secret reveal (FR-R4).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain import Severity

_SEPARATORS = ("/", "\\")

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class RenderOptions:
    """Cross-renderer display options."""

    show_secrets: bool = False
    absolute_paths: bool = False
    home: str | None = None


def display_path(path: str, opts: RenderOptions) -> str:
    """Relativize a filesystem path under the home dir to ``~/…`` (FR-R7).

    Non-path locations (e.g. ``ip:port``) and paths outside home are returned
    unchanged. ``--absolute-paths`` disables relativization.
    """
    if opts.absolute_paths or not opts.home:
        return path
    # Separator-agnostic so it works regardless of the OS the report is rendered
    # on (Windows CI rendering POSIX-style paths, and vice versa).
    home = opts.home.rstrip("/\\")
    if path == home:
        return "~"
    if any(path.startswith(home + s) for s in _SEPARATORS):
        return "~" + path[len(home) :]
    return path
