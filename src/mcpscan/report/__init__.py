"""Report renderers: terminal, JSON, and self-contained HTML.

All renderers consume only the pure ``domain`` model. Secrets are already
fingerprinted before a Report exists (R1), so no renderer can leak a raw value.
``RenderOptions`` controls path privacy (FR-R7) and secret reveal (FR-R4).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain import Severity

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

    The separator is inferred from ``opts.home`` itself rather than ``os.sep``
    so that POSIX-style paths are handled correctly even when the tool runs on
    Windows (e.g. in tests that pass explicit ``/home/user`` strings).
    """
    if opts.absolute_paths or not opts.home:
        return path
    # Infer separator from the home string, not os.sep, so POSIX-style paths
    # round-trip correctly on Windows.
    sep = "/" if "/" in opts.home else "\\"
    home = opts.home.rstrip(sep)
    if path == home:
        return "~"
    if path.startswith(home + sep):
        return "~" + path[len(home):]
    return path
