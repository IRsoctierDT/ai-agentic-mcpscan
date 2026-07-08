# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""OS-aware config-path resolution (ticket T-103).

This is the *only* place in the codebase that branches on operating system
(ARCHITECTURE.md §6). Paths are computed from an injected ``system`` string and
``env`` mapping so the resolver is fully unit-testable on any host.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath, PurePosixPath, PureWindowsPath


def _home(system: str, env: Mapping[str, str]) -> PurePath | None:
    """Resolve the user's home directory from the environment, per OS."""
    if system == "Windows":
        userprofile = env.get("USERPROFILE")
        if userprofile:
            return PureWindowsPath(userprofile)
        drive, path = env.get("HOMEDRIVE"), env.get("HOMEPATH")
        if drive and path:
            return PureWindowsPath(drive + path)
        return None
    home = env.get("HOME")
    return PurePosixPath(home) if home else None


def claude_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return candidate Claude-ecosystem config paths for the given OS.

    Args:
        system: ``platform.system()`` value — ``"Darwin"``, ``"Linux"``, or
            ``"Windows"``.
        env: Environment mapping (e.g. ``os.environ``) supplying ``HOME`` /
            ``USERPROFILE`` / ``APPDATA``.

    Returns:
        Candidate paths in priority order. The caller checks which exist; a path
        being returned does not imply it is present.
    """
    home = _home(system, env)
    candidates: list[PurePath] = []

    if home is not None:
        # User-level Claude Code settings (cross-platform layout).
        candidates.append(home / ".claude" / "settings.json")
        candidates.append(home / ".claude" / "settings.local.json")

    # Claude Desktop config — location differs per OS.
    if system == "Darwin" and home is not None:
        candidates.append(
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = env.get("APPDATA")
        if appdata:
            candidates.append(PureWindowsPath(appdata) / "Claude" / "claude_desktop_config.json")
    elif home is not None:  # Linux and other POSIX
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")

    return candidates


def cursor_config_candidates(
    system: str,
    env: Mapping[str, str],
) -> list[PurePath]:
    """Return the candidate user-level Cursor MCP config path for the given OS.

    Cursor uses a single global config at ``~/.cursor/mcp.json`` on every OS
    (``%USERPROFILE%\\.cursor\\mcp.json`` on Windows).
    """
    home = _home(system, env)
    if home is None:
        return []
    return [home / ".cursor" / "mcp.json"]
