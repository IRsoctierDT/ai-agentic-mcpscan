"""Unit tests for OS-aware path resolution (T-103, NFR-X1)."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from mcpscan.adapters.paths import (
    claude_config_candidates,
    project_config_candidates,
)


def test_macos_paths() -> None:
    paths = [str(p) for p in claude_config_candidates("Darwin", {"HOME": "/Users/jane"})]
    assert "/Users/jane/.claude/settings.json" in paths
    assert any("Library/Application Support/Claude" in p for p in paths)


def test_linux_paths() -> None:
    paths = [str(p) for p in claude_config_candidates("Linux", {"HOME": "/home/jane"})]
    assert "/home/jane/.claude/settings.json" in paths
    assert any(".config/Claude" in p for p in paths)


def test_windows_paths() -> None:
    env = {"USERPROFILE": r"C:\Users\jane", "APPDATA": r"C:\Users\jane\AppData\Roaming"}
    cands = claude_config_candidates("Windows", env)
    assert any(isinstance(p, PureWindowsPath) for p in cands)
    assert any("Claude" in str(p) and "claude_desktop_config.json" in str(p) for p in cands)


def test_missing_home_yields_no_user_paths() -> None:
    # Fail closed: no HOME -> no user-level candidates, never a crash.
    assert claude_config_candidates("Linux", {}) == []


def test_project_candidates() -> None:
    root = Path("/proj")
    names = {p.name for p in project_config_candidates(root)}
    assert names == {".mcp.json", ".env"}


def test_windows_homedrive_homepath_fallback() -> None:
    # No USERPROFILE: fall back to legacy HOMEDRIVE + HOMEPATH.
    env = {"HOMEDRIVE": "C:", "HOMEPATH": r"\Users\jane"}
    paths = [str(p) for p in claude_config_candidates("Windows", env)]
    assert any(p.endswith(r"\Users\jane\.claude\settings.json") for p in paths)


def test_windows_no_home_vars_fails_closed() -> None:
    # Neither USERPROFILE nor HOMEDRIVE/HOMEPATH -> no user candidates, no crash.
    assert claude_config_candidates("Windows", {}) == []


def test_windows_without_appdata_skips_desktop_config() -> None:
    # USERPROFILE present but APPDATA absent: user-level paths only.
    cands = claude_config_candidates("Windows", {"USERPROFILE": r"C:\Users\jane"})
    assert cands  # the two ~/.claude candidates are still produced
    assert not any("claude_desktop_config.json" in str(p) for p in cands)
