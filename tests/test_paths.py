"""Unit tests for OS-aware path resolution (T-103, NFR-X1)."""

from __future__ import annotations

from pathlib import PureWindowsPath

from mcpscan.adapters.paths import (
    claude_config_candidates,
    cursor_config_candidates,
    windsurf_config_candidates,
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


def test_windows_homedrive_homepath_fallback() -> None:
    # No USERPROFILE -> fall back to HOMEDRIVE + HOMEPATH for the user home.
    env = {"HOMEDRIVE": "C:", "HOMEPATH": r"\Users\jane"}
    paths = [str(p) for p in claude_config_candidates("Windows", env)]
    assert any(p.endswith(r"\Users\jane\.claude\settings.json") for p in paths)


def test_windows_missing_home_yields_no_user_paths() -> None:
    # Fail closed on Windows too: no USERPROFILE/HOMEDRIVE -> no user candidates.
    assert claude_config_candidates("Windows", {}) == []


def test_missing_home_yields_no_user_paths() -> None:
    # Fail closed: no HOME -> no user-level candidates, never a crash.
    assert claude_config_candidates("Linux", {}) == []


def test_cursor_paths_posix() -> None:
    # Cursor uses a single global config at ~/.cursor/mcp.json on macOS/Linux.
    for system, home in (("Darwin", "/Users/jane"), ("Linux", "/home/jane")):
        paths = [str(p) for p in cursor_config_candidates(system, {"HOME": home})]
        assert paths == [f"{home}/.cursor/mcp.json"]


def test_cursor_paths_windows() -> None:
    cands = cursor_config_candidates("Windows", {"USERPROFILE": r"C:\Users\jane"})
    assert any(isinstance(p, PureWindowsPath) for p in cands)
    assert any(str(p).endswith(r"\.cursor\mcp.json") for p in cands)


def test_cursor_missing_home_yields_no_paths() -> None:
    assert cursor_config_candidates("Linux", {}) == []


def test_windsurf_paths_posix() -> None:
    paths = [str(p) for p in windsurf_config_candidates("Darwin", {"HOME": "/Users/jane"})]
    assert paths == ["/Users/jane/.codeium/windsurf/mcp_config.json"]


def test_windsurf_missing_home_yields_no_paths() -> None:
    assert windsurf_config_candidates("Linux", {}) == []


def test_windows_without_appdata_skips_desktop_config() -> None:
    # USERPROFILE present but APPDATA absent: user-level paths only.
    cands = claude_config_candidates("Windows", {"USERPROFILE": r"C:\Users\jane"})
    assert cands  # the two ~/.claude candidates are still produced
    assert not any("claude_desktop_config.json" in str(p) for p in cands)
