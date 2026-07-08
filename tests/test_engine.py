"""Engine + Claude adapter integration tests (T-204/205, golden/clean — T-212)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket
from mcpscan.domain import Dimension, ServerState
from mcpscan.engine import scan

VULN_CONFIG = {
    "mcpServers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "some-mcp-server"],
            "env": {"OPENAI_API_KEY": "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123"},
        }
    },
    "permissions": {"allow": ["Bash(*)"]},
}

CLEAN_CONFIG = {
    "mcpServers": {
        "safe": {
            "command": "npx",
            "args": ["-y", "some-mcp-server@1.2.3"],
            "env": {"LOG_LEVEL": "info"},
        }
    },
    "permissions": {"allow": ["Read", "Glob(src/**)"]},
}


def test_adapter_parses_servers_and_permissions() -> None:
    cfg = ClaudeAdapter().parse("/cfg.json", json.dumps(VULN_CONFIG))
    assert cfg.servers[0].name == "leaky"
    assert cfg.allow_permissions == ("Bash(*)",)


def test_adapter_never_raises_on_bad_json() -> None:
    cfg = ClaudeAdapter().parse("/cfg.json", "{not json")
    assert cfg.parse_error is not None
    assert cfg.servers == ()


def _scan_root(tmp_path: Path, config: dict[str, object]) -> object:
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    return scan(
        roots=[tmp_path],
        system="Linux",
        env={},  # no HOME -> no user configs, deterministic
        enumerate_sockets=False,  # no psutil/network in tests
    )


def test_vulnerable_config_grades_f_with_expected_findings(tmp_path: Path) -> None:
    report = _scan_root(tmp_path, VULN_CONFIG)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids  # plaintext OpenAI key
    assert "SCOPE-DANGEROUS-ALLOW" in ids  # Bash(*) auto-allowed
    assert "PIN-UNPINNED" in ids  # npx -y with no version
    assert report.overall_grade == "F"  # a Critical secret => F


def test_clean_config_grades_a_with_zero_findings(tmp_path: Path) -> None:
    # T-212 golden clean fixture: a well-configured setup must be silent.
    report = _scan_root(tmp_path, CLEAN_CONFIG)
    all_findings = [f for s in report.servers for f in s.findings]
    assert all_findings == []
    assert report.overall_grade == "A"


def test_scan_is_deterministic(tmp_path: Path) -> None:
    a = _scan_root(tmp_path, VULN_CONFIG)
    b = _scan_root(tmp_path, VULN_CONFIG)
    assert a == b


# --- orchestration wiring the pure-check tests bypass ---
def test_running_socket_exposure_lands_in_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An exposed listening socket becomes a RUNNING server with an exposure finding.
    monkeypatch.setattr(
        engine_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket("0.0.0.0", 8000, 100, "node"),),  # noqa: S104
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    running = [s for s in report.servers if s.running]
    assert len(running) == 1
    assert running[0].bind_addr == "0.0.0.0"  # noqa: S104
    assert running[0].state is ServerState.RUNNING
    assert any(f.dimension is Dimension.EXPOSURE for f in running[0].findings)


def test_loopback_socket_is_not_surfaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A loopback bind has no exposure, so it must not appear as a server.
    monkeypatch.setattr(
        engine_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(ListeningSocket("127.0.0.1", 8000, 100, "node"),),
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    assert [s for s in report.servers if s.running] == []


def test_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Drive the OS-default config discovery loop via system/env overrides.
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(json.dumps(VULN_CONFIG), encoding="utf-8")
    report = scan(roots=[], system="Darwin", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


def test_env_file_in_project_root_is_audited(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    env_servers = [s for s in report.servers if s.id.endswith(".env")]
    assert len(env_servers) == 1
    assert any(f.id == "CRED-PLAINTEXT" for f in env_servers[0].findings)


def test_unreadable_config_is_skipped(tmp_path: Path) -> None:
    # A path that exists but can't be safely read (here: a directory named
    # like a config) is skipped gracefully rather than crashing the scan.
    (tmp_path / ".mcp.json").mkdir()
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert report.servers == ()
    assert report.overall_grade == "A"


# --- Cursor host adapter (second adapter, ADR-4) ---
CURSOR_VULN = {
    "mcpServers": {
        "leaky": {
            "command": "npx",
            "args": ["-y", "db-mcp-server"],
            "env": {"POSTGRES_PASSWORD": "S3cr3t-Pa55w0rd-abcdef123456"},
        }
    }
}


def test_cursor_project_config_is_discovered(tmp_path: Path) -> None:
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    leaky = [s for s in report.servers if s.id.endswith("#leaky")]
    assert len(leaky) == 1
    assert "mcp.json" in leaky[0].id and ".cursor" in leaky[0].id
    ids = {f.id for f in leaky[0].findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_cursor_and_claude_project_configs_coexist(tmp_path: Path) -> None:
    # Both adapters run over the same project root, each on its own file.
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    names = {s.id.rsplit("#", 1)[-1] for s in report.servers}
    assert {"leaky", "safe"} <= names  # cursor's leaky + claude's safe


def test_cursor_user_level_config_is_discovered(tmp_path: Path) -> None:
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


def test_windsurf_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Windsurf's global config at ~/.codeium/windsurf/mcp_config.json.
    ws_dir = tmp_path / ".codeium" / "windsurf"
    ws_dir.mkdir(parents=True)
    (ws_dir / "mcp_config.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids


def test_cline_user_level_config_is_discovered(tmp_path: Path) -> None:
    # Cline's global config lives under the VS Code globalStorage tree.
    cline_dir = (
        tmp_path
        / ".config"
        / "Code"
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
    )
    cline_dir.mkdir(parents=True)
    (cline_dir / "cline_mcp_settings.json").write_text(json.dumps(CURSOR_VULN), encoding="utf-8")
    report = scan(roots=[], system="Linux", env={"HOME": str(tmp_path)}, enumerate_sockets=False)
    ids = {f.id for s in report.servers for f in s.findings}
    assert {"CRED-PLAINTEXT", "PIN-UNPINNED"} <= ids
