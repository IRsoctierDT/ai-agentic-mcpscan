"""Engine + Claude adapter integration tests (T-204/205, golden/clean — T-212)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.adapters.claude import ClaudeAdapter
from mcpscan.discovery.sockets import EnumerationResult, ListeningSocket
from mcpscan.engine import scan
from mcpscan.enrichment.osv import OsvVuln

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

PINNED_CONFIG = {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]}}}

UNPINNED_CONFIG = {"mcpServers": {"svc": {"command": "npx", "args": ["-y", "some-mcp-server"]}}}


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


# --- discovery edges (no project .mcp.json on these paths) ---
def test_scan_discovers_os_default_config(tmp_path: Path) -> None:
    # OS-default discovery: a planted ~/.claude/settings.json is found + audited,
    # while the other (absent) candidate paths are skipped, not fatal.
    home = tmp_path / "home"
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps(VULN_CONFIG), encoding="utf-8")
    empty_root = tmp_path / "proj"
    empty_root.mkdir()
    report = scan(
        roots=[empty_root],
        system="Darwin",
        env={"HOME": str(home)},
        enumerate_sockets=False,
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "CRED-PLAINTEXT" in ids


def test_scan_audits_project_env_file(tmp_path: Path) -> None:
    # .env project discovery -> env-file secret audit path.
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123\n", encoding="utf-8"
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    env_servers = [s for s in report.servers if s.id.endswith(".env")]
    assert env_servers
    assert env_servers[0].findings  # at least one secret/permission finding


def test_scan_skips_unreadable_config(tmp_path: Path) -> None:
    # A path that fails safe_read (a directory named .mcp.json) is skipped, not fatal.
    (tmp_path / ".mcp.json").mkdir()
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert report.servers == ()
    assert report.overall_grade == "A"


def test_scan_enumerates_exposed_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Running-server discovery: a wildcard-bound socket becomes an EXPOSE finding.
    monkeypatch.setattr(
        engine_mod,
        "enumerate_listening",
        lambda: EnumerationResult(
            sockets=(
                ListeningSocket("0.0.0.0", 8000, 123, "node"),  # noqa: S104  exposed
                ListeningSocket("127.0.0.1", 9000, 124, "node"),  # loopback: filtered out
            ),
            inspection_incomplete=False,
        ),
    )
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=True)
    running = [s for s in report.servers if s.running]
    assert len(running) == 1  # only the exposed socket is surfaced
    assert running[0].bind_addr == "0.0.0.0"  # noqa: S104
    assert any(f.id == "EXPOSE-BIND" for f in running[0].findings)


# --- online enrichment wiring ---
def test_online_default_fetch_wires_real_osv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # online=True with no injected fetch -> _default_osv_fetch imports query_osv.
    import mcpscan.enrichment.osv as osv_mod

    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")
    monkeypatch.setattr(osv_mod, "query_osv", lambda *a: [OsvVuln(id="GHSA-real", critical=True)])
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False, online=True)
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" in ids


def test_online_no_vuln_adds_nothing(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")
    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=lambda *a: ((), False),
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" not in ids


def test_online_skips_unpinnable_command(tmp_path: Path) -> None:
    # An unpinned command has no concrete version -> fetch is never called.
    (tmp_path / ".mcp.json").write_text(json.dumps(UNPINNED_CONFIG), encoding="utf-8")
    calls: list[tuple[str, str, str]] = []

    def fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        calls.append((name, version, ecosystem))
        return ((), False)

    scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fetch,
    )
    assert calls == []
