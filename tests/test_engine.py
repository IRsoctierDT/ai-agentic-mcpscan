"""Engine + Claude adapter integration tests (T-204/205, golden/clean — T-212)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.claude import ClaudeAdapter
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
