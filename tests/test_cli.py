"""CLI wiring tests (help, scan summary, exit codes, report writing, warnings)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.cli import main
from mcpscan.domain import Finding, Report, Severity


def test_no_command_prints_help_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    assert rc == 0
    assert "mcpscan" in capsys.readouterr().out


def test_scan_clean_returns_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    rc = main(["scan"])
    assert rc == 0
    assert "posture: A" in capsys.readouterr().out


def test_scan_with_critical_returns_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(make_finding()))
    assert main(["scan"]) == 1


def test_fail_on_threshold_respected(
    monkeypatch: pytest.MonkeyPatch,
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
) -> None:
    # A MEDIUM finding is non-blocking at the default 'high' threshold but
    # blocking when --fail-on is lowered to 'medium'.
    medium = make_finding(id="M", severity=Severity.MEDIUM)
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(medium))
    assert main(["scan"]) == 0
    assert main(["scan", "--fail-on", "medium"]) == 1


def test_writes_json_and_html_reports(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    rc = main(["scan", "--json", str(json_path), "--html", str(html_path)])
    assert rc == 0
    assert isinstance(json.loads(json_path.read_text(encoding="utf-8")), dict)
    assert html_path.exists() and "<html" in html_path.read_text(encoding="utf-8").lower()
    err = capsys.readouterr().err
    assert "wrote JSON report" in err
    assert "wrote HTML report" in err


def test_writes_sarif_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report(make_finding()))
    sarif_path = tmp_path / "results.sarif"
    # A critical finding still writes SARIF before the non-zero exit.
    rc = main(["scan", "--sarif", str(sarif_path), "--fail-on", "critical"])
    assert rc == 1
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], "expected at least one SARIF result"
    assert "wrote SARIF report" in capsys.readouterr().err


def test_fix_removes_dangerous_grant_and_backs_up(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    # End-to-end: a project .mcp.json with an auto-allowed Bash(*) is remediated
    # in place, a backup is written, and a re-scan finds the tool-scope issue gone.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {}, "permissions": {"allow": ["Read", "Bash(*)"]}}),
        encoding="utf-8",
    )
    rc = main(["scan", "--root", str(tmp_path), "--fix", "--fail-on", "low"])
    # Exit code reflects the pre-fix scan (a HIGH finding was present).
    assert rc == 1
    assert (tmp_path / ".mcp.json.mcpscan.bak").exists()
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["permissions"]["allow"] == ["Read"]  # Bash(*) removed
    err = capsys.readouterr().err
    assert "--fix modifies config files" in err
    assert "applied 1 fix" in err


def test_no_fix_flag_never_writes(tmp_path: Path) -> None:
    # Advise-only preserved: without --fix, the config is byte-for-byte untouched
    # and no backup is created.
    cfg = tmp_path / ".mcp.json"
    original = json.dumps({"mcpServers": {}, "permissions": {"allow": ["Bash(*)"]}})
    cfg.write_text(original, encoding="utf-8")
    main(["scan", "--root", str(tmp_path)])
    assert cfg.read_text(encoding="utf-8") == original
    assert not (tmp_path / ".mcp.json.mcpscan.bak").exists()


def test_fix_with_nothing_to_do_reports_cleanly(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {}, "permissions": {"allow": ["Read"]}}), "utf-8")
    main(["scan", "--root", str(tmp_path), "--fix"])
    assert "no auto-fixable tool-scope findings." in capsys.readouterr().err
    assert not (tmp_path / ".mcp.json.mcpscan.bak").exists()


def test_show_secrets_emits_warning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    main(["scan", "--show-secrets"])
    assert "--show-secrets" in capsys.readouterr().err


def test_online_emits_note(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: make_report())
    main(["scan", "--online"])
    assert "api.osv.dev" in capsys.readouterr().err
