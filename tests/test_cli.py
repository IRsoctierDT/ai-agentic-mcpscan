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


# --- lan command wiring ---
_LAN_ED25519 = b"""
authorization_id = "ENG-2026-0710"
operator = "op@example.com"
expires_at = 2030-01-01T00:00:00Z
targets = ["192.168.10.20/32"]
ports = [3000]
[signature]
scheme = "ed25519"
"""


def test_lan_requires_manifest_and_invoker(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lan"]) == 2
    assert "requires --manifest and --invoker" in capsys.readouterr().err


def test_lan_unreadable_manifest_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert main(["lan", "--manifest", str(missing), "--invoker", "human"]) == 2
    assert "cannot read manifest" in capsys.readouterr().err


def test_lan_ed25519_without_extra_is_refused(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Real run through the CLI: ed25519 is refused before any subprocess/probe.
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    assert main(["lan", "--manifest", str(manifest), "--invoker", "human"]) == 2
    err = capsys.readouterr().err
    assert "refused:" in err and "crypto" in err


def test_lan_success_prints_report_and_audit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    make_finding: Callable[..., Finding],
    tmp_path: Path,
) -> None:
    from mcpscan.domain import Dimension
    from mcpscan.lan.audit import AuditRecord
    from mcpscan.lan.runner import LanOutcome

    finding = make_finding(id="LAN-EXPOSED", severity=Severity.HIGH, dimension=Dimension.EXPOSURE)
    audit = AuditRecord(
        manifest_sha256="a" * 64,
        authorization_id="ENG-42",
        operator="op@example.com",
        tool_version="0.6.0",
        invoker="human",
        utc_timestamp="2026-07-10T09:00:00Z",
        argv=("mcpscan", "lan"),
        resolved_targets=("192.168.10.20",),
        results_digest="d" * 64,
    )
    outcome = LanOutcome(
        report=make_report(finding),
        audit=audit,
        dry_run=False,
        plan_hosts=("192.168.10.20",),
        plan_ports=(3000,),
    )
    monkeypatch.setattr("mcpscan.lan.run_lan", lambda **_: outcome)
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    out_json = tmp_path / "lan.json"

    rc = main(["lan", "--manifest", str(manifest), "--invoker", "human", "--json", str(out_json)])
    assert rc == 1  # a HIGH finding is blocking at the default threshold
    err = capsys.readouterr().err
    assert "authorized run ENG-42" in err
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["audit"]["authorization_id"] == "ENG-42"
    assert payload["report"]["servers"]


def test_lan_dry_run_sends_no_packet(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    make_report: Callable[..., Report],
    tmp_path: Path,
) -> None:
    from mcpscan.lan.audit import AuditRecord
    from mcpscan.lan.runner import LanOutcome

    audit = AuditRecord(
        manifest_sha256="a" * 64,
        authorization_id="ENG-42",
        operator="op@example.com",
        tool_version="0.6.0",
        invoker="human",
        utc_timestamp="2026-07-10T09:00:00Z",
        argv=("mcpscan", "lan"),
        resolved_targets=("192.168.10.20",),
        results_digest="d" * 64,
    )
    outcome = LanOutcome(
        report=make_report(),
        audit=audit,
        dry_run=True,
        plan_hosts=("192.168.10.20",),
        plan_ports=(3000, 8000),
    )
    monkeypatch.setattr("mcpscan.lan.run_lan", lambda **_: outcome)
    manifest = tmp_path / "auth.toml"
    manifest.write_bytes(_LAN_ED25519)
    assert main(["lan", "--manifest", str(manifest), "--invoker", "human", "--dry-run"]) == 0
    err = capsys.readouterr().err
    assert "[dry-run]" in err and "no packets sent" in err
