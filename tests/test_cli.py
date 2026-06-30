"""CLI wiring tests (help, scan summary, exit codes)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcpscan.engine as engine_mod
from mcpscan.cli import main
from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)


def test_no_command_prints_help_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    assert rc == 0
    assert "mcpscan" in capsys.readouterr().out


def _report(*findings: Finding) -> Report:
    server = Server(
        id="s",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=tuple(findings),
    )
    return Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="F" if findings else "A",
        dimension_grades={},
    )


def test_scan_clean_returns_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report())
    rc = main(["scan"])
    assert rc == 0
    assert "posture: A" in capsys.readouterr().out


def test_scan_with_critical_returns_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    finding = Finding(
        id="X",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="t",
        location=Location(path="p"),
        remediation="fix",
        rationale="r",
    )
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report(finding))
    assert main(["scan"]) == 1


def test_show_secrets_emits_warning(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report())
    main(["scan", "--show-secrets"])
    assert "show-secrets" in capsys.readouterr().err


def test_online_emits_egress_note(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report())
    main(["scan", "--online"])
    assert "api.osv.dev" in capsys.readouterr().err


def test_writes_json_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report())
    out = tmp_path / "report.json"
    main(["scan", "--json", str(out)])
    assert isinstance(json.loads(out.read_text(encoding="utf-8")), dict)
    assert "wrote JSON report" in capsys.readouterr().err


def test_writes_html_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(engine_mod, "scan", lambda **_: _report())
    out = tmp_path / "report.html"
    main(["scan", "--html", str(out)])
    assert "<html" in out.read_text(encoding="utf-8").lower()
    assert "wrote HTML report" in capsys.readouterr().err
