"""CLI wiring tests (help, scan summary, exit codes)."""

from __future__ import annotations

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
