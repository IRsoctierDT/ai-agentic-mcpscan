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
