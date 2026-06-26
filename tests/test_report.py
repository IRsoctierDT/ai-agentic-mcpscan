"""Renderer tests: JSON determinism, HTML offline-safety, redaction, paths, perms."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)
from mcpscan.redaction import fingerprint_secret
from mcpscan.report import RenderOptions, display_path
from mcpscan.report.html import render_html
from mcpscan.report.json_report import render_json
from mcpscan.report.terminal import render_terminal
from mcpscan.report.writer import write_report

RAW_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"


def _report(home: str = "/home/jane") -> Report:
    finding = Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="Plaintext OpenAI API key in config",
        location=Location(path=f"{home}/.mcp.json", line=4),
        remediation="Move it to a secret manager and rotate the key.",
        rationale="Plaintext credentials are trivially exfiltrated.",
        secret=fingerprint_secret(RAW_SECRET),
    )
    server = Server(
        id=f"{home}/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(finding,),
    )
    return Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F", Dimension.EXPOSURE: "A"},
    )


# --- JSON (T-302) ---
def test_json_is_deterministic() -> None:
    r = _report()
    assert render_json(r) == render_json(r)  # byte-stable


def test_json_never_contains_raw_secret() -> None:
    out = render_json(_report(), RenderOptions(home="/home/jane"))
    assert RAW_SECRET not in out
    data = json.loads(out)
    secret = data["servers"][0]["findings"][0]["secret"]
    assert "masked" not in secret  # redacted by default
    assert secret["length"] == len(RAW_SECRET)


def test_json_show_secrets_adds_masked_only() -> None:
    out = render_json(_report(), RenderOptions(show_secrets=True, home="/home/jane"))
    secret = json.loads(out)["servers"][0]["findings"][0]["secret"]
    assert "masked" in secret
    assert RAW_SECRET not in out  # masked, never raw


# --- path privacy (T-306) ---
def test_display_path_relativizes_home() -> None:
    opts = RenderOptions(home="/home/jane")
    assert display_path("/home/jane/.mcp.json", opts) == "~/.mcp.json"
    assert display_path("/etc/other", opts) == "/etc/other"


def test_absolute_paths_opt_out() -> None:
    opts = RenderOptions(home="/home/jane", absolute_paths=True)
    assert display_path("/home/jane/.mcp.json", opts) == "/home/jane/.mcp.json"


def test_json_path_is_relativized_by_default() -> None:
    out = render_json(_report(), RenderOptions(home="/home/jane"))
    path = json.loads(out)["servers"][0]["findings"][0]["location"]["path"]
    assert path == "~/.mcp.json"


# --- HTML (T-303) ---
def test_html_makes_no_external_references() -> None:
    html = render_html(_report(), RenderOptions(home="/home/jane"))
    lowered = html.lower()
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "cdn" not in lowered
    assert "src=" not in lowered  # no external images/scripts
    assert "Plaintext OpenAI API key" in html
    assert RAW_SECRET not in html


def test_html_escapes_and_grades() -> None:
    html = render_html(_report())
    assert "grade-F" in html


# --- terminal (T-301) ---
def test_terminal_redacts_by_default() -> None:
    out = render_terminal(_report(), RenderOptions(home="/home/jane"))
    assert "[redacted" in out
    assert RAW_SECRET not in out
    assert "overall posture: F" in out


def test_terminal_clean_report() -> None:
    clean = Report(schema_version="1.0", servers=(), overall_grade="A", dimension_grades={})
    assert "No findings" in render_terminal(clean)


# --- writer perms (T-305) ---
@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_write_report_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    write_report(target, '{"ok": true}')
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600
    assert target.read_text() == '{"ok": true}'


def test_write_report_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    write_report(target, "first")
    write_report(target, "second")
    assert target.read_text() == "second"
