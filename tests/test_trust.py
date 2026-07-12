"""Tier-4 agent trust: factor scoring, risk relationships, grading, rendering."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.adapters.base import ParsedConfig, ServerDecl
from mcpscan.report import RenderOptions
from mcpscan.trust import (
    TrustFactor,
    analyze_config,
    build_trust_report,
    collect_trust,
    profile_server,
)
from mcpscan.trust.render import render_json_trust, render_terminal_trust

_SECRET = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _factor(profile: object, factor: TrustFactor) -> int:
    from mcpscan.trust.model import TrustProfile

    assert isinstance(profile, TrustProfile)
    return next(f.risk for f in profile.factors if f.factor is factor)


def _rel_ids(profile: object) -> set[str]:
    from mcpscan.trust.model import TrustProfile

    assert isinstance(profile, TrustProfile)
    return {r.id for r in profile.relationships}


# --- individual factors ---
def test_clean_server_is_fully_trusted() -> None:
    server = ServerDecl(name="safe", command="npx", args=("db-mcp-server@1.2.3",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.score == 100 and profile.grade == "A"
    assert profile.relationships == ()
    assert profile.present_factors == ()


def test_secret_access_lowers_trust() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.SECRET_ACCESS) == 25
    assert profile.score == 75


def test_multiple_secrets_add_risk_up_to_cap() -> None:
    env = tuple((f"KEY{i}", _SECRET) for i in range(6))
    server = ServerDecl(name="db", command="npx", args=("pg@1.0.0",), env=env)
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.SECRET_ACCESS) == 40  # capped


def test_dangerous_autoapprove_is_privilege_and_autonomy() -> None:
    server = ServerDecl(name="sh", command="npx", args=("x@1.0.0",), auto_approve=("run_command",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.TOOL_PRIVILEGE) == 25
    assert _factor(profile, TrustFactor.AUTONOMY) == 15


def test_wildcard_grant_adds_privilege() -> None:
    server = ServerDecl(name="w", command="npx", args=("x@1.0.0",), auto_approve=("mcp__*",))
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.TOOL_PRIVILEGE) == 20


def test_unpinned_runner_flags_provenance() -> None:
    server = ServerDecl(name="u", command="npx", args=("some-server",))  # no @version
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert _factor(profile, TrustFactor.CODE_PROVENANCE) == 10


# --- risk relationships: the differentiator ---
def test_privileged_secret_holder_relationship() -> None:
    server = ServerDecl(
        name="db",
        command="npx",
        args=("pg@1.0.0",),
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("run_command",),
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    ids = _rel_ids(profile)
    assert "PRIVILEGED-SECRET-HOLDER" in ids
    assert "AUTONOMOUS-PRIVILEGED" in ids
    assert "AUTONOMOUS-SECRET-HOLDER" in ids


def test_unvetted_privileged_relationship() -> None:
    server = ServerDecl(
        name="u", command="npx", args=("some-server",), auto_approve=("run_command",)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert "UNVETTED-PRIVILEGED" in _rel_ids(profile)


def test_secrets_alone_create_no_relationship() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.relationships == ()  # one factor is not a combination


def test_score_floors_at_zero() -> None:
    env = tuple((f"KEY{i}", _SECRET) for i in range(6))  # 40
    server = ServerDecl(
        name="worst",
        command="npx",
        args=("some-server",),  # unpinned: 10
        env=env,
        auto_approve=("run_command", "mcp__*"),  # 40 + autonomy 15
    )
    profile = profile_server(server, "/cfg/.mcp.json", "claude")
    assert profile.score == 0 and profile.grade == "F"


# --- report assembly ---
def test_report_grades_by_worst_subject() -> None:
    clean = ServerDecl(name="safe", command="npx", args=("x@1.0.0",))
    risky = ServerDecl(name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),))
    config = ParsedConfig(path="/cfg/.mcp.json", servers=(clean, risky))
    report = build_trust_report(analyze_config(config, "claude"))
    assert report.overall_grade == "C"  # 75 -> C is the worst
    assert report.profiles[0].server_name == "db"  # worst score sorts first
    assert len(report.risky) == 0  # secrets alone -> no relationship


# --- rendering ---
def test_terminal_render_lists_relationships() -> None:
    server = ServerDecl(
        name="db",
        command="npx",
        args=("pg@1.0.0",),
        env=(("PGPASSWORD", _SECRET),),
        auto_approve=("run_command",),
    )
    report = build_trust_report([profile_server(server, "/cfg/.mcp.json", "claude")])
    out = render_terminal_trust(report, RenderOptions())
    assert "Trust" in out and "PRIVILEGED-SECRET-HOLDER" in out
    assert _SECRET not in out  # never leaks the raw secret


def test_terminal_render_empty() -> None:
    report = build_trust_report([])
    out = render_terminal_trust(report, RenderOptions())
    assert "No MCP servers found" in out


def test_json_render_is_stable_and_secretless() -> None:
    server = ServerDecl(
        name="db", command="npx", args=("pg@1.0.0",), env=(("PGPASSWORD", _SECRET),)
    )
    report = build_trust_report([profile_server(server, "/cfg/.mcp.json", "claude")])
    first = render_json_trust(report, RenderOptions())
    assert first == render_json_trust(report, RenderOptions())
    payload = json.loads(first)
    assert payload["schema_version"] == "1.0"
    assert payload["profiles"][0]["score"] == 75
    assert _SECRET not in first


# --- collection end to end ---
def test_collect_trust_from_real_config(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "command": "npx",
                        "args": ["pg-mcp"],
                        "env": {"PGPASSWORD": _SECRET},
                        "autoApprove": ["run_command"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = collect_trust(roots=[tmp_path], system="Linux", env={})
    assert len(report.profiles) == 1
    profile = report.profiles[0]
    assert profile.server_name == "db"
    assert "PRIVILEGED-SECRET-HOLDER" in {r.id for r in profile.relationships}
    assert report.risky  # this tool is a risky relationship subject


def test_collect_skips_unreadable_config(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from mcpscan.io_safe import SafeReadError

    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")

    def boom(path: object, root: object) -> str:
        raise SafeReadError("unreadable")

    monkeypatch.setattr("mcpscan.trust.collect.safe_read_text", boom)
    report = collect_trust(roots=[tmp_path], system="Linux", env={})
    assert report.profiles == ()  # skipped gracefully, no crash
