"""Credential checks: detection, redaction in findings, and clean fixtures (T-206/207/212)."""

from __future__ import annotations

from mcpscan.adapters.base import ServerDecl
from mcpscan.checks import parse_env_text
from mcpscan.checks.secrets import (
    check_env_file_secrets,
    check_secret_at_rest,
    check_server_env,
    shannon_entropy,
)
from mcpscan.domain import Severity

ANTHROPIC_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def test_detects_provider_key_in_server_env() -> None:
    server = ServerDecl(name="x", command="node", env=(("ANTHROPIC_API_KEY", ANTHROPIC_KEY),))
    findings = check_server_env(server, "/cfg.json")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    # Redaction: the raw key must NOT appear anywhere on the finding.
    fp = findings[0].secret
    assert fp is not None
    assert ANTHROPIC_KEY not in fp.masked
    assert ANTHROPIC_KEY not in repr(findings[0])


def test_clean_server_env_yields_no_findings() -> None:
    # T-212 negative fixture: a non-secret env var must not fire.
    server = ServerDecl(name="x", command="node", env=(("LOG_LEVEL", "debug"),))
    assert check_server_env(server, "/cfg.json") == []


def test_env_file_detection_with_line_numbers() -> None:
    text = "# comment\nLOG=info\nOPENAI_API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWX\n"
    findings = check_env_file_secrets(parse_env_text("/.env", text))
    assert len(findings) == 1
    assert findings[0].location.line == 3


def test_at_rest_flags_group_readable_secret() -> None:
    env = parse_env_text("/.env", f"TOKEN={ANTHROPIC_KEY}\n", mode=0o644)
    findings = check_secret_at_rest(env)
    assert any(f.id == "CRED-PERMS" for f in findings)


def test_at_rest_clean_when_no_secret_present() -> None:
    env = parse_env_text("/.env", "LOG=info\n", mode=0o644)
    assert check_secret_at_rest(env) == []


def test_entropy_monotonic() -> None:
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("a8Fk2Lp9Qz")
