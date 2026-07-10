# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Dogfood corpus + evaluation harness (ticket T-402, Phase 1).

A curated set of *clean* and *messy* MCP configs across every supported host,
each hand-labeled with the finding ids it must produce. :func:`evaluate` lays a
fixture out at its real discovery location and runs the actual ``scan`` pipeline
end to end, then compares the findings to the label — surfacing false positives
(flagged a non-issue) and false negatives (missed a real one).

This is the measurable pre-1.0 quality gate: a clean fixture must be silent, and
a messy one must produce exactly its labeled findings — no more, no less. The
same corpus is driven as a CI regression test (``tests/test_dogfood.py``) so any
heuristic regression is caught permanently.

The bundled fixtures are synthetic (safe to commit). Real, anonymized configs
collected during the stakeholder dogfood pass drop in here the same way.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from mcpscan.engine import scan


def _json(obj: object) -> str:
    return json.dumps(obj, indent=2)


# --- shared fragments -------------------------------------------------------
_SECRET = "S3cr3t-Pa55w0rd-abcdef123456"  # trips CRED-PLAINTEXT
_MESSY_SERVER = {"command": "npx", "args": ["-y", "db-mcp-server"], "env": {"PGPASSWORD": _SECRET}}
_CLEAN_SERVER = {"command": "npx", "args": ["-y", "db-mcp-server@1.2.3"], "env": {"LOG_LEVEL": "x"}}

# Every finding id a fixture may legitimately produce (for per-check metrics).
CHECK_IDS = (
    "CRED-PLAINTEXT",
    "PIN-UNPINNED",
    "SCOPE-DANGEROUS-ALLOW",
    "SCOPE-WILDCARD",
    "SCOPE-DANGEROUS-AUTOAPPROVE",
    "SCOPE-AUTOAPPROVE-WILDCARD",
)


@dataclass(frozen=True)
class Fixture:
    """One labeled corpus config."""

    host: str
    label: str  # "clean" | "messy"
    scope: str  # "project" | "user"
    relpath: str  # path relative to the project root (project) or HOME (user)
    content: str  # the config file's text
    expects: frozenset[str] = field(default_factory=frozenset)  # expected finding ids

    @property
    def name(self) -> str:
        return f"{self.host}:{self.label}"


@dataclass(frozen=True)
class Result:
    """The outcome of evaluating one fixture."""

    fixture: Fixture
    actual: frozenset[str]

    @property
    def false_positives(self) -> frozenset[str]:
        return self.actual - self.fixture.expects

    @property
    def false_negatives(self) -> frozenset[str]:
        return self.fixture.expects - self.actual

    @property
    def passed(self) -> bool:
        return not self.false_positives and not self.false_negatives


def evaluate(fixture: Fixture) -> Result:
    """Lay the fixture out at its real discovery path and run the scan pipeline."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        target = root / fixture.relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(fixture.content, encoding="utf-8")

        if fixture.scope == "project":
            report = scan(roots=[root], system="Linux", env={}, enumerate_sockets=False)
        else:  # user-level: drive OS-default discovery via HOME
            report = scan(
                roots=[], system="Linux", env={"HOME": str(root)}, enumerate_sockets=False
            )

    actual = frozenset(f.id for s in report.servers for f in s.findings if f.id in CHECK_IDS)
    return Result(fixture=fixture, actual=actual)


# --- the corpus -------------------------------------------------------------
# YAML content is hand-written so the corpus module needs no yaml dependency.
_CONTINUE_MESSY = (
    "name: cfg\n"
    "mcpServers:\n"
    "  - name: leaky\n"
    "    command: npx\n"
    '    args: ["-y", "db-mcp-server"]\n'
    "    env:\n"
    f"      PGPASSWORD: {_SECRET}\n"
)
_CONTINUE_CLEAN = (
    "name: cfg\n"
    "mcpServers:\n"
    "  - name: safe\n"
    "    command: npx\n"
    '    args: ["-y", "db-mcp-server@1.2.3"]\n'
    "    env:\n"
    "      LOG_LEVEL: info\n"
)

_CRED_PIN = frozenset({"CRED-PLAINTEXT", "PIN-UNPINNED"})

CORPUS: tuple[Fixture, ...] = (
    # --- Claude (mcpServers + permissions) ---
    Fixture(
        "claude",
        "messy",
        "project",
        ".mcp.json",
        _json(
            {"mcpServers": {"leaky": _MESSY_SERVER}, "permissions": {"allow": ["Read", "Bash(*)"]}}
        ),
        _CRED_PIN | {"SCOPE-DANGEROUS-ALLOW"},
    ),
    Fixture(
        "claude",
        "clean",
        "project",
        ".mcp.json",
        _json(
            {
                "mcpServers": {"safe": _CLEAN_SERVER},
                "permissions": {"allow": ["Read", "Glob(src/**)"]},
            }
        ),
    ),
    # --- Cursor (mcpServers) ---
    Fixture(
        "cursor",
        "messy",
        "project",
        ".cursor/mcp.json",
        _json({"mcpServers": {"leaky": _MESSY_SERVER}}),
        _CRED_PIN,
    ),
    Fixture(
        "cursor",
        "clean",
        "project",
        ".cursor/mcp.json",
        _json({"mcpServers": {"safe": _CLEAN_SERVER}}),
    ),
    # --- VS Code (servers) ---
    Fixture(
        "vscode",
        "messy",
        "project",
        ".vscode/mcp.json",
        _json({"servers": {"leaky": _MESSY_SERVER}}),
        _CRED_PIN,
    ),
    Fixture(
        "vscode",
        "clean",
        "project",
        ".vscode/mcp.json",
        _json({"servers": {"safe": _CLEAN_SERVER}}),
    ),
    # --- Zed (context_servers) ---
    Fixture(
        "zed",
        "messy",
        "project",
        ".zed/settings.json",
        _json({"context_servers": {"leaky": _MESSY_SERVER}}),
        _CRED_PIN,
    ),
    Fixture(
        "zed",
        "clean",
        "project",
        ".zed/settings.json",
        _json({"context_servers": {"safe": _CLEAN_SERVER}}),
    ),
    # --- Continue (YAML mcpServers list) ---
    Fixture("continue", "messy", "project", ".continue/config.yaml", _CONTINUE_MESSY, _CRED_PIN),
    Fixture("continue", "clean", "project", ".continue/config.yaml", _CONTINUE_CLEAN),
    # --- Windsurf (user-level) ---
    Fixture(
        "windsurf",
        "messy",
        "user",
        ".codeium/windsurf/mcp_config.json",
        _json({"mcpServers": {"leaky": _MESSY_SERVER}}),
        _CRED_PIN,
    ),
    Fixture(
        "windsurf",
        "clean",
        "user",
        ".codeium/windsurf/mcp_config.json",
        _json({"mcpServers": {"safe": _CLEAN_SERVER}}),
    ),
    # --- Cline (user-level; messy adds a dangerous autoApprove) ---
    Fixture(
        "cline",
        "messy",
        "user",
        ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        _json({"mcpServers": {"leaky": {**_MESSY_SERVER, "autoApprove": ["run_command"]}}}),
        _CRED_PIN | {"SCOPE-DANGEROUS-AUTOAPPROVE"},
    ),
    Fixture(
        "cline",
        "clean",
        "user",
        ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        _json({"mcpServers": {"safe": _CLEAN_SERVER}}),
    ),
    # --- wildcard-scope variants (otherwise-clean; exercise the wildcard checks) ---
    Fixture(
        "claude",
        "wildcard",
        "project",
        ".mcp.json",
        _json({"mcpServers": {"safe": _CLEAN_SERVER}, "permissions": {"allow": ["mcp__*"]}}),
        frozenset({"SCOPE-WILDCARD"}),
    ),
    Fixture(
        "cline",
        "wildcard",
        "user",
        ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        _json({"mcpServers": {"safe": {**_CLEAN_SERVER, "autoApprove": ["mcp__*"]}}}),
        frozenset({"SCOPE-AUTOAPPROVE-WILDCARD"}),
    ),
)


def evaluate_all() -> list[Result]:
    return [evaluate(fx) for fx in CORPUS]
