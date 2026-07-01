# Copyright 2026 IRsoctierDT
# SPDX-License-Identifier: Apache-2.0
"""Tool-scope / auto-approval checks (ticket T-208).

Flags over-broad permission grants and auto-approved dangerous (shell/exec-class)
tools. Pure functions over parsed config.
"""

from __future__ import annotations

import re

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity

_DANGEROUS = re.compile(
    r"(bash|sh|shell|exec|execute|run[_-]?command|command|subprocess|eval|os\.)",
    re.IGNORECASE,
)
_PARENS = re.compile(r"\([^)]*\)")


def _is_dangerous(token: str) -> bool:
    return bool(_DANGEROUS.search(token))


def _has_broad_wildcard(entry: str) -> bool:
    """True if ``*`` wildcards the tool/permission *name* itself.

    A ``*`` inside parentheses (e.g. ``Glob(src/**)``) scopes a specific tool's
    arguments and is fine; a ``*`` outside parentheses (``*``, ``mcp__*``) grants
    access broadly and is flagged.
    """
    outside = _PARENS.sub("", entry)
    return "*" in outside


def check_permissions(allow: tuple[str, ...], config_path: str) -> list[Finding]:
    """Flag wildcard grants and auto-allowed dangerous tools in an allow-list."""
    findings: list[Finding] = []
    for entry in allow:
        if _is_dangerous(entry):
            findings.append(
                Finding(
                    id="SCOPE-DANGEROUS-ALLOW",
                    dimension=Dimension.TOOL_SCOPE,
                    severity=Severity.HIGH,
                    title=f"Dangerous tool auto-allowed: {entry!r}",
                    location=Location(path=config_path),
                    remediation=(
                        "Remove the blanket allow for shell/exec-class tools; "
                        "require interactive approval, or scope to specific safe "
                        "commands."
                    ),
                    rationale="Auto-approved command execution is a full RCE primitive.",
                )
            )
        elif _has_broad_wildcard(entry):
            findings.append(
                Finding(
                    id="SCOPE-WILDCARD",
                    dimension=Dimension.TOOL_SCOPE,
                    severity=Severity.MEDIUM,
                    title=f"Wildcard permission grant: {entry!r}",
                    location=Location(path=config_path),
                    remediation="Replace the wildcard with an explicit allow-list.",
                    rationale="Wildcards grant more tool access than is needed.",
                )
            )
    return findings


def check_server_auto_approve(server: ServerDecl, config_path: str) -> list[Finding]:
    """Flag a server's own ``autoApprove`` entries that are dangerous/wildcards."""
    findings: list[Finding] = []
    for entry in server.auto_approve:
        if _is_dangerous(entry):
            findings.append(
                Finding(
                    id="SCOPE-DANGEROUS-AUTOAPPROVE",
                    dimension=Dimension.TOOL_SCOPE,
                    severity=Severity.HIGH,
                    title=f"Server {server.name!r} auto-approves dangerous tool {entry!r}",
                    location=Location(path=config_path),
                    remediation="Remove dangerous tools from autoApprove.",
                    rationale="Auto-approval removes the human check on risky tools.",
                )
            )
        elif _has_broad_wildcard(entry):
            findings.append(
                Finding(
                    id="SCOPE-AUTOAPPROVE-WILDCARD",
                    dimension=Dimension.TOOL_SCOPE,
                    severity=Severity.MEDIUM,
                    title=f"Server {server.name!r} auto-approves wildcard {entry!r}",
                    location=Location(path=config_path),
                    remediation="Replace the wildcard with explicit tool names.",
                    rationale="Wildcard auto-approval grants broad unattended access.",
                )
            )
    return findings
