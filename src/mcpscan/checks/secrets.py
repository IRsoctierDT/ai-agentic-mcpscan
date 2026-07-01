# Copyright 2026 IRsoctierDT
# SPDX-License-Identifier: Apache-2.0
"""Credential-hygiene checks (T-206 detection, T-207 at-rest).

Detects plaintext secrets in server ``env`` blocks and ``.env`` files (by known
provider patterns and by high-entropy values on secret-named keys), and flags
secret-bearing files that are world/group-readable or git-tracked. Every detected
secret is reduced to a fingerprint immediately (R1) — the raw value never leaves
this module.
"""

from __future__ import annotations

import math
import re

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity
from ..redaction import fingerprint_secret
from . import EnvFile

# Known high-confidence provider patterns.
_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
)

_SECRET_NAME = re.compile(
    r"(API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)
_ENTROPY_THRESHOLD = 3.5
_MIN_ENTROPY_LEN = 20


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char) of a string."""
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _provider_match(value: str) -> str | None:
    for label, pattern in _PROVIDER_PATTERNS:
        if pattern.search(value):
            return label
    return None


def _looks_secret(key: str, value: str) -> str | None:
    """Return a human label if (key, value) looks like a plaintext secret."""
    label = _provider_match(value)
    if label is not None:
        return label
    if (
        _SECRET_NAME.search(key)
        and len(value) >= _MIN_ENTROPY_LEN
        and shannon_entropy(value) >= _ENTROPY_THRESHOLD
    ):
        return "High-entropy secret"
    return None


def _finding(label: str, location: Location, raw_value: str) -> Finding:
    return Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title=f"Plaintext {label} in config",
        location=location,
        remediation=(
            "Remove the literal value from the file. Reference it from a secret "
            "manager or an environment variable resolved at runtime, and rotate "
            "the exposed credential."
        ),
        rationale="Plaintext credentials in agent config are trivially exfiltrated.",
        secret=fingerprint_secret(raw_value),
    )


def check_server_env(server: ServerDecl, config_path: str) -> list[Finding]:
    """Detect plaintext secrets in a declared server's ``env`` block."""
    findings: list[Finding] = []
    for key, value in server.env:
        label = _looks_secret(key, value)
        if label is not None:
            findings.append(_finding(label, Location(path=config_path), value))
    return findings


def check_env_file_secrets(env_file: EnvFile) -> list[Finding]:
    """Detect plaintext secrets in a parsed ``.env`` file."""
    findings: list[Finding] = []
    for lineno, key, value in env_file.entries:
        label = _looks_secret(key, value)
        if label is not None:
            findings.append(_finding(label, Location(path=env_file.path, line=lineno), value))
    return findings


def check_secret_at_rest(env_file: EnvFile) -> list[Finding]:
    """Flag a secret-bearing ``.env`` that is world/group-readable or tracked."""
    findings: list[Finding] = []
    has_secret = any(_looks_secret(k, v) is not None for _, k, v in env_file.entries)
    if not has_secret:
        return findings

    if env_file.mode is not None and env_file.mode & 0o077:
        findings.append(
            Finding(
                id="CRED-PERMS",
                dimension=Dimension.CREDENTIAL,
                severity=Severity.HIGH,
                title="Secret file is group/world-readable",
                location=Location(path=env_file.path),
                remediation="Restrict permissions: chmod 600 the file.",
                rationale="Other local users/processes can read the secrets.",
            )
        )
    if env_file.git_tracked:
        findings.append(
            Finding(
                id="CRED-GIT",
                dimension=Dimension.CREDENTIAL,
                severity=Severity.HIGH,
                title="Secret file is tracked by git",
                location=Location(path=env_file.path),
                remediation="Remove from git history and add the file to .gitignore.",
                rationale="Committed secrets leak to anyone with repo access.",
            )
        )
    return findings
