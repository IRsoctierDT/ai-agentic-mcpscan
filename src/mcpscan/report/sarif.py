# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 renderer (GitHub code-scanning integration).

Emits a deterministic, byte-stable SARIF log (sorted keys, no timestamps) that
``github/codeql-action/upload-sarif`` can ingest to raise code-scanning alerts.
Secrets are never present — findings carry only the redacted fingerprint,
exactly like every other renderer (architecture refinement R1).

GitHub maps a result to a file in the checkout when its ``artifactLocation.uri``
is repo-relative, so paths under ``base`` (the scanned root) are emitted
relative to it. Paths outside the repo (e.g. user-home host configs) keep the
``~`` privacy relativization and simply don't annotate — they still appear in
the log.
"""

from __future__ import annotations

import hashlib
import json

from .. import __version__
from ..domain import Finding, Report, Severity
from . import RenderOptions, display_path
from .common import ordered_findings, secret_str

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ai-agentic-mcpscan"
INFORMATION_URI = "https://github.com/IRsoctierDT/ai-agentic-mcpscan"

# Severity -> SARIF result level (error | warning | note).
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Severity -> GitHub ``security-severity`` score (drives the alert's severity band).
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _artifact_uri(path: str, base: str | None, opts: RenderOptions) -> str:
    """Map a finding location to a SARIF ``artifactLocation.uri``.

    Repo-relative when under ``base`` (so GitHub can annotate the file);
    otherwise ``~``-privatized and, if still absolute, expressed as a ``file://``
    URI. Opaque scheme locations (``socket://host:port``) pass through unchanged.
    """
    if "://" in path:
        return path
    norm = path.replace("\\", "/")
    if base:
        b = base.replace("\\", "/").rstrip("/")
        if norm == b:
            return "."
        if norm.startswith(b + "/"):
            return norm[len(b) + 1 :]
    disp = display_path(path, opts).replace("\\", "/")
    if disp.startswith("/"):
        return "file://" + disp
    if len(disp) > 2 and disp[1] == ":":  # Windows drive, e.g. C:/Users/...
        return "file:///" + disp
    return disp  # already relative, or ~/… privacy form


def _message(finding: Finding, opts: RenderOptions) -> str:
    """Human-readable result message (redaction-safe — never a raw secret)."""
    parts = [f"{finding.title}.", finding.rationale, f"Remediation: {finding.remediation}"]
    sstr = secret_str(finding.secret, opts)
    if sstr is not None:
        parts.append(f"Secret: {sstr}")
    return " ".join(p for p in parts if p)


def _partial_fingerprint(finding: Finding, uri: str) -> str:
    """Stable per-result fingerprint so GitHub tracks alerts across commits."""
    line = "" if finding.location.line is None else str(finding.location.line)
    secret = "" if finding.secret is None else finding.secret.sha256_8
    material = "\x1f".join((finding.id, uri, line, secret))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "name": finding.id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.rationale},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", finding.dimension.value],
        },
    }


def report_to_sarif(
    report: Report, opts: RenderOptions | None = None, *, base: str | None = None
) -> dict[str, object]:
    """Convert a Report to a SARIF 2.1.0 log dict (stable shape).

    Args:
        report: The scan result.
        opts: Cross-renderer display options (path privacy, secret reveal).
        base: Absolute path of the scanned root; locations under it become
            repo-relative URIs so GitHub code scanning can annotate them.
    """
    opts = opts or RenderOptions()
    rules: list[dict[str, object]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, object]] = []

    for server in report.servers:
        for finding in ordered_findings(server):
            if finding.id not in rule_index:
                rule_index[finding.id] = len(rules)
                rules.append(_rule(finding))
            uri = _artifact_uri(finding.location.path, base, opts)
            physical: dict[str, object] = {"artifactLocation": {"uri": uri}}
            if finding.location.line is not None and finding.location.line >= 1:
                physical["region"] = {"startLine": finding.location.line}
            results.append(
                {
                    "ruleId": finding.id,
                    "ruleIndex": rule_index[finding.id],
                    "level": _LEVEL[finding.severity],
                    "message": {"text": _message(finding, opts)},
                    "locations": [{"physicalLocation": physical}],
                    "partialFingerprints": {
                        "mcpscanFindingHash/v1": _partial_fingerprint(finding, uri)
                    },
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFORMATION_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(
    report: Report, opts: RenderOptions | None = None, *, base: str | None = None
) -> str:
    """Render a Report as deterministic, byte-stable SARIF 2.1.0 JSON text."""
    payload = report_to_sarif(report, opts, base=base)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
