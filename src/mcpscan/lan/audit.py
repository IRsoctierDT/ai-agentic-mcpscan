# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Immutable run audit record for LAN assessment (LAN proposal §3.1, §3.7).

Every LAN run is bound to a written record: which signed manifest authorized it,
who the operator was, the exact command, the resolved targets, and a digest of
the results. The record is deterministic given its inputs (the timestamp is
injected, never read from the clock here) so it can be golden-tested and diffed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass

from .manifest import Manifest


@dataclass(frozen=True)
class AuditRecord:
    """The bound record of one authorized LAN run."""

    manifest_sha256: str
    authorization_id: str
    operator: str
    tool_version: str
    invoker: str
    utc_timestamp: str  # caller-supplied ISO-8601 (injected, not read here)
    argv: tuple[str, ...]
    resolved_targets: tuple[str, ...]
    results_digest: str


def digest_payload(payload: object) -> str:
    """SHA-256 of a canonical JSON encoding — stable across runs for equal input."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_audit_record(
    *,
    manifest: Manifest,
    invoker: str,
    tool_version: str,
    utc_timestamp: str,
    argv: Sequence[str],
    resolved_targets: Sequence[str],
    results: object,
) -> AuditRecord:
    """Assemble the audit record binding this run to its authorizing manifest."""
    return AuditRecord(
        manifest_sha256=manifest.sha256,
        authorization_id=manifest.authorization_id,
        operator=manifest.operator,
        tool_version=tool_version,
        invoker=invoker,
        utc_timestamp=utc_timestamp,
        argv=tuple(argv),
        resolved_targets=tuple(resolved_targets),
        results_digest=digest_payload(results),
    )


def audit_record_to_dict(record: AuditRecord) -> dict[str, object]:
    """A JSON-serializable, stable-shaped view of the audit record."""
    return {
        "manifest_sha256": record.manifest_sha256,
        "authorization_id": record.authorization_id,
        "operator": record.operator,
        "tool_version": record.tool_version,
        "invoker": record.invoker,
        "utc_timestamp": record.utc_timestamp,
        "argv": list(record.argv),
        "resolved_targets": list(record.resolved_targets),
        "results_digest": record.results_digest,
    }
