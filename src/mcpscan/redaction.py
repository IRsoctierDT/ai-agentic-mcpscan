# Copyright 2026 IRsoctierDT
# SPDX-License-Identifier: Apache-2.0
"""Secret redaction (architecture R1; foundational slice of ticket T-206).

The single place a raw secret value is turned into a share-safe
:class:`~mcpscan.domain.SecretFingerprint`. Call this immediately at detection so
the raw value never propagates into the domain model or any report.
"""

from __future__ import annotations

import hashlib

from .domain import SecretFingerprint

_VISIBLE_EACH_SIDE = 2


def mask(raw: str) -> str:
    """Return a masked form revealing at most first-2/last-2 characters.

    Short secrets (<= 2 * visible) are fully masked to avoid revealing most of a
    small token.
    """
    if len(raw) <= _VISIBLE_EACH_SIDE * 2:
        return "*" * len(raw)
    hidden = len(raw) - _VISIBLE_EACH_SIDE * 2
    return f"{raw[:_VISIBLE_EACH_SIDE]}{'*' * hidden}{raw[-_VISIBLE_EACH_SIDE:]}"


def fingerprint_secret(raw: str) -> SecretFingerprint:
    """Reduce a raw secret to a non-reversible, share-safe fingerprint.

    ``sha256_8`` is a 32-bit truncation for operator triage only and must never
    be treated as a security control (review finding F3).
    """
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    return SecretFingerprint(masked=mask(raw), sha256_8=digest, length=len(raw))
