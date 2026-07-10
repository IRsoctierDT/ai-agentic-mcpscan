# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Configuration-drift detection (VISION Tier 5): baseline, then diff.

``build_snapshot`` normalizes a scan (and optional inventory) into a comparable
:class:`Snapshot`; ``render_baseline`` / ``load_baseline`` persist it with an
integrity digest; ``diff_snapshots`` reports what drifted, flagging regressions
for a CI gate. Offline and read-only — it writes only the baseline you ask for.
"""

from .baseline import BaselineError, load_baseline, render_baseline
from .diff import diff_snapshots
from .model import ChangeType, Direction, DriftEntry, DriftReport, FactKind, PostureFact, Snapshot
from .snapshot import build_snapshot, snapshot_digest

__all__ = [
    "BaselineError",
    "ChangeType",
    "Direction",
    "DriftEntry",
    "DriftReport",
    "FactKind",
    "PostureFact",
    "Snapshot",
    "build_snapshot",
    "diff_snapshots",
    "load_baseline",
    "render_baseline",
    "snapshot_digest",
]
