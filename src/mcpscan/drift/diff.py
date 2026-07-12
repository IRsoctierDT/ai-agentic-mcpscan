# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Compare two snapshots into a :class:`DriftReport` (VISION Tier 5).

Pure set-difference over posture facts by their stable key, plus a **direction**
for each change so a CI gate can act on regressions only:

- a **new finding** or a **newly-exposed** server is a REGRESSION (posture worse);
- a **resolved finding** or a server that **stopped being exposed** is an
  IMPROVEMENT;
- everything else — a new/removed asset, a declared server appearing — is
  INFORMATIONAL.

The asymmetry is deliberate: findings are problems, so *gaining* one is bad and
*losing* one is good; assets are inventory, so their coming and going is just
news. A control that disappears shows up here as a **new finding** (the check
that the control was present now fires), which is why added findings are the
core regression signal.
"""

from __future__ import annotations

from .model import ChangeType, Direction, DriftEntry, DriftReport, FactKind, PostureFact, Snapshot


def _exposure_of(fact: PostureFact) -> str:
    return fact.detail_map().get("exposure", "")


def _added_direction(fact: PostureFact) -> Direction:
    if fact.kind is FactKind.FINDING:
        return Direction.REGRESSION
    if fact.kind is FactKind.SERVER and _exposure_of(fact) == "exposed":
        return Direction.REGRESSION
    return Direction.INFORMATIONAL


def _removed_direction(fact: PostureFact) -> Direction:
    if fact.kind is FactKind.FINDING:
        return Direction.IMPROVEMENT
    return Direction.INFORMATIONAL


def _changed_direction(before: PostureFact, after: PostureFact) -> Direction:
    if after.kind is FactKind.SERVER:
        was, now = _exposure_of(before), _exposure_of(after)
        if was != "exposed" and now == "exposed":
            return Direction.REGRESSION
        if was == "exposed" and now != "exposed":
            return Direction.IMPROVEMENT
    return Direction.INFORMATIONAL


def diff_snapshots(baseline: Snapshot, current: Snapshot) -> DriftReport:
    """Diff a baseline snapshot against a current one."""
    old = baseline.by_key()
    new = current.by_key()
    entries: list[DriftEntry] = []

    for key in new.keys() - old.keys():
        fact = new[key]
        entries.append(
            DriftEntry(
                change=ChangeType.ADDED,
                kind=fact.kind,
                key=key,
                summary=fact.summary,
                direction=_added_direction(fact),
                detail_after=fact.detail,
            )
        )

    for key in old.keys() - new.keys():
        fact = old[key]
        entries.append(
            DriftEntry(
                change=ChangeType.REMOVED,
                kind=fact.kind,
                key=key,
                summary=fact.summary,
                direction=_removed_direction(fact),
                detail_before=fact.detail,
            )
        )

    for key in old.keys() & new.keys():
        before, after = old[key], new[key]
        if before.detail == after.detail:
            continue
        entries.append(
            DriftEntry(
                change=ChangeType.CHANGED,
                kind=after.kind,
                key=key,
                summary=after.summary,
                direction=_changed_direction(before, after),
                detail_before=before.detail,
                detail_after=after.detail,
            )
        )

    entries.sort(key=lambda e: (_DIRECTION_ORDER[e.direction], e.kind.value, e.key))
    return DriftReport(entries=tuple(entries))


_DIRECTION_ORDER = {
    Direction.REGRESSION: 0,
    Direction.IMPROVEMENT: 1,
    Direction.INFORMATIONAL: 2,
}
