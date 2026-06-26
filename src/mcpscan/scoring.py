"""Deterministic posture scoring (ticket T-210, SPEC §6).

Pure functions: identical findings always yield identical grades. Each server
starts at 100, loses points per finding by severity weight, and maps to A-F.
"""

from __future__ import annotations

from collections.abc import Iterable

from .domain import Dimension, Finding

_MAX_SCORE = 100
_GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
)
_FAIL_GRADE = "F"


def score_findings(findings: Iterable[Finding]) -> int:
    """Return a 0-100 score for a set of findings (floored at 0)."""
    score = _MAX_SCORE - sum(f.severity.weight for f in findings)
    return max(0, score)


def grade_for_score(score: int) -> str:
    """Map a 0-100 score to an A-F letter grade."""
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return _FAIL_GRADE


def grade_findings(findings: Iterable[Finding]) -> str:
    """Convenience: grade a set of findings directly."""
    return grade_for_score(score_findings(list(findings)))


def worst_grade(grades: Iterable[str]) -> str:
    """Return the worst (highest-letter) grade in the set; 'A' if empty."""
    letters = list(grades)
    if not letters:
        return "A"
    return max(letters)  # 'F' > 'D' > ... > 'A' lexicographically


def dimension_grades(findings: Iterable[Finding]) -> dict[Dimension, str]:
    """Per-dimension grade over the given findings."""
    by_dim: dict[Dimension, list[Finding]] = {dim: [] for dim in Dimension}
    for finding in findings:
        by_dim[finding.dimension].append(finding)
    return {dim: grade_findings(items) for dim, items in by_dim.items()}
