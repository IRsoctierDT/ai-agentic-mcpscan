"""Command-line entry point for AI Agentic MCPscan (``mcpscan``).

Scaffold only. The ``scan`` behavior is implemented in the build sprints; this
module exists so the console script is wired and installable from day one. It
makes **no** network calls and writes **no** files — consistent with the spec's
offline-by-default, stateless trust properties.
"""

from __future__ import annotations

import argparse

from . import __version__
from .domain import Report, Severity


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcpscan",
        description=(
            "Local-first, offline-by-default security posture scanner for MCP / local-agent setups."
        ),
    )
    parser.add_argument("--version", action="version", version=f"mcpscan {__version__}")
    parser.add_argument(
        "command",
        nargs="?",
        default=None,
        choices=["scan"],
        help="The action to run (only 'scan' is planned for the MVP).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code.

    Until the engine lands, this reports that the build is pending rather than
    pretending to scan — failing closed instead of returning a false 'clean'.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # args.command == "scan"
    from .engine import scan

    report = scan()
    _print_summary(report)
    # Exit non-zero if any finding is at/above the threshold (CI-friendly).
    has_serious = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for s in report.servers for f in s.findings
    )
    return 1 if has_serious else 0


def _print_summary(report: Report) -> None:
    """Concise terminal summary. Rich terminal/HTML/JSON renderers land in Sprint 3."""
    print(f"AI Agentic MCPscan — overall posture: {report.overall_grade}")
    findings = [(s, f) for s in report.servers for f in s.findings]
    if not findings:
        print("No findings. (Note: rich reporting arrives in Sprint 3.)")
        return
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    for server, finding in sorted(findings, key=lambda sf: order[sf[1].severity]):
        loc = finding.location.path
        if finding.location.line is not None:
            loc = f"{loc}:{finding.location.line}"
        print(f"  [{finding.severity.value.upper():8}] {finding.title}  ({loc})")
        print(f"             fix: {finding.remediation}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
