"""Command-line entry point for AI Agentic MCPscan (``mcpscan``).

Scaffold only. The ``scan`` behavior is implemented in the build sprints; this
module exists so the console script is wired and installable from day one. It
makes **no** network calls and writes **no** files — consistent with the spec's
offline-by-default, stateless trust properties.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__


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
    print(
        "AI Agentic MCPscan: the scanner engine is not yet implemented "
        "(specification complete; build pending — see docs/BACKLOG.md).",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
