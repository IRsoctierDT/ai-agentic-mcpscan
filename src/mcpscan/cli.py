# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for AI Agentic MCPscan (``mcpscan``).

Wires the scan engine to the renderers. Honors the spec's trust properties:
offline by default, secrets redacted unless ``--show-secrets``, and — advise-only
by default — the only file writes are the reports the user explicitly requests
(``--json`` / ``--html`` / ``--sarif``) plus the config edits of opt-in ``--fix``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .domain import Report, Severity

_THRESHOLDS = {
    "critical": (Severity.CRITICAL,),
    "high": (Severity.CRITICAL, Severity.HIGH),
    "medium": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM),
    "low": (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW),
}


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
        help="The action to run (only 'scan' is available in the MVP).",
    )
    parser.add_argument(
        "--root",
        action="append",
        type=Path,
        metavar="DIR",
        help="Project root to scan for .mcp.json/.env (repeatable; default: cwd).",
    )
    parser.add_argument("--json", metavar="PATH", type=Path, help="Write a JSON report.")
    parser.add_argument("--html", metavar="PATH", type=Path, help="Write an HTML report.")
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        type=Path,
        help="Write a SARIF 2.1.0 report for GitHub code scanning.",
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Reveal masked (first-2/last-2) secret values. Off by default.",
    )
    parser.add_argument(
        "--absolute-paths",
        action="store_true",
        help="Show full paths instead of relativizing to ~ (off by default).",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(_THRESHOLDS),
        default="high",
        help="Minimum severity that makes the command exit non-zero (default: high).",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help=(
            "Enrich pinned packages with OSV advisories. Makes outbound requests "
            "to api.osv.dev (sends only package name+version). Off by default."
        ),
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Apply safe, reversible remediations to discovered configs: remove "
            "dangerous/wildcard entries from permission allow-lists and autoApprove. "
            "Backs up each file to <path>.mcpscan.bak first. Off by default "
            "(the tool is advise-only unless you pass --fix)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # Imported lazily so the default/help path stays light and import-isolated.
    from .engine import scan
    from .report import RenderOptions
    from .report.html import render_html
    from .report.json_report import render_json
    from .report.sarif import render_sarif
    from .report.terminal import render_terminal
    from .report.writer import write_report

    if args.show_secrets:
        print(
            "warning: --show-secrets reveals masked secret values; keep the output private.",
            file=sys.stderr,
        )
    if args.online:
        print(
            "note: --online contacts api.osv.dev with package name+version only "
            "(no config contents, paths, or secrets).",
            file=sys.stderr,
        )

    report = scan(roots=args.root, online=args.online)
    opts = RenderOptions(
        show_secrets=args.show_secrets,
        absolute_paths=args.absolute_paths,
        home=str(Path.home()),
    )

    # Redaction-safe by construction: secrets are reduced to non-reversible
    # fingerprints at detection (redaction.fingerprint_secret) and never reach
    # the report raw. Default output shows only "[redacted len=N sha256:XX]";
    # --show-secrets reveals at most a first-2/last-2 masked preview and prints a
    # warning (see report.common.secret_str, docs/SECURITY_SIGNOFF.md, T-305).
    # CodeQL py/clear-text-logging-sensitive-data flags this sink because it
    # can't model that redaction boundary as a sanitizer — accepted, documented.
    print(render_terminal(report, opts), end="")
    if args.json is not None:
        write_report(args.json, render_json(report, opts))
        print(f"wrote JSON report: {args.json}", file=sys.stderr)
    if args.html is not None:
        write_report(args.html, render_html(report, opts))
        print(f"wrote HTML report: {args.html}", file=sys.stderr)
    if args.sarif is not None:
        # Relativize repo-local paths to cwd so GitHub code scanning can map them.
        write_report(args.sarif, render_sarif(report, opts, base=str(Path.cwd())))
        print(f"wrote SARIF report: {args.sarif}", file=sys.stderr)

    if args.fix:
        _apply_fixes(args.root, opts)

    return _exit_code(report, args.fail_on)


def _apply_fixes(roots: list[Path] | None, opts: object) -> None:
    """Apply safe tool-scope remediations to discovered configs (``--fix``).

    The single, explicit exception to advise-only: writes only when asked, backs
    each file up first, and touches only over-broad permission/autoApprove grants.
    """
    from .engine import discover_host_config_files
    from .fix import apply_fix_to_file, plan_config_fixes
    from .io_safe import SafeReadError, safe_read_text

    print(
        "note: --fix modifies config files in place (backup written to "
        "<path>.mcpscan.bak). Only over-broad tool-scope grants are removed; "
        "credential and pinning findings still need a manual fix.",
        file=sys.stderr,
    )

    total = 0
    for path in discover_host_config_files(roots=roots):
        try:
            raw = safe_read_text(path, root=path.parent)
        except SafeReadError:
            continue
        plan = plan_config_fixes(str(path), raw)
        if not plan.changed or plan.new_text is None:
            continue
        backup = apply_fix_to_file(path, plan.new_text)
        total += len(plan.fixes)
        print(f"fixed {path} ({len(plan.fixes)} change(s); backup: {backup})", file=sys.stderr)
        for fx in plan.fixes:
            print(f"    removed {fx.removed!r} from {fx.where} [{fx.rule_id}]", file=sys.stderr)

    if total == 0:
        print("no auto-fixable tool-scope findings.", file=sys.stderr)
    else:
        print(f"applied {total} fix(es). Re-run mcpscan to confirm.", file=sys.stderr)


def _exit_code(report: Report, fail_on: str) -> int:
    """Non-zero if any finding is at/above the configured threshold."""
    blocking = _THRESHOLDS[fail_on]
    has_blocking = any(f.severity in blocking for s in report.servers for f in s.findings)
    return 1 if has_blocking else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
