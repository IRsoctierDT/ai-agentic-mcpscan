"""Version-pinning checks (ticket T-209).

Flags MCP servers launched from unpinned package specs (npx/uvx/pip), where a
floating version is a silent supply-chain risk.
"""

from __future__ import annotations

import re

from ..adapters.base import ServerDecl
from ..domain import Dimension, Finding, Location, Severity

_VERSIONED = re.compile(r"@\d|@latest|==|@[~^]?\d")
_LATEST = re.compile(r"@latest\b")
_FLOATING_RUNNERS = {"npx", "uvx", "pnpx", "bunx"}


def _package_args(args: tuple[str, ...]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


def check_server_pinning(server: ServerDecl, config_path: str) -> list[Finding]:
    """Flag an unpinned package runner command for a declared server."""
    command = (server.command or "").rsplit("/", 1)[-1]
    if command not in _FLOATING_RUNNERS:
        return []

    packages = _package_args(server.args)
    if not packages:
        return []

    pinned = any(_VERSIONED.search(a) and not _LATEST.search(a) for a in packages)
    uses_latest = any(_LATEST.search(a) for a in packages)

    if pinned and not uses_latest:
        return []

    title = (
        f"Server {server.name!r} pinned to a floating tag (@latest)"
        if uses_latest
        else f"Server {server.name!r} runs an unpinned package via {command}"
    )
    return [
        Finding(
            id="PIN-UNPINNED",
            dimension=Dimension.PINNING,
            severity=Severity.MEDIUM,
            title=title,
            location=Location(path=config_path),
            remediation=(
                f"Pin the package to an exact version (e.g. {command} "
                "some-pkg@1.2.3) so the running code can't change silently."
            ),
            rationale=(
                "An unpinned/floating package fetches new code on each run — a "
                "supply-chain and reproducibility risk."
            ),
        )
    ]
