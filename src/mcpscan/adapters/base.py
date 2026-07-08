# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Host-adapter interface and parsed-config types (ticket T-205).

The ``HostAdapter`` ABC is the pluggable seam (ADR-4): adding support for another
MCP host (Cursor, Cline, …) means adding an adapter, with no change to the engine
or checks. Parsed types are frozen so the audit operates on immutable data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath


@dataclass(frozen=True)
class ServerDecl:
    """An MCP server declared in a host config file."""

    name: str
    command: str | None
    args: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()  # frozen (key, value) pairs
    auto_approve: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedConfig:
    """The audit-relevant content extracted from one host config file."""

    path: str
    servers: tuple[ServerDecl, ...] = ()
    allow_permissions: tuple[str, ...] = ()
    parse_error: str | None = None
    extra: Mapping[str, object] = field(default_factory=dict)


def coerce_args(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def coerce_env(value: object) -> tuple[tuple[str, str], ...]:
    if isinstance(value, dict):
        return tuple((str(k), str(v)) for k, v in value.items())
    return ()


def coerce_str_list(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def parse_mcp_servers(data: object) -> tuple[ServerDecl, ...]:
    """Extract ``ServerDecl``s from a parsed config's ``mcpServers`` mapping.

    Shared by every host adapter: the ``mcpServers`` shape (``command``/``args``/
    ``env``/``autoApprove`` per named server) is common to Claude, Cursor, and
    other MCP hosts.
    """
    servers: list[ServerDecl] = []
    mcp_servers = data.get("mcpServers") if isinstance(data, dict) else None
    if isinstance(mcp_servers, dict):
        for name, spec in mcp_servers.items():
            if not isinstance(spec, dict):
                continue
            command = spec.get("command")
            servers.append(
                ServerDecl(
                    name=str(name),
                    command=str(command) if command is not None else None,
                    args=coerce_args(spec.get("args")),
                    env=coerce_env(spec.get("env")),
                    auto_approve=coerce_str_list(spec.get("autoApprove")),
                )
            )
    return tuple(servers)


class HostAdapter(ABC):
    """Base class for host-specific config discovery and parsing."""

    name: str

    @abstractmethod
    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        """Return candidate user-level config paths for this host on the given OS."""

    def project_config_paths(self, project_root: Path) -> list[Path]:
        """Return project-scoped config paths this host uses under a project root.

        Default: none. Hosts with a per-project config (Claude's ``.mcp.json``,
        Cursor's ``.cursor/mcp.json``) override this.
        """
        return []

    @abstractmethod
    def parse(self, path: str, raw: str) -> ParsedConfig:
        """Parse raw config text into a :class:`ParsedConfig`.

        Implementations must never raise on malformed input — they return a
        ``ParsedConfig`` with ``parse_error`` set instead (NFR-S3).
        """
