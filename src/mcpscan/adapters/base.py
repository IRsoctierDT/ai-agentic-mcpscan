"""Host-adapter interface and parsed-config types (ticket T-205).

The ``HostAdapter`` ABC is the pluggable seam (ADR-4): adding support for another
MCP host (Cursor, Cline, …) means adding an adapter, with no change to the engine
or checks. Parsed types are frozen so the audit operates on immutable data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePath


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


class HostAdapter(ABC):
    """Base class for host-specific config discovery and parsing."""

    name: str

    @abstractmethod
    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        """Return candidate config paths for this host on the given OS."""

    @abstractmethod
    def parse(self, path: str, raw: str) -> ParsedConfig:
        """Parse raw config text into a :class:`ParsedConfig`.

        Implementations must never raise on malformed input — they return a
        ``ParsedConfig`` with ``parse_error`` set instead (NFR-S3).
        """
