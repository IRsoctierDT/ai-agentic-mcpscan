# Copyright 2026 IRsoctierDT
# SPDX-License-Identifier: Apache-2.0
"""Claude-ecosystem host adapter (ticket T-205, first HostAdapter impl).

Parses the ``mcpServers`` mapping and permission allow-lists from Claude Code
settings, project ``.mcp.json``, and Claude Desktop config. Never raises on bad
input — malformed JSON becomes a ``ParsedConfig`` with ``parse_error`` set.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import PurePath

from .base import HostAdapter, ParsedConfig, ServerDecl
from .paths import claude_config_candidates


def _coerce_args(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def _coerce_env(value: object) -> tuple[tuple[str, str], ...]:
    if isinstance(value, dict):
        return tuple((str(k), str(v)) for k, v in value.items())
    return ()


def _coerce_str_list(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


class ClaudeAdapter(HostAdapter):
    """Adapter for Claude Code / Claude Desktop config files."""

    name = "claude"

    def default_config_paths(self, system: str, env: Mapping[str, str]) -> list[PurePath]:
        return claude_config_candidates(system, env)

    def parse(self, path: str, raw: str) -> ParsedConfig:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            return ParsedConfig(path=path, parse_error=f"invalid JSON: {exc}")

        if not isinstance(data, dict):
            return ParsedConfig(path=path, parse_error="config root is not an object")

        servers: list[ServerDecl] = []
        mcp_servers = data.get("mcpServers")
        if isinstance(mcp_servers, dict):
            for name, spec in mcp_servers.items():
                if not isinstance(spec, dict):
                    continue
                command = spec.get("command")
                servers.append(
                    ServerDecl(
                        name=str(name),
                        command=str(command) if command is not None else None,
                        args=_coerce_args(spec.get("args")),
                        env=_coerce_env(spec.get("env")),
                        auto_approve=_coerce_str_list(spec.get("autoApprove")),
                    )
                )

        allow: tuple[str, ...] = ()
        permissions = data.get("permissions")
        if isinstance(permissions, dict):
            allow = _coerce_str_list(permissions.get("allow"))

        return ParsedConfig(
            path=path,
            servers=tuple(servers),
            allow_permissions=allow,
        )
