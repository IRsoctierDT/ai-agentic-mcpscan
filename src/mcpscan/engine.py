"""Scan pipeline: discover → audit → score → assemble Report (Sprint 2 wiring).

Orchestrates the pure checks and the I/O edges into a single deterministic
``Report``. All file reads go through ``io_safe``; the only network touched here
is the loopback probe (and only when ``probe=True``). No file is ever written.
"""

from __future__ import annotations

import os
import platform
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePath

from .adapters.base import ParsedConfig
from .adapters.claude import ClaudeAdapter
from .adapters.paths import project_config_candidates
from .checks import EnvFile, parse_env_text
from .checks.exposure import check_socket_exposure
from .checks.pinning import check_server_pinning
from .checks.secrets import (
    check_env_file_secrets,
    check_secret_at_rest,
    check_server_env,
)
from .checks.tool_scope import (
    check_permissions,
    check_server_auto_approve,
)
from .discovery.sockets import EnumerationResult, enumerate_listening
from .domain import Finding, Report, Server, ServerState
from .io_safe import SafeReadError, safe_read_text
from .scoring import dimension_grades, grade_findings, worst_grade

SCHEMA_VERSION = "1.0"


def _audit_config(cfg: ParsedConfig) -> list[Server]:
    servers: list[Server] = []
    for decl in cfg.servers:
        findings: list[Finding] = []
        findings += check_server_env(decl, cfg.path)
        findings += check_server_auto_approve(decl, cfg.path)
        findings += check_server_pinning(decl, cfg.path)
        servers.append(
            Server(
                id=f"{cfg.path}#{decl.name}",
                bind_addr=None,
                port=None,
                pid=None,
                proc_name=None,
                state=ServerState.DECLARED,
                running=False,
                findings=tuple(findings),
            )
        )

    # Config-level permission grants (not tied to one server).
    perm_findings = check_permissions(cfg.allow_permissions, cfg.path)
    if perm_findings:
        servers.append(
            Server(
                id=f"{cfg.path}#permissions",
                bind_addr=None,
                port=None,
                pid=None,
                proc_name=None,
                state=ServerState.DECLARED,
                running=False,
                findings=tuple(perm_findings),
            )
        )
    return servers


def _audit_env_file(env_file: EnvFile) -> Server:
    findings = check_env_file_secrets(env_file) + check_secret_at_rest(env_file)
    return Server(
        id=env_file.path,
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=tuple(findings),
    )


def _server_from_socket(
    result_incomplete: bool,
    sock_ip: str,
    sock_port: int,
    pid: int | None,
    proc: str | None,
    findings: Sequence[Finding],
) -> Server:
    return Server(
        id=f"socket://{sock_ip}:{sock_port}",
        bind_addr=sock_ip,
        port=sock_port,
        pid=pid,
        proc_name=proc,
        state=ServerState.RUNNING,
        running=True,
        inspection_incomplete=result_incomplete,
        findings=tuple(findings),
    )


def _read_config_file(path: Path) -> str | None:
    try:
        return safe_read_text(path, root=path.parent)
    except SafeReadError:
        return None


def scan(
    *,
    roots: Sequence[Path] | None = None,
    system: str | None = None,
    env: Mapping[str, str] | None = None,
    enumerate_sockets: bool = True,
) -> Report:
    """Run a full localhost scan and return a deterministic Report.

    Args:
        roots: Project roots to scan for ``.mcp.json`` / ``.env`` (defaults to cwd).
        system: ``platform.system()`` override (for testing).
        env: Environment mapping override (for testing).
        enumerate_sockets: When False, skips psutil enumeration (used in tests).
    """
    system = system or platform.system()
    env = env if env is not None else os.environ
    roots = list(roots) if roots is not None else [Path.cwd()]

    adapter = ClaudeAdapter()
    servers: list[Server] = []

    # --- config discovery + audit ---
    candidate_paths: list[PurePath] = list(adapter.default_config_paths(system, env))
    project_paths: list[Path] = []
    for root in roots:
        project_paths.extend(project_config_candidates(root))

    for cand in candidate_paths:
        path = Path(str(cand))
        if path.name == ".env":
            continue
        raw = _read_config_file(path)
        if raw is None:
            continue
        servers.extend(_audit_config(adapter.parse(str(path), raw)))

    for path in project_paths:
        if not path.exists():
            continue
        raw = _read_config_file(path)
        if raw is None:
            continue
        if path.name == ".env":
            mode = stat.S_IMODE(path.stat().st_mode)
            servers.append(_audit_env_file(parse_env_text(str(path), raw, mode=mode)))
        else:
            servers.extend(_audit_config(adapter.parse(str(path), raw)))

    # --- running-server discovery + exposure ---
    if enumerate_sockets:
        result: EnumerationResult = enumerate_listening()
        for sock in result.sockets:
            exposure = check_socket_exposure(sock)
            if exposure:  # only surface sockets that are actually exposed
                servers.append(
                    _server_from_socket(
                        result.inspection_incomplete,
                        sock.ip,
                        sock.port,
                        sock.pid,
                        sock.proc_name,
                        exposure,
                    )
                )

    return _assemble_report(servers)


def _assemble_report(servers: Sequence[Server]) -> Report:
    all_findings = [f for s in servers for f in s.findings]
    server_grades = [grade_findings(s.findings) for s in servers]
    return Report(
        schema_version=SCHEMA_VERSION,
        servers=tuple(servers),
        overall_grade=worst_grade(server_grades),
        dimension_grades=dimension_grades(all_findings),
        generated_with_online=False,
    )
