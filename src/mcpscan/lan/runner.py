# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""LAN assessment orchestration (LAN proposal §3).

The single entry point that turns an authorization manifest into an exposure
:class:`~mcpscan.domain.Report` — but only after every gate passes, in order:
parse → expiry → **signature** → scope/budget → probe. Any failure returns a
:class:`LanRefusal` and **no packet is sent**. Every side-effecting dependency
(clock, verifier, prober, sleep, abort switch) is injected, so the whole flow is
deterministic and network-free under test.

Exposure-only: a remotely-reachable MCP endpoint becomes a HIGH finding; we never
read a remote config, and remote response bytes never enter a finding's text
(they live only in the sanitized audit results).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..domain import Dimension, Finding, Location, Report, Server, ServerState, Severity
from ..scoring import dimension_grades, grade_findings, worst_grade
from .audit import AuditRecord, build_audit_record
from .budgets import Invoker, budgets_for_invoker
from .manifest import ManifestError, load_manifest
from .probe import Prober, ProbeResult, tcp_probe
from .scope import ScopeError, resolve_scope
from .verify import Verifier, verify_manifest

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class LanRefusal:
    """A run that a gate refused. No probe was performed."""

    reason: str


@dataclass(frozen=True)
class LanOutcome:
    """A completed (or dry-run) LAN assessment."""

    report: Report
    audit: AuditRecord
    dry_run: bool
    plan_hosts: tuple[str, ...]
    plan_ports: tuple[int, ...]


def _exposed_server(result: ProbeResult) -> Server:
    finding = Finding(
        id="LAN-EXPOSED",
        dimension=Dimension.EXPOSURE,
        severity=Severity.HIGH,
        title=f"MCP server reachable across the network at {result.host}:{result.port}",
        location=Location(path=f"{result.host}:{result.port}"),
        remediation=(
            "Bind the server to 127.0.0.1 (loopback), or place it behind "
            "authenticated network controls. Do not expose MCP tools to the LAN."
        ),
        rationale=(
            "A remotely reachable MCP endpoint exposes its tools to other hosts, "
            "often without authentication."
        ),
    )
    return Server(
        id=f"lan://{result.host}:{result.port}",
        bind_addr=result.host,
        port=result.port,
        pid=None,
        proc_name=None,
        state=ServerState.RUNNING,
        running=True,
        findings=(finding,),
    )


def _assemble(servers: Sequence[Server]) -> Report:
    all_findings = [f for s in servers for f in s.findings]
    return Report(
        schema_version=SCHEMA_VERSION,
        servers=tuple(servers),
        overall_grade=worst_grade([grade_findings(s.findings) for s in servers]),
        dimension_grades=dimension_grades(all_findings),
    )


def run_lan(
    *,
    manifest_bytes: bytes,
    now: datetime,
    invoker: Invoker,
    tool_version: str,
    argv: Sequence[str],
    signature_path: Path | None = None,
    allowed_signers: Path | None = None,
    allow_public: bool = False,
    dry_run: bool = False,
    probe_timeout: float = 1.5,
    verifier: Verifier | None = None,
    prober: Prober | None = None,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    should_abort: Callable[[], bool] | None = None,
) -> LanOutcome | LanRefusal:
    """Run one authorized LAN assessment, or refuse. No packet on any refusal."""
    manifest = load_manifest(manifest_bytes)
    if isinstance(manifest, ManifestError):
        return LanRefusal(f"invalid manifest: {manifest.message}")
    if manifest.is_expired(now):
        return LanRefusal(f"manifest expired at {manifest.expires_at.isoformat()}")

    verified = verify_manifest(
        scheme=manifest.signature_scheme,
        manifest_bytes=manifest_bytes,
        signature_path=signature_path,
        allowed_signers=allowed_signers,
        operator=manifest.operator,
        verifier=verifier,
    )
    if not verified.ok:
        return LanRefusal(verified.detail)

    budgets = budgets_for_invoker(invoker)
    scope = resolve_scope(manifest, invoker, budgets, allow_public=allow_public)
    if isinstance(scope, ScopeError):
        return LanRefusal(scope.message)

    timestamp = now.isoformat()
    if dry_run:
        return LanOutcome(
            report=_assemble([]),
            audit=build_audit_record(
                manifest=manifest,
                invoker=invoker,
                tool_version=tool_version,
                utc_timestamp=timestamp,
                argv=argv,
                resolved_targets=scope.hosts,
                results={"dry_run": True},
            ),
            dry_run=True,
            plan_hosts=scope.hosts,
            plan_ports=scope.ports,
        )

    do_probe = prober or tcp_probe
    do_sleep = sleep if sleep is not None else time.sleep
    clock = monotonic if monotonic is not None else time.monotonic
    aborted = should_abort or (lambda: False)

    started = clock()
    servers: list[Server] = []
    results: dict[str, object] = {}
    connections = 0
    stop = False
    for host in scope.hosts:
        if stop:
            break
        for port in scope.ports:
            over_budget = aborted() or connections >= budgets.max_total_connections
            past_deadline = clock() - started > budgets.max_runtime_s
            if over_budget or past_deadline:
                stop = True  # abort/budget/deadline -> halt the whole run
                break
            result = do_probe(host, port, probe_timeout)
            connections += 1
            results[f"{host}:{port}"] = {
                "reachable": result.reachable,
                "looks_like_mcp": result.looks_like_mcp,
                "evidence": result.evidence,
            }
            if result.reachable and result.looks_like_mcp:
                servers.append(_exposed_server(result))
            do_sleep(budgets.per_target_cooldown_s)  # non-aggressive pacing (always > 0)

    return LanOutcome(
        report=_assemble(servers),
        audit=build_audit_record(
            manifest=manifest,
            invoker=invoker,
            tool_version=tool_version,
            utc_timestamp=timestamp,
            argv=argv,
            resolved_targets=scope.hosts,
            results=results,
        ),
        dry_run=False,
        plan_hosts=scope.hosts,
        plan_ports=scope.ports,
    )
