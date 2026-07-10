# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Scope resolution for LAN assessment (LAN proposal §2, §3.2, §3.3).

Turns a manifest's raw target strings into a concrete, bounded list of hosts to
probe — or a :class:`ScopeError`. Enforces the trust constraints:

- **Private-address default.** Every resolved host must be private (RFC-1918 /
  RFC-4193 / loopback / link-local) unless ``allow_public`` is explicitly set (an
  enterprise-policy path, not a plain flag).
- **Invoker gating.** ``agent`` invocations get exact hosts / ``/32`` only; a
  ``human`` may supply an explicit, budget-capped CIDR.
- **No implicit expansion.** A bare IP is exactly one host. Only an
  explicitly-typed ``/NN`` (narrower than a full host) expands, and only within
  the immutable host budget.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .budgets import Budgets, Invoker
from .manifest import Manifest

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class ScopeError:
    """A target set that violates a scope constraint."""

    message: str


@dataclass(frozen=True)
class ResolvedScope:
    """The concrete, budget-checked hosts and ports to probe."""

    hosts: tuple[str, ...]
    ports: tuple[int, ...]


def _as_network(target: str) -> IPNetwork | ScopeError:
    try:
        # strict=False tolerates host bits; we classify width via prefixlen below.
        return ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        return ScopeError(f"invalid target {target!r}: {exc}")


def resolve_scope(
    manifest: Manifest,
    invoker: Invoker,
    budgets: Budgets,
    *,
    allow_public: bool = False,
) -> ResolvedScope | ScopeError:
    """Resolve manifest targets to concrete hosts, enforcing all scope rules."""
    ports = manifest.ports
    if len(ports) > budgets.max_ports_per_host:
        return ScopeError(
            f"{len(ports)} ports exceeds the per-host budget of {budgets.max_ports_per_host}"
        )

    hosts: list[str] = []
    seen: set[str] = set()
    for target in manifest.targets:
        net = _as_network(target)
        if isinstance(net, ScopeError):
            return net

        is_single = net.prefixlen == net.max_prefixlen
        if not is_single and invoker == "agent":
            return ScopeError(
                f"agent invocation may not use CIDR ranges (target {target!r}); supply exact hosts"
            )

        # Private-address default: refuse anything routable unless explicitly allowed.
        if not allow_public and not net.is_private:
            return ScopeError(
                f"refusing non-private target {target!r}: public addresses require an "
                "enterprise policy, not a flag"
            )

        expanded = [str(net.network_address)] if is_single else [str(h) for h in net.hosts()]
        if not expanded:
            return ScopeError(f"target {target!r} contains no usable hosts")
        for host in expanded:
            if host not in seen:
                seen.add(host)
                hosts.append(host)
            if len(hosts) > budgets.max_hosts:
                return ScopeError(
                    f"targets expand to more than the host budget of {budgets.max_hosts}"
                )

    if not hosts:
        return ScopeError("no targets resolved")
    if len(hosts) * len(ports) > budgets.max_total_connections:
        return ScopeError(
            f"{len(hosts)}×{len(ports)} probes exceeds the connection budget of "
            f"{budgets.max_total_connections}"
        )
    return ResolvedScope(hosts=tuple(hosts), ports=ports)
