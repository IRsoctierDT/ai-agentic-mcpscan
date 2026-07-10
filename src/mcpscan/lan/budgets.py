# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Immutable operational budgets for LAN assessment (LAN proposal §3.4).

Ceilings are *structural*, not advisory: a caller may lower a value but never
raise it past the compiled ceiling. ``agent`` invocations get strictly tighter
ceilings than ``human`` ones, so an autonomous caller always has less reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Invoker = Literal["human", "agent"]


@dataclass(frozen=True)
class Budgets:
    """A resolved set of operational ceilings for one run."""

    max_hosts: int
    max_ports_per_host: int
    max_concurrency: int
    max_total_connections: int
    max_runtime_s: float
    per_target_cooldown_s: float

    def lowered(self, **overrides: float) -> Budgets:
        """Return a copy with the given fields lowered.

        Raising a ceiling is refused — a value above the current ceiling is
        clamped down to it, never applied. This is what makes the ceiling
        immutable: callers can be more conservative, never less.
        """
        current = {
            "max_hosts": self.max_hosts,
            "max_ports_per_host": self.max_ports_per_host,
            "max_concurrency": self.max_concurrency,
            "max_total_connections": self.max_total_connections,
            "max_runtime_s": self.max_runtime_s,
            "per_target_cooldown_s": self.per_target_cooldown_s,
        }
        for key, value in overrides.items():
            if key not in current:
                raise KeyError(f"unknown budget: {key}")
            if key == "per_target_cooldown_s":
                # A longer cooldown is *more* conservative — allow raising it only.
                current[key] = max(current[key], value)
            else:
                current[key] = min(current[key], value)
        return Budgets(**current)  # type: ignore[arg-type]


# Compiled ceilings. `human` is the maximum any run may reach; `agent` is tighter.
# `max_total_connections` is deliberately set BELOW max_hosts × max_ports_per_host
# so it is an independent ceiling on total probe volume, not a redundant one — a
# wide-but-shallow or narrow-but-deep run can still be capped on aggregate work.
_HUMAN_CEILING = Budgets(
    max_hosts=256,
    max_ports_per_host=16,
    max_concurrency=16,
    max_total_connections=2048,  # < 256 × 16
    max_runtime_s=300.0,
    per_target_cooldown_s=0.05,
)
_AGENT_CEILING = Budgets(
    max_hosts=16,
    max_ports_per_host=8,
    max_concurrency=4,
    max_total_connections=64,  # < 16 × 8
    max_runtime_s=60.0,
    per_target_cooldown_s=0.25,
)


def budgets_for_invoker(invoker: Invoker) -> Budgets:
    """Return the immutable ceiling budgets for the given invoker mode."""
    return _AGENT_CEILING if invoker == "agent" else _HUMAN_CEILING
