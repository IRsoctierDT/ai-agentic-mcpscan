# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Enterprise policy for public LAN targets (LAN proposal §2, §3.6).

Public (routable) addresses are refused by default — and, per the proposal, only
an **enterprise policy file** may lift that, *not a mere flag*. The policy is a
signed-in-spirit TOML file (stdlib ``tomllib``) that names the exact public
targets an organization has authorized. Scope resolution then permits a public
target only when it is covered by this allow-list. Never raises: malformed input
returns a :class:`PolicyError`.
"""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass


@dataclass(frozen=True)
class EnterprisePolicy:
    """The set of public targets an organization has explicitly authorized."""

    public_targets: tuple[str, ...]


@dataclass(frozen=True)
class PolicyError:
    """A policy file that could not be parsed or failed validation."""

    message: str


def load_policy(raw: bytes) -> EnterprisePolicy | PolicyError:
    """Parse and validate an enterprise policy file into an allow-list or error."""
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return PolicyError(f"invalid policy TOML: {exc}")

    targets = data.get("public_targets")
    if not isinstance(targets, list) or not targets:
        return PolicyError("policy field 'public_targets' must be a non-empty array")
    if not all(isinstance(t, str) and t.strip() for t in targets):
        return PolicyError("every entry in 'public_targets' must be a non-empty string")
    for target in targets:
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            return PolicyError(f"invalid public target {target!r}: {exc}")
    return EnterprisePolicy(public_targets=tuple(str(t) for t in targets))
