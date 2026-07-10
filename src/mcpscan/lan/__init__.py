# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Authorized-LAN assessment (``mcpscan lan``) — Phase A safety core.

This package is the authorization and safety machinery for LAN exposure
assessment, per ``docs/proposals/LAN_SCANNING.md``. **Governing principle:**
*discovery never converts into authority.* The feature is inert without a valid,
signed authorization manifest and is exposure-only.

Phase A (this slice) is the pure, network-free core: manifest parsing
(:mod:`.manifest`), scope resolution (:mod:`.scope`), immutable operational
budgets (:mod:`.budgets`), hostile-response sanitization (:mod:`.sanitize`), and
the run audit record (:mod:`.audit`). Signature verification, the CLI
subcommand, and the actual network probe are wired in a follow-up on top of this
verified core.
"""

from __future__ import annotations

from .budgets import Budgets, budgets_for_invoker
from .manifest import Manifest, ManifestError, load_manifest
from .runner import LanOutcome, LanRefusal, run_lan
from .scope import ScopeError, resolve_scope
from .verify import VerifyResult, verify_manifest

__all__ = [
    "Budgets",
    "LanOutcome",
    "LanRefusal",
    "Manifest",
    "ManifestError",
    "ScopeError",
    "VerifyResult",
    "budgets_for_invoker",
    "load_manifest",
    "resolve_scope",
    "run_lan",
    "verify_manifest",
]
