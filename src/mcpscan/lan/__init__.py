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
from .scope import ScopeError, resolve_scope

__all__ = [
    "Budgets",
    "Manifest",
    "ManifestError",
    "ScopeError",
    "budgets_for_invoker",
    "load_manifest",
    "resolve_scope",
]
