# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""AI/MCP asset inventory (VISION Tier 1): discover and classify what exists.

Public surface: :func:`collect_inventory` plus the frozen model types. The
inventory observes and names AI infrastructure — it renders no judgment; posture
stays in ``scan``.
"""

from .collect import collect_inventory
from .model import Asset, AssetKind, AssetSource, Confidence, Inventory

__all__ = [
    "Asset",
    "AssetKind",
    "AssetSource",
    "Confidence",
    "Inventory",
    "collect_inventory",
]
