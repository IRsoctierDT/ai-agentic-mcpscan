# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Framework atlas (VISION Tier 2): findings mapped to security frameworks.

Public surface: the mapping table plus its render functions. The atlas adds
citations to what ``scan`` finds; it discovers nothing and judges nothing new.
"""

from .model import MAPPINGS, Framework, FrameworkRef, framework_label, refs_for

__all__ = [
    "MAPPINGS",
    "Framework",
    "FrameworkRef",
    "framework_label",
    "refs_for",
]
