# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Host adapters — the pluggable seam for supporting different MCP hosts.

Claude is the first implementation (ADR-4). Adding a host adapter must require no
change to the engine core.
"""
