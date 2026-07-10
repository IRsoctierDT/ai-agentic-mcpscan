# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Hostile-by-default handling of remote responses (LAN proposal §3.5).

Every byte a remote host returns is untrusted adversarial input — MCP research
flags prompt injection, tool poisoning, and capability misrepresentation. Nothing
remote reaches a report or (especially) an LLM/agent context raw. This module
normalizes any remote string to an inert, clearly-labelled form: ANSI/control
sequences stripped, non-UTF-8 replaced, whitespace collapsed, length-capped, and
prefixed so it can never be mistaken for tool output or an instruction.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_LABEL = "[untrusted remote data]"


def sanitize_remote(raw: bytes | str, *, max_len: int = 200) -> str:
    """Return an inert, labelled, length-capped rendering of remote bytes.

    A prompt-injection payload survives only as plain, labelled text — it is
    never interpreted, interpolated into remediation prose, or fed to a model.
    """
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = _ANSI.sub("", text)
    # Replace C0/C1 control characters and DEL with a space, keep printable text.
    text = "".join(ch if (ch >= " " and ch != "\x7f") else " " for ch in text)
    text = " ".join(text.split())  # collapse runs of whitespace
    if not text:
        return f"{_LABEL} (empty)"
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return f"{_LABEL} {text}"
