# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Minimal JSONC (JSON-with-comments) support for editor config files.

VS Code (`mcp.json`) and Zed (`settings.json`) accept ``//`` line comments,
``/* */`` block comments, and trailing commas. Python's ``json`` rejects all
three, so these editors' real configs would otherwise fail to parse. This module
strips comments and trailing commas in a **string-aware** single pass per concern
(so a ``//`` or ``,}`` *inside* a JSON string is never touched), then leaves the
actual JSON decoding to the stdlib.

No third-party dependency — a hand-rolled scanner keeps the tool stdlib-only.
"""

from __future__ import annotations

import json


def _strip_comments(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:  # copy the escaped char verbatim
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":  # line comment
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":  # block comment
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
            continue
        if c in ('"', "'"):
            in_str = True
            quote = c
            out.append(c)
            i += 1
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":  # trailing comma before a close -> drop
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_jsonc(text: str) -> str:
    """Return ``text`` with JSONC comments and trailing commas removed."""
    return _drop_trailing_commas(_strip_comments(text))


def loads_jsonc(text: str) -> object:
    """Parse JSONC text into Python objects.

    Comments/trailing commas are stripped first, then ``json.loads`` decodes the
    result — so a malformed document still raises ``json.JSONDecodeError`` exactly
    as callers expect.
    """
    return json.loads(strip_jsonc(text))
