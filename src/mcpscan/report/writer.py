# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Safe report writing (ticket T-305, FR-R6).

The only place the tool writes to disk. Files are created with owner-only
permissions where the OS supports it, so a report containing findings is not
left world-readable.
"""

from __future__ import annotations

import os
from pathlib import Path


def write_report(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` with owner-only (0600) permissions.

    On POSIX the file is opened with mode 0o600 from the start (no brief window
    where it is world-readable). On platforms without POSIX permissions the
    chmod is best-effort.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    finally:
        # Ensure perms even if the file pre-existed with looser bits.
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - non-POSIX best effort
            pass
