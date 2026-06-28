"""Guard: the package version must match pyproject.toml (T-407 release safety).

The release workflow (.github/workflows/release.yml) verifies the git *tag*
matches ``[project].version`` in pyproject.toml, but nothing checks that
``mcpscan.__version__`` agrees. If the two drift, we'd publish a wheel whose
``mcpscan --version`` lies. This test fails fast on that drift so it can't ship.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import mcpscan

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _pyproject_version() -> str:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_package_version_matches_pyproject() -> None:
    assert mcpscan.__version__ == _pyproject_version(), (
        f"mcpscan.__version__ ({mcpscan.__version__}) != "
        f"pyproject [project].version ({_pyproject_version()}); "
        "keep src/mcpscan/__init__.py and pyproject.toml in sync (see docs/RELEASING.md)."
    )
