"""Unit tests for the CLI scaffold (fails closed until the engine lands)."""

from __future__ import annotations

import pytest

from mcpscan.cli import main


def test_no_command_prints_help_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main([])
    assert rc == 0
    assert "mcpscan" in capsys.readouterr().out


def test_scan_fails_closed_until_implemented() -> None:
    # Must NOT return a false 'clean' (rc 0) while the engine is unimplemented.
    assert main(["scan"]) == 2
