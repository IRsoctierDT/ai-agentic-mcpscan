"""Online enrichment + offline-isolation guarantees (T-401, NFR-SEC1, R2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path


from mcpscan.checks.pinning import PackageSpec, parse_package_spec
from mcpscan.enrichment.osv import OsvVuln, parse_osv_response
from mcpscan.engine import scan

PINNED_CONFIG = {
    "mcpServers": {
        "svc": {"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]},
    }
}


# --- pure spec parsing ---
def test_parse_npm_spec() -> None:
    assert parse_package_spec("npx", ("-y", "pkg@1.2.3")) == PackageSpec("npm", "pkg", "1.2.3")


def test_parse_pypi_spec() -> None:
    assert parse_package_spec("uvx", ("tool==2.0.0",)) == PackageSpec("PyPI", "tool", "2.0.0")


def test_unpinned_spec_returns_none() -> None:
    # No concrete version -> nothing is ever sent online.
    assert parse_package_spec("npx", ("-y", "pkg")) is None


# --- pure OSV parsing ---
def test_parse_osv_response() -> None:
    data = {
        "vulns": [
            {"id": "GHSA-xxxx"},
            {"id": "CVE-1", "database_specific": {"severity": "CRITICAL"}},
        ]
    }
    vulns = parse_osv_response(data)
    assert [v.id for v in vulns] == ["GHSA-xxxx", "CVE-1"]
    assert vulns[1].critical is True


def test_parse_osv_empty() -> None:
    assert parse_osv_response({}) == []
    assert parse_osv_response("nonsense") == []


# --- engine integration via injected fetch (no real network) ---
def test_online_adds_known_vuln_finding(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")

    def fake_fetch(name: str, version: str, ecosystem: str) -> tuple[tuple[str, ...], bool]:
        assert (name, version, ecosystem) == ("some-mcp-server", "1.2.3", "npm")
        return (("GHSA-demo",), False)

    report = scan(
        roots=[tmp_path],
        system="Linux",
        env={},
        enumerate_sockets=False,
        online=True,
        osv_fetch=fake_fetch,
    )
    ids = {f.id for s in report.servers for f in s.findings}
    assert "PIN-KNOWN-VULN" in ids
    assert report.generated_with_online is True


def test_offline_default_does_not_import_egress_module(tmp_path: Path) -> None:
    # NFR-SEC1 / R2: a default scan must not even load the egress module.
    sys.modules.pop("mcpscan.enrichment.osv", None)
    (tmp_path / ".mcp.json").write_text(json.dumps(PINNED_CONFIG), encoding="utf-8")
    report = scan(roots=[tmp_path], system="Linux", env={}, enumerate_sockets=False)
    assert "mcpscan.enrichment.osv" not in sys.modules
    assert report.generated_with_online is False


def test_osv_vuln_dataclass() -> None:
    assert OsvVuln(id="X", critical=False).id == "X"
