"""Online enrichment + offline-isolation guarantees (T-401, NFR-SEC1, R2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcpscan.checks.pinning import PackageSpec, parse_package_spec
from mcpscan.enrichment import osv as osv_mod
from mcpscan.enrichment.osv import OsvVuln, parse_osv_response, query_osv
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


def test_parse_osv_skips_non_dict_entries() -> None:
    # A malformed (non-dict) entry in the vulns list is skipped, not fatal.
    data = {"vulns": ["not-a-dict", {"id": "CVE-9"}]}
    assert [v.id for v in parse_osv_response(data)] == ["CVE-9"]


def test_is_critical_via_cvss_9x_vector() -> None:
    # No explicit "CRITICAL" label, but a 9.x CVSS vector -> treated as critical.
    data = {
        "vulns": [{"id": "CVE-X", "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8"}]
    }
    assert parse_osv_response(data)[0].critical is True


# --- query_osv egress: exercised via injected urlopen, never the live service ---
class _FakeHttpResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def test_query_osv_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"vulns": [{"id": "GHSA-net"}]}).encode("utf-8")
    monkeypatch.setattr(osv_mod.urllib.request, "urlopen", lambda *a, **k: _FakeHttpResponse(body))
    assert [v.id for v in query_osv("pkg", "1.0.0", "PyPI")] == ["GHSA-net"]


def test_query_osv_is_failsafe_on_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError("network down")

    monkeypatch.setattr(osv_mod.urllib.request, "urlopen", boom)
    assert query_osv("pkg", "1.0.0", "PyPI") == []


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
