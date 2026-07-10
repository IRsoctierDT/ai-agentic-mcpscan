"""Tier-5 drift: snapshot building, diff direction, baseline integrity, rendering."""

from __future__ import annotations

import json

import pytest

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)
from mcpscan.drift import (
    BaselineError,
    ChangeType,
    Direction,
    build_snapshot,
    diff_snapshots,
    load_baseline,
    render_baseline,
    snapshot_digest,
)
from mcpscan.drift.render import render_json_drift, render_terminal_drift


def _server(sid: str, *, bind: str | None = None, port: int | None = None) -> Server:
    return Server(
        id=sid,
        bind_addr=bind,
        port=port,
        pid=None,
        proc_name=None,
        state=ServerState.RUNNING if bind else ServerState.DECLARED,
        running=bind is not None,
        findings=(),
    )


def _finding(fid: str = "CRED-PLAINTEXT", sev: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        id=fid,
        dimension=Dimension.CREDENTIAL,
        severity=sev,
        title=f"{fid} title",
        location=Location(path="/cfg/.mcp.json", line=4),
        remediation="fix",
        rationale="why",
    )


def _report(*servers: Server) -> Report:
    return Report(
        schema_version="1.0", servers=tuple(servers), overall_grade="A", dimension_grades={}
    )


# --- snapshot building ---
def test_snapshot_is_deterministic_and_secretless() -> None:
    from mcpscan.redaction import fingerprint_secret

    finding = Finding(
        id="CRED-PLAINTEXT",
        dimension=Dimension.CREDENTIAL,
        severity=Severity.CRITICAL,
        title="Plaintext key",
        location=Location(path="/cfg/.mcp.json", line=4),
        remediation="fix",
        rationale="why",
        secret=fingerprint_secret("sk-SUPER-SECRET-VALUE-1234567890"),
    )
    server = Server(
        id="/cfg/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=(finding,),
    )
    snap = build_snapshot(_report(server))
    a = snapshot_digest(snap)
    b = snapshot_digest(build_snapshot(_report(server)))
    assert a == b  # deterministic
    blob = json.dumps([{"k": f.key, "d": dict(f.detail), "s": f.summary} for f in snap.facts])
    assert "SUPER-SECRET" not in blob  # no raw secret anywhere in the snapshot


# --- diff direction: the core value ---
def test_new_finding_is_a_regression() -> None:
    base = build_snapshot(_report(_server("s#1")))
    curr_server = _server("s#1")
    curr_server = Server(**{**curr_server.__dict__, "findings": (_finding(),)})
    report = diff_snapshots(base, build_snapshot(_report(curr_server)))
    finding_entries = [e for e in report.entries if e.kind.value == "finding"]
    assert len(finding_entries) == 1
    assert finding_entries[0].change is ChangeType.ADDED
    assert finding_entries[0].direction is Direction.REGRESSION
    assert report.regressions


def test_resolved_finding_is_an_improvement() -> None:
    with_finding = Server(**{**_server("s#1").__dict__, "findings": (_finding(),)})
    base = build_snapshot(_report(with_finding))
    report = diff_snapshots(base, build_snapshot(_report(_server("s#1"))))
    finding_entries = [e for e in report.entries if e.kind.value == "finding"]
    assert finding_entries[0].change is ChangeType.REMOVED
    assert finding_entries[0].direction is Direction.IMPROVEMENT
    assert not report.regressions


def test_newly_exposed_server_is_a_regression() -> None:
    base = build_snapshot(_report())
    exposed = _server("socket://0.0.0.0:8000", bind="0.0.0.0", port=8000)
    report = diff_snapshots(base, build_snapshot(_report(exposed)))
    entry = next(e for e in report.entries if e.kind.value == "server")
    assert entry.direction is Direction.REGRESSION


def test_local_server_appearing_is_informational() -> None:
    base = build_snapshot(_report())
    localhost = _server("socket://127.0.0.1:8000", bind="127.0.0.1", port=8000)
    report = diff_snapshots(base, build_snapshot(_report(localhost)))
    entry = next(e for e in report.entries if e.kind.value == "server")
    assert entry.direction is Direction.INFORMATIONAL


def test_server_becoming_exposed_is_a_regression() -> None:
    base = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    curr = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    report = diff_snapshots(base, curr)
    changed = next(e for e in report.entries if e.change is ChangeType.CHANGED)
    assert changed.direction is Direction.REGRESSION


def test_server_becoming_local_is_an_improvement() -> None:
    base = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    curr = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    report = diff_snapshots(base, curr)
    changed = next(e for e in report.entries if e.change is ChangeType.CHANGED)
    assert changed.direction is Direction.IMPROVEMENT


def test_identical_posture_has_no_drift() -> None:
    server = Server(**{**_server("s#1").__dict__, "findings": (_finding(),)})
    base = build_snapshot(_report(server))
    report = diff_snapshots(base, build_snapshot(_report(server)))
    assert not report.has_drift
    assert report.entries == ()


def test_new_ai_asset_is_informational() -> None:
    from mcpscan.inventory.model import (
        Asset,
        AssetKind,
        AssetSource,
        Confidence,
        Inventory,
    )

    base = build_snapshot(_report(), None)
    asset = Asset(
        kind=AssetKind.MODEL_SERVER,
        product="Ollama",
        source=AssetSource.SOCKET,
        location="127.0.0.1:11434",
        confidence=Confidence.HIGH,
        evidence=("process name 'ollama'",),
    )
    inv = Inventory(schema_version="1.0", assets=(asset,))
    report = diff_snapshots(base, build_snapshot(_report(), inv))
    entry = next(e for e in report.entries if e.kind.value == "asset")
    assert entry.change is ChangeType.ADDED
    assert entry.direction is Direction.INFORMATIONAL


# --- baseline round-trip + integrity ---
def test_baseline_round_trips() -> None:
    server = Server(
        **{**_server("s", bind="0.0.0.0", port=8000).__dict__, "findings": (_finding(),)}
    )
    snap = build_snapshot(_report(server))
    loaded = load_baseline(render_baseline(snap, created_at="2026-07-10T00:00:00Z"))
    assert snapshot_digest(loaded) == snapshot_digest(snap)
    # A round-tripped baseline diffs clean against the same posture.
    assert not diff_snapshots(loaded, snap).has_drift


def test_baseline_tamper_is_detected() -> None:
    snap = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    text = render_baseline(snap)
    # Flip an exposed bind to loopback without updating the digest.
    tampered = text.replace("0.0.0.0", "127.0.0.1")
    with pytest.raises(BaselineError, match="integrity check failed"):
        load_baseline(tampered)


def test_baseline_malformed_json_errors() -> None:
    with pytest.raises(BaselineError, match="malformed"):
        load_baseline("{not json")


def test_baseline_unknown_schema_errors() -> None:
    with pytest.raises(BaselineError, match="schema_version"):
        load_baseline(json.dumps({"schema_version": "999", "facts": []}))


def test_baseline_load_can_skip_digest_check() -> None:
    snap = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    tampered = render_baseline(snap).replace("0.0.0.0", "127.0.0.1")
    # Explicit opt-out still parses (for tooling that re-derives its own trust).
    loaded = load_baseline(tampered, verify_digest=False)
    assert loaded.facts


# --- rendering ---
def test_terminal_render_regressions_first() -> None:
    base = build_snapshot(_report(_server("s#1")))
    curr = Server(**{**_server("s#1").__dict__, "findings": (_finding(),)})
    report = diff_snapshots(base, build_snapshot(_report(curr)))
    out = render_terminal_drift(report)
    assert "1 regression(s)" in out and "REGRESSION" in out


def test_terminal_render_no_drift() -> None:
    base = build_snapshot(_report(_server("s#1")))
    assert "No drift from baseline" in render_terminal_drift(diff_snapshots(base, base))


def test_json_render_is_stable() -> None:
    base = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    curr = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    report = diff_snapshots(base, curr)
    first = render_json_drift(report)
    assert first == render_json_drift(report)
    payload = json.loads(first)
    assert payload["summary"]["regressions"] == 1
    assert payload["entries"][0]["direction"] == "regression"


# --- baseline parse-error paths ---
def test_baseline_non_object_json_errors() -> None:
    with pytest.raises(BaselineError, match="not a JSON object"):
        load_baseline("123")


def test_baseline_facts_not_a_list_errors() -> None:
    with pytest.raises(BaselineError, match="'facts' is not a list"):
        load_baseline(json.dumps({"schema_version": "1.0", "facts": {}}))


def test_baseline_fact_not_object_errors() -> None:
    with pytest.raises(BaselineError, match="fact is not an object"):
        load_baseline(json.dumps({"schema_version": "1.0", "facts": ["nope"]}))


def test_baseline_fact_missing_field_errors() -> None:
    body = {"schema_version": "1.0", "facts": [{"kind": "server"}]}  # no key/summary
    with pytest.raises(BaselineError, match="invalid baseline fact"):
        load_baseline(json.dumps(body))


def test_baseline_fact_bad_detail_errors() -> None:
    fact = {"kind": "server", "key": "server:s", "summary": "s", "detail": []}
    body = {"schema_version": "1.0", "facts": [fact]}
    with pytest.raises(BaselineError, match="'detail' is not an object"):
        load_baseline(json.dumps(body))


# --- diff informational branches ---
def test_removed_server_is_informational() -> None:
    base = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    report = diff_snapshots(base, build_snapshot(_report()))
    entry = next(e for e in report.entries if e.kind.value == "server")
    assert entry.change is ChangeType.REMOVED
    assert entry.direction is Direction.INFORMATIONAL


def test_changed_asset_is_informational() -> None:
    from mcpscan.inventory.model import (
        Asset,
        AssetKind,
        AssetSource,
        Confidence,
        Inventory,
    )

    def _inv(conf: Confidence) -> Inventory:
        return Inventory(
            schema_version="1.0",
            assets=(
                Asset(
                    kind=AssetKind.MODEL_SERVER,
                    product="Ollama",
                    source=AssetSource.SOCKET,
                    location="127.0.0.1:11434",
                    confidence=conf,
                    evidence=("port hint",),
                ),
            ),
        )

    base = build_snapshot(_report(), _inv(Confidence.LOW))
    curr = build_snapshot(_report(), _inv(Confidence.HIGH))
    report = diff_snapshots(base, curr)
    entry = next(e for e in report.entries if e.kind.value == "asset")
    assert entry.change is ChangeType.CHANGED
    assert entry.direction is Direction.INFORMATIONAL


def test_terminal_render_shows_changed_fields() -> None:
    base = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    curr = build_snapshot(_report(_server("s", bind="0.0.0.0", port=8000)))
    out = render_terminal_drift(diff_snapshots(base, curr))
    assert "→" in out  # the field-level before→after diff is printed
    assert "exposed" in out


def test_changed_local_server_stays_informational() -> None:
    # A server whose detail changes but stays local (neither exposure transition).
    base = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8000)))
    curr = build_snapshot(_report(_server("s", bind="127.0.0.1", port=8001)))
    report = diff_snapshots(base, curr)
    changed = next(e for e in report.entries if e.change is ChangeType.CHANGED)
    assert changed.direction is Direction.INFORMATIONAL
