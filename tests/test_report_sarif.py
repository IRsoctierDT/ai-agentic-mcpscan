"""SARIF 2.1.0 renderer tests: shape, level/severity mapping, redaction, URIs."""

from __future__ import annotations

import json

from mcpscan.domain import (
    Dimension,
    Finding,
    Location,
    Report,
    Server,
    ServerState,
    Severity,
)
from mcpscan.redaction import fingerprint_secret
from mcpscan.report import RenderOptions
from mcpscan.report.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    render_sarif,
    report_to_sarif,
)

RAW_SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123456789"


def _finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "id": "CRED-PLAINTEXT",
        "dimension": Dimension.CREDENTIAL,
        "severity": Severity.CRITICAL,
        "title": "Plaintext OpenAI API key in config",
        "location": Location(path="/repo/.mcp.json", line=4),
        "remediation": "Move it to a secret manager and rotate the key.",
        "rationale": "Plaintext credentials are trivially exfiltrated.",
        "secret": fingerprint_secret(RAW_SECRET),
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def _report(*findings: Finding) -> Report:
    server = Server(
        id="/repo/.mcp.json#leaky",
        bind_addr=None,
        port=None,
        pid=None,
        proc_name=None,
        state=ServerState.DECLARED,
        running=False,
        findings=findings or (_finding(),),
    )
    return Report(
        schema_version="1.0",
        servers=(server,),
        overall_grade="F",
        dimension_grades={Dimension.CREDENTIAL: "F"},
    )


def test_top_level_sarif_shape() -> None:
    doc = json.loads(render_sarif(_report()))
    assert doc["$schema"] == SARIF_SCHEMA
    assert doc["version"] == SARIF_VERSION
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert driver["informationUri"].startswith("https://")
    assert isinstance(driver["version"], str) and driver["version"]


def test_result_and_rule_are_linked() -> None:
    doc = json.loads(render_sarif(_report()))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    assert len(rules) == 1
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "CRED-PLAINTEXT"
    assert rules[r["ruleIndex"]]["id"] == "CRED-PLAINTEXT"


def test_critical_maps_to_error_and_security_severity() -> None:
    doc = json.loads(render_sarif(_report()))
    run = doc["runs"][0]
    assert run["results"][0]["level"] == "error"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "9.5"
    assert "security" in rule["properties"]["tags"]
    assert "credential" in rule["properties"]["tags"]


def test_medium_maps_to_warning() -> None:
    f = _finding(
        id="PIN-UNPINNED",
        dimension=Dimension.PINNING,
        severity=Severity.MEDIUM,
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f)))
    assert doc["runs"][0]["results"][0]["level"] == "warning"
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "5.0"


def test_duplicate_finding_ids_share_one_rule() -> None:
    doc = json.loads(
        render_sarif(
            _report(_finding(), _finding(location=Location(path="/repo/.mcp.json", line=9)))
        )
    )
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1  # deduped
    assert len(run["results"]) == 2
    assert {res["ruleIndex"] for res in run["results"]} == {0}


def test_region_only_present_when_line_known() -> None:
    with_line = json.loads(render_sarif(_report(_finding())))  # default location has line=4
    loc = with_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] == 4

    no_line = json.loads(render_sarif(_report(_finding(location=Location(path="/repo/.mcp.json")))))
    loc2 = no_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in loc2


def test_uri_is_repo_relative_under_base() -> None:
    doc = json.loads(render_sarif(_report(), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == ".mcp.json"  # repo-relative -> GitHub can annotate it


def test_uri_outside_base_is_privatized_file_url() -> None:
    f = _finding(location=Location(path="/home/jane/.cursor/mcp.json"))
    doc = json.loads(render_sarif(_report(f), RenderOptions(home="/home/jane"), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "~/.cursor/mcp.json"  # ~ privacy, no username leak
    assert "jane" not in uri


def test_socket_location_passes_through() -> None:
    f = _finding(
        id="EXPOSURE-WILDCARD",
        dimension=Dimension.EXPOSURE,
        severity=Severity.HIGH,
        location=Location(path="socket://0.0.0.0:8000"),
        secret=None,
    )
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "socket://0.0.0.0:8000"


def test_path_equal_to_base_becomes_dot() -> None:
    f = _finding(location=Location(path="/repo"))
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "."


def test_windows_absolute_path_becomes_file_uri() -> None:
    # Outside base, an absolute Windows path (no ~ relativization) -> file:/// URI.
    f = _finding(location=Location(path=r"C:\Users\jane\.mcp.json"))
    doc = json.loads(render_sarif(_report(f), base="/repo"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "file:///C:/Users/jane/.mcp.json"


def test_message_and_log_never_contain_raw_secret() -> None:
    out = render_sarif(_report(), RenderOptions(home="/home/jane"), base="/repo")
    assert RAW_SECRET not in out
    msg = json.loads(out)["runs"][0]["results"][0]["message"]["text"]
    assert "[redacted" in msg  # fingerprint form, never the raw value


def test_show_secrets_reveals_masked_only() -> None:
    out = render_sarif(_report(), RenderOptions(show_secrets=True), base="/repo")
    assert RAW_SECRET not in out  # masked (first-2/last-2), never raw


def test_partial_fingerprint_is_stable_and_present() -> None:
    a = json.loads(render_sarif(_report(), base="/repo"))
    b = json.loads(render_sarif(_report(), base="/repo"))
    fp = a["runs"][0]["results"][0]["partialFingerprints"]["mcpscanFindingHash/v1"]
    assert fp == b["runs"][0]["results"][0]["partialFingerprints"]["mcpscanFindingHash/v1"]
    assert len(fp) == 16


def test_render_is_byte_stable() -> None:
    assert render_sarif(_report(), base="/repo") == render_sarif(_report(), base="/repo")


def test_clean_report_is_valid_empty_run() -> None:
    clean = Report(schema_version="1.0", servers=(), overall_grade="A", dimension_grades={})
    doc = report_to_sarif(clean)
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
