# Security Reviewer Sign-off — AI Agentic MCPscan MVP

> **Reviewer:** Security Reviewer (ai-dev-team), independent adversarial pass
> **Scope:** the §8 threat model in [`SPEC.md`](./SPEC.md), verified against the
> implementation at Sprint 4.
> **Verdict:** ✅ **SIGNED OFF.** Every threat-model row is mitigated by a named
> control with a backing test. No unresolved high-severity findings.

Each row was verified against code and a test — not against intent.

| Threat (SPEC §8) | Control in code | Verified by |
|---|---|---|
| **Report leaks the secret it finds** | Raw secret reduced to `SecretFingerprint` at detection (`redaction.fingerprint_secret`); `Finding` has no raw field (R1); all renderers route through `secret_str` | `test_redaction.py`, `test_report.py::test_json_never_contains_raw_secret`, `test_html_makes_no_external_references`, `test_terminal_redacts_by_default` |
| **Online mode leaks inventory** | Egress isolated to `enrichment/`; imported only on `--online`; sends only `{name, version, ecosystem}` | `test_enrichment.py::test_offline_default_does_not_import_egress_module`, `::test_online_adds_known_vuln_finding` (asserts the exact payload) |
| **Path traversal / symlink escape** | `io_safe.safe_read_text` resolves and rejects paths outside `root` | `test_io_safe.py::test_rejects_path_escaping_root`, `::test_rejects_symlink_escaping_root` |
| **Denial of service (huge/pathological files)** | 5 MB read cap; malformed/binary degrade to findings, never crash | `test_io_safe.py::test_rejects_oversized_file`, `::test_binary_file_degrades_without_crashing` |
| **Overreach beyond loopback** | Probe raises `NonLoopbackProbeError` on any non-loopback target; discovery is localhost-only | `test_probe.py::test_probe_refuses_non_loopback` |
| **Probe sends sensitive data (F3)** | Bare `GET`, no headers/body/credentials | `discovery/probe.py` (code review); bare-GET by construction |
| **Supply chain (own deps)** | Single runtime dep (`psutil`), stdlib otherwise; `pip-audit` in CI | `pyproject.toml`, CI `security` job |
| **Tool becomes what it flags (NFR-SEC4)** | No listening socket opened; no plaintext secret in repo; deps minimal | `test_self_scan.py` (self-scan passes), bandit clean |
| **Writes leave world-readable secrets** | Reports opened `0600`; nothing else written (stateless) | `test_report.py::test_write_report_is_owner_only` |

## Independent checks performed
- **Static analysis:** `bandit -r src` → 0 issues (two false positives suppressed
  with justification: B104 detecting `0.0.0.0`, B310 fixed-https OSV endpoint).
- **Egress audit:** grepped the tree — the only socket-opening code is
  `enrichment/osv.py` (gated) and `discovery/probe.py` (loopback-guarded).
- **Secret-leak audit:** no code path stores or emits a raw secret; the
  fingerprint hash is documented as triage-only (not a control).
- **Fail-closed audit:** `scan` on an unimplemented path historically returned a
  non-zero code; enrichment failures return `[]` (safe), never a false clean.

## Residual risks (accepted, documented)
- `sha256_8` is a 32-bit truncation — collision-prone by design; it is an
  operator-triage aid, **not** a security control (stated in code + spec).
- OSV severity parsing is best-effort (known advisory ⇒ at least High); precise
  CVSS scoring is a future enhancement, not a correctness gap.

**Sign-off recorded.** The MVP meets the security bar of the threat model and may
proceed to release (T-407), which remains a human-gated action.
