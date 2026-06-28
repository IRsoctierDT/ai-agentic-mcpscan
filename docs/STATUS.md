# Delivery Status — AI Agentic MCPscan

Human-readable view of [`STATUS.yaml`](./STATUS.yaml) (the source of truth). Keep
the two in sync when a ticket changes state. Tickets and acceptance criteria are
defined in [`BACKLOG.md`](./BACKLOG.md); requirements in [`SPEC.md`](./SPEC.md).

- **Updated:** 2026-06-28
- **Test coverage:** 98% line (gate: `fail_under = 90` in `pyproject.toml`)

**Status legend**

| Status | Meaning |
|---|---|
| ✅ `done` | Implemented and backed by code + tests in this repo |
| 📄 `done_doc` | Required artifact/sign-off exists in the repo, but final acceptance is a human/process step |
| ⏳ `pending` | Not yet completed |
| ❓ `unverified` | Acceptance needs an environment we can't inspect from the repo |

## Rollup

| Sprint | Name | State |
|---|---|---|
| 1 | Foundations & data model | ✅ done |
| 2 | Core engine: discovery, audit, scoring | ✅ done |
| 3 | Reporting & remediation | ✅ done |
| 4 | Online enrichment, integration & hardening | 🔄 in progress (T-402 ❓, T-407 ⏳) |

## Sprint 1 — Foundations & data model

| Ticket | Title | Owner | Status | Evidence |
|---|---|---|---|---|
| T-101 | Project scaffold & packaging | REL/ARCH | ✅ | `pyproject.toml`, `.github/workflows/ci.yml`, `LICENSE`, `src/mcpscan/cli.py` |
| T-102 | Core domain model | DE | ✅ | `src/mcpscan/domain.py`, `tests/test_domain.py` |
| T-103 | OS-aware path resolver | DE | ✅ | `src/mcpscan/adapters/paths.py`, `tests/test_paths.py` |
| T-104 | Safe file reader | DE/SEC | ✅ | `src/mcpscan/io_safe.py`, `tests/test_io_safe.py` |

## Sprint 2 — Core engine: discovery, audit, scoring

| Ticket | Title | Owner | Status | Evidence |
|---|---|---|---|---|
| T-201 | Socket/process enumeration | BE | ✅ | `discovery/sockets.py`, `tests/test_sockets.py` |
| T-202 | Exposure detection (0.0.0.0) | BE/SEC | ✅ | `checks/exposure.py`, `discovery/sockets.py`, `tests/test_checks_other.py` |
| T-203 | MCP confirmation probe | BE | ✅ | `discovery/probe.py`, `tests/test_probe.py` |
| T-204 | Declared-server discovery | BE | ✅ | `engine.py`, `adapters/claude.py`, `tests/test_engine.py` |
| T-205 | Host adapter + Claude adapter | BE/ARCH | ✅ | `adapters/base.py`, `adapters/claude.py`, `tests/test_engine.py` |
| T-206 | Secret detection + redaction core | BE/SEC | ✅ | `checks/secrets.py`, `redaction.py`, `tests/test_checks_secrets.py`, `tests/test_redaction.py` |
| T-207 | Secret-at-rest checks | BE | ✅ | `checks/secrets.py`, `tests/test_checks_secrets.py` |
| T-208 | Tool-scope / auto-approval checks | BE | ✅ | `checks/tool_scope.py`, `tests/test_checks_other.py` |
| T-209 | Version-pinning checks | BE | ✅ | `checks/pinning.py`, `tests/test_checks_other.py`, `tests/test_enrichment.py` |
| T-210 | Scoring engine | BE | ✅ | `scoring.py`, `tests/test_checks_other.py` |
| T-211 | Code Quality pass (post-sprint) | CQ | ✅ | `ci.yml`, `pyproject.toml`, `tests/conftest.py` |

> **T-201 note:** permission-degradation AC now directly tested
> (`test_proc_name_denied_marks_incomplete_but_keeps_socket`).
> **T-205 note:** adapter seam + Claude impl shipped; the AC's "stub adapter
> proves no core change" holds by design but has no dedicated stub-adapter test.

## Sprint 3 — Reporting & remediation

| Ticket | Title | Owner | Status | Evidence |
|---|---|---|---|---|
| T-301 | Terminal renderer | BE | ✅ | `report/terminal.py`, `cli.py`, `tests/test_report.py`, `tests/test_cli.py` |
| T-302 | JSON renderer | BE | ✅ | `report/json_report.py`, `tests/test_report.py` (byte-stable) |
| T-303 | Static HTML renderer | BE | ✅ | `report/html.py`, `tests/test_report.py` |
| T-304 | Remediation content | BE/SEC | ✅ | `checks/*.py` (remediation + rationale per finding type) |
| T-305 | `--show-secrets` gating + output perms | SEC/BE | ✅ | `cli.py`, `report/writer.py`, `tests/test_report.py`, `tests/test_cli.py` |
| T-306 | Path privacy (relativize home) | BE | ✅ | `report/common.py`, `report/__init__.py`, `tests/test_report.py` |
| T-212 | Test corpus: clean + golden fixtures | QA | ✅ | `tests/test_engine.py`, `tests/test_checks_other.py`, `tests/test_checks_secrets.py`, `tests/test_report.py` |

> **T-304 note:** remediation strings are exercised indirectly via check tests,
> not a dedicated remediation test.
> **T-212 note:** ID is in the 2xx series (added via review F2) but scheduled in Sprint 3.

## Sprint 4 — Online enrichment, integration & hardening

| Ticket | Title | Owner | Status | Evidence |
|---|---|---|---|---|
| T-401 | `--online` OSV/PyPI enrichment | IE | ✅ | `enrichment/osv.py`, `engine.py`, `tests/test_enrichment.py` |
| T-402 | End-to-end dogfood on real lab | IE/QA | ❓ | — (needs real MCP + pfSense/Suricata lab) |
| T-403 | Self-scan (NFR-SEC4) | SEC | ✅ | `tests/test_self_scan.py` |
| T-404 | Cross-platform verification + coverage gate | QA | ✅ | `ci.yml` (3-OS × 3-Py matrix), `pyproject.toml` (`fail_under=90`) |
| T-405 | Security Reviewer sign-off | SEC | 📄 | `docs/SECURITY_SIGNOFF.md` |
| T-406 | Docs, onboarding, issue/PR templates | REL | ✅ | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/*` |
| T-407 | PyPI release | REL | ⏳ | `.github/workflows/release.yml`, `docs/RELEASING.md` (publish is human-gated) |

> **T-404 note:** the "coverage gate met" portion of the AC was satisfied by
> adding `fail_under = 90` (PR #1, this work). Cross-platform "suite green" is
> confirmed per-run by CI, not statically.
> **T-405 note:** sign-off doc present; threat-model row verification is a human
> attestation.
> **T-407 note:** release workflow (OIDC) is wired but no published, approved
> release is confirmable from the repo.
