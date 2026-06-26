# Backlog & Sprint Plan — MCP Posture Scanner

Sprint-tagged tickets (the team can't create JIRA sprints directly, so sprints
are **tags** with manual dependency mapping). Every ticket carries acceptance
criteria and traces to requirements in [`SPEC.md`](./SPEC.md). Sprint order
follows the team workflow: **Data/Foundations → Core engine → Reporting →
Integration & hardening**.

Legend — Owner roles: DE=Data Engineer, BE=Backend/CLI Engineer,
IE=Integration Engineer, QA=QA Engineer, SEC=Security Reviewer,
REL=Release Engineer, CQ=Code Quality, ARCH=Principal Architect.

> **Pre-development gate:** the full team (Architect, Product Council, Test
> Architect, Code Quality, Security) reviews this backlog before Sprint 1.

---

## Sprint 1 — Foundations & data model `[Sprint 1]`

- **T-101 — Project scaffold & packaging** (REL/ARCH)
  `pyproject.toml`, console entry point, Apache-2.0 LICENSE+headers, 3-OS CI
  skeleton, ruff/mypy/pytest/bandit wired.
  *AC:* `pipx install .` exposes `mcpscan`; empty CI matrix green on 3 OSes.
  *Traces:* ADR-10, ADR-11, ADR-14, NFR-LIC.
- **T-102 — Core domain model** (DE)
  Typed models: `Server`, `Finding(severity, dimension, location, fingerprint,
  remediation)`, `Report(schema_version, servers, grades)`.
  *AC:* models fully typed; bad state unrepresentable (severities/dimensions are
  enums); unit-tested.
  *Traces:* FR-S1, FR-R3.
- **T-103 — OS-aware path resolver** (DE)
  Resolve Claude/host config locations per macOS/Linux/Windows.
  *AC:* correct default paths per OS (table-tested); unknown OS handled.
  *Traces:* FR-C1, NFR-X1. *Depends:* T-102.
- **T-104 — Safe file reader** (DE/SEC)
  Bounded reads (≤5MB default), no external-symlink follow, traversal-safe,
  permission-aware.
  *AC:* oversized/binary/denied files raise typed errors → `parse_error`
  finding, never crash.
  *Traces:* NFR-S3, NFR-SEC3.

## Sprint 2 — Core engine: discovery, audit, scoring `[Sprint 2]`

- **T-201 — Socket/process enumeration** (BE)
  psutil-based listener enumeration with graceful permission degradation.
  *AC:* loopback listener appears with PID/proc/addr/port; permission failure →
  `inspection_incomplete`.
  *Traces:* FR-D1.
- **T-202 — Exposure detection (0.0.0.0)** (BE/SEC)
  *AC:* `0.0.0.0`/`::`/routable bind → Critical `EXPOSURE`; loopback-only → none.
  *Traces:* FR-D2. *Depends:* T-201.
- **T-203 — MCP confirmation probe** (BE)
  Loopback-only HTTP probe of `/mcp`,`/sse`, ≤2s/endpoint, bounded concurrency.
  *AC:* no request leaves host (isolation test); timeouts respected.
  *Traces:* FR-D3, NFR-P1.
- **T-204 — Declared-server discovery** (BE)
  Parse host configs to list declared servers.
  *AC:* configured-but-not-running server → `declared, running=false`.
  *Traces:* FR-D4. *Depends:* T-103.
- **T-205 — Host adapter + Claude adapter** (BE/ARCH)
  `HostAdapter` seam; Claude implementation for settings/.mcp.json/desktop cfg.
  *AC:* adding a new adapter needs no core change (proven by a stub adapter).
  *Traces:* ADR-4, FR-C1.
- **T-206 — Secret detection + redaction core** (BE/SEC)
  Pattern+entropy detection; central redaction producing masked fingerprint.
  *AC:* test key → Critical `CREDENTIAL` w/ `file:line` + masked fp; raw value
  never emitted (corpus test).
  *Traces:* FR-C2, FR-R4.
- **T-207 — Secret-at-rest checks** (BE)
  World/group-readable + git-tracked/un-gitignored secret files.
  *AC:* git-tracked `.env` w/ secret → High `CREDENTIAL` citing cause.
  *Traces:* FR-C3.
- **T-208 — Tool-scope / auto-approval checks** (BE)
  Auto-approve flags, wildcard allow-lists, auto-approved shell/exec tools.
  *AC:* auto-approved exec tool → High `TOOL_SCOPE`; wildcard → Medium.
  *Traces:* FR-C4.
- **T-209 — Version-pinning checks** (BE)
  Unpinned `npx -y`/`latest`/`^`/`~`.
  *AC:* unpinned cmd → Medium `PINNING`.
  *Traces:* FR-C5.
- **T-210 — Scoring engine** (BE)
  Deterministic rubric → per-server, per-dimension, overall grades.
  *AC:* identical findings → identical grade; rubric (SPEC §6) table-tested.
  *Traces:* FR-S2, FR-S3.
- **T-211 — Code Quality pass (post-sprint)** (CQ)
  *AC:* no cycles, naming consistent, no structural-debt regression.
  *Traces:* team workflow.

## Sprint 3 — Reporting & remediation `[Sprint 3]`

- **T-301 — Terminal renderer** (BE)
  Severity-ordered output; CI exit code on findings ≥ threshold (default High).
  *AC:* threshold flag changes exit code as specified.
  *Traces:* FR-R1.
- **T-302 — JSON renderer** (BE)
  Stable `schema_version` JSON; no raw secrets.
  *AC:* schema validates; redaction holds in JSON.
  *Traces:* FR-R3, FR-R4.
- **T-303 — Static HTML renderer** (BE/designer-equiv)
  Self-contained, inline assets, WCAG-AA, no external calls.
  *AC:* renders offline; network-blocked test = zero outbound; contrast checked.
  *Traces:* FR-R2, NFR-A11Y, ADR-8.
- **T-304 — Remediation content** (BE/SEC)
  Copy-pasteable fix + rationale per check type.
  *AC:* every finding type has a tested remediation string; no file writes.
  *Traces:* FR-R5.
- **T-305 — `--show-secrets` gating + output file perms** (SEC/BE)
  *AC:* default redacts; flag reveals masked/partial only (≤ first-2/last-2) +
  prints warning; written files are `0600` where supported; `sha256_8`
  documented as triage-only, not a security control (review F3).
  *Traces:* FR-R4, FR-R6.
- **T-306 — Path privacy (review F1)** (BE)
  Relativize home to `~/…` by default; `--absolute-paths` opt-in.
  *AC:* home-dir finding renders `~/…` by default; flag shows full path.
  *Traces:* FR-R7.
- **T-212 — Test corpus: clean + golden fixtures (review F2)** (QA)
  A clean/well-configured input per check that must yield **zero** findings, and
  a golden fixed-input→byte-stable JSON test.
  *AC:* no check fires on its clean fixture; golden JSON is byte-stable.
  *Traces:* false-positive guard (DoD), FR-S2, FR-R3.

## Sprint 4 — Online enrichment, integration & hardening `[Sprint 4]`

- **T-401 — `--online` OSV/PyPI enrichment** (IE)
  Off by default; enriches pinning findings; discloses egress.
  *AC:* default run = zero egress (isolation test); `--online` upgrades known-vuln
  versions w/ source label.
  *Traces:* FR-C5[online], ADR-9, NFR-SEC1.
- **T-402 — End-to-end dogfood on real lab** (IE/QA)
  Run against stakeholder's real MCP setups + pfSense/Suricata lab.
  *AC:* discovers & grades real servers correctly; findings manually verified.
  *Traces:* SPEC §14.
- **T-403 — Self-scan (NFR-SEC4)** (SEC)
  *AC:* `mcpscan` passes its own scan — no exposed port, no plaintext secret,
  pinned deps.
  *Traces:* NFR-SEC4.
- **T-404 — Cross-platform verification** (QA)
  *AC:* full suite green on macOS/Linux/Windows; coverage gate met.
  *Traces:* NFR-X1, NFR-DET.
- **T-405 — Security Reviewer sign-off** (SEC)
  *AC:* every §8 threat-model row verified against implementation; high-sev
  findings resolved + re-verified.
  *Traces:* SPEC §8.
- **T-406 — Docs, onboarding, issue templates** (REL)
  README, usage, install, CONTRIBUTING, SECURITY.md, issue/PR templates.
  *AC:* clean-machine `pipx install mcpscan` + quickstart works as written.
  *Traces:* D15, SPEC §14.
- **T-407 — PyPI release** (REL)
  *AC:* versioned, signed build published; install verified on a clean machine;
  human-approved release.
  *Traces:* ADR-14, SPEC §14.

---

## Traceability summary (requirement → ticket)

| Requirement | Ticket(s) |
|---|---|
| FR-D1..D4 | T-201, T-202, T-203, T-204 |
| FR-C1..C5 | T-103, T-204, T-205, T-206, T-207, T-208, T-209, T-401 |
| FR-S1..S3 | T-102, T-210 |
| FR-R1..R6 | T-301, T-302, T-303, T-304, T-305 |
| NFR-SEC1..4 | T-203, T-305, T-401, T-403, T-405 |
| NFR-S3 / X1 / A11Y / DET / P1 | T-104, T-303, T-404, T-203 |
| Threat model §8 | T-405 (+ owners per row) |

**Open items: RESOLVED (2026-06-26).** Own repo `ai-agentic-mcpscan`; score
thresholds accepted; no checks added; Python 3.11 floor (CI 3.11→3.13); product
name **AI Agentic MCPscan** (CLI `mcpscan`). Cleared for architect validation +
full-team backlog review before Sprint 1.
