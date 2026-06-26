# AI Agentic MCPscan — Product & Technical Specification

> **Status:** Confirmed — open items resolved (2026-06-26)
> **Author:** System Analyst (ai-dev-team)
> **Product name:** AI Agentic MCPscan · **CLI:** `mcpscan` · **dist:** `ai-agentic-mcpscan`
> **Source idea:** Option A — MCP / Local-Agent Security Scanner & Posture Tool

This specification is the single source of truth for the MVP. It was produced
after a 15-question interrogation in which every trust boundary and architecture
fork was decided by the stakeholder. Decisions are recorded in
[`DECISIONS.md`](./DECISIONS.md); the work breakdown in
[`BACKLOG.md`](./BACKLOG.md). Per the team standard, every requirement below is
written to be **testable**, facts are separated from **assumptions**, and scope
is bounded on **both** sides.

---

## 1. Executive Summary

**AI Agentic MCPscan** (CLI: `mcpscan`) is a **local-first, offline-by-default CLI** that audits the security
posture of an individual developer's MCP (Model Context Protocol) / local-agent
setup. It discovers MCP servers running on the local machine, statically audits
agent configuration files, scores each server across four posture dimensions,
and emits a prioritized remediation report (terminal + self-contained HTML +
machine-readable JSON).

It serves the **unserved bottom of the market**: solo developers and small teams
who stand up MCP servers with no security discipline, where enterprise control
planes don't reach. Differentiation is **breadth of checks** and **quality of
remediation guidance** — not the scan mechanic, which is copyable.

## 2. Objectives

1. Give a solo developer an accurate, at-a-glance posture grade for their local
   MCP/agent setup in a single command.
2. Surface the highest-impact, lowest-effort fixes first, with copy-pasteable
   remediation.
3. Be trustworthy *by construction*: a security tool that handles secrets must
   not leak them, phone home, or expand the user's attack surface.
4. Be credible portfolio evidence of frontier MCP-security threat modeling.

**Non-objectives (MVP):** see §9 Out of Scope.

## 3. Users & Goals

| User | Job-to-be-done | Success looks like |
|---|---|---|
| **Solo developer** (primary) | "Tell me if my MCP setup is exposed or leaking keys, and how to fix it." | One command → graded report → fixes the Criticals in minutes. |
| **Small-team lead** (secondary) | "Give me a shareable posture report I can act on." | A redacted HTML/JSON report safe to pass to a teammate. |
| **The portfolio reviewer** (tertiary) | "Does this person understand the frontier?" | Reads the threat model + check catalog and concludes yes. |

- **Stated need:** discovery + config audit + scoring + remediation.
- **Revealed need:** the report itself must be *safe to produce and share*
  (redaction, no egress).
- **Latent need:** the tool must not become the very thing it flags (no exposed
  ports, no plaintext-secret sinks, no unpinned supply chain).

## 4. Scope-Defining Decisions (confirmed)

| # | Decision | Choice |
|---|---|---|
| D1 | Scan surface | **Localhost only** (127.0.0.1 + local files). LAN deferred & gated. |
| D2 | Interface | **CLI** + self-contained **HTML report**. |
| D3 | Found-secret handling | **Redact by default**; `--show-secrets` reveals masked/partial only. |
| D4 | Audit surface | **Claude ecosystem first**, behind pluggable host adapters. |
| D5 | Remediation | **Advise-only** (no file writes). `--fix` deferred. |
| D6 | Score shape | **Letter grade A–F** from severity-weighted findings. |
| D7 | Machine output | **JSON now**, SARIF later. |
| D8 | Report serving | **Static self-contained HTML file** (no server/port). |
| D9 | Network egress | **Offline + zero telemetry by default**; `--online` opt-in (OSV/PyPI). |
| D10 | License | **Apache-2.0**. |
| D11 | Platforms | **macOS + Linux + Windows**. |
| D12 | Discovery | **Socket/process enumeration (psutil) + targeted probe**. |
| D13 | State | **Fully stateless** (writes only the report the user requests). |
| D14 | Distribution | **PyPI via pipx** (`pipx install mcpscan`). |
| D15 | Definition of done | **Public-adoption-ready**. |

## 5. Functional Requirements

Each requirement has an ID, a statement, and **acceptance criteria** (AC) a QA
agent can turn into a pass/fail test. `[online]` marks behavior gated behind
`--online`.

### 5.1 Discovery (FR-D)

- **FR-D1 — Enumerate listening sockets.** The tool lists local listening
  sockets/processes via psutil.
  - AC: given a process bound to `127.0.0.1:N`, it appears in results with PID,
    process name, bind address, port.
  - AC: enumeration failures due to permissions degrade gracefully — the server
    is reported with an explicit `inspection_incomplete` flag, never a crash.
- **FR-D2 — Detect non-loopback bindings.** Any socket bound to `0.0.0.0`, `::`,
  or a routable address is flagged as exposed.
  - AC: a `0.0.0.0`-bound server yields an `EXPOSURE` finding at **Critical**.
  - AC: a `127.0.0.1`/`::1`-only server yields **no** exposure finding on this
    check.
- **FR-D3 — Confirm MCP identity.** For candidate sockets, probe likely MCP
  endpoints (`/mcp`, `/sse`) on the bound localhost address to confirm.
  - AC: probes target only loopback; no request leaves the host (verified by a
    network-isolation test). Probe timeout ≤ 2s/endpoint; total discovery
    bounded (see NFR-P1).
- **FR-D4 — Discover declared servers.** Parse host config files (FR-C1) to
  enumerate declared MCP servers even if not currently running.
  - AC: a server present in config but not running is reported with
    `state=declared,running=false`.

### 5.2 Config Audit (FR-C)

- **FR-C1 — Locate & parse host configs.** Resolve and parse, per-OS:
  `.claude/settings.json`, `.claude/settings.local.json`, project `.mcp.json`,
  `claude_desktop_config.json`, and `.env` files in scanned roots.
  - AC: OS-correct default paths resolved on macOS, Linux, Windows.
  - AC: malformed/oversized files are reported as a `parse_error` finding, never
    crash the run (see NFR-S3).
- **FR-C2 — Plaintext secret detection.** Detect plaintext secrets (API keys,
  tokens, private keys) in configs and `.env`, by pattern + entropy.
  - AC: a known test key is detected with `file:line` and a masked fingerprint
    (last 4 + hash); **the raw value never appears** in any output unless
    `--show-secrets`, and even then only masked/partial (FR-R3).
  - AC: `CREDENTIAL` finding at **Critical** for a live-looking key.
- **FR-C3 — Secret-at-rest exposure.** Flag secret-bearing files that are
  world/group-readable, or tracked by git / not gitignored.
  - AC: a `.env` containing a secret that is `git`-tracked yields a **High**
    `CREDENTIAL` finding citing the cause.
- **FR-C4 — Auto-approval / tool-scope breadth.** Detect auto-approve flags and
  over-broad tool permissions (e.g. wildcard allow-lists, auto-approved
  shell/exec tools).
  - AC: an auto-approved server exposing a shell/exec-class tool yields a
    **High** `TOOL_SCOPE` finding; wildcard permissions yield **Medium**.
- **FR-C5 — Version pinning.** Detect unpinned MCP server packages (e.g.
  `npx -y pkg` with no version, `latest`, `^`, `~`).
  - AC: an unpinned server command yields a **Medium** `PINNING` finding.
  - AC `[online]`: with `--online`, a pinned-but-known-vulnerable version is
    enriched to **High/Critical** per OSV severity, labeled as online-sourced.

### 5.3 Scoring (FR-S)

- **FR-S1 — Severity per finding.** Every finding carries one of
  `Critical|High|Medium|Low|Info`.
- **FR-S2 — Per-server grade.** Each server gets a letter grade A–F via the
  rubric in §6.
  - AC: identical findings always yield the same grade (deterministic).
- **FR-S3 — Overall posture grade.** The report shows an overall grade plus a
  per-dimension breakdown (Exposure, Credential Hygiene, Tool-Scope, Pinning).
  - AC: overall grade equals the worst per-server grade; aggregate counts shown.

### 5.4 Reporting & Remediation (FR-R)

- **FR-R1 — Terminal report.** Human-readable, severity-ordered summary to
  stdout; non-zero exit code if any finding ≥ a configurable threshold (default
  High) for CI use.
- **FR-R2 — HTML report.** A single self-contained `.html` (inline CSS/JS, **no
  external network calls**) written only when `--html PATH` is given.
  - AC: opening the file offline renders fully; a network-blocked test confirms
    zero outbound requests.
- **FR-R3 — JSON report.** A stable, versioned JSON schema (`schema_version`)
  with scores, findings, locations, fingerprints — never raw secrets.
- **FR-R4 — Redaction everywhere.** No raw secret value appears in terminal,
  HTML, or JSON. `--show-secrets` reveals only a masked/partial value and prints
  a visible warning.
- **FR-R5 — Remediation guidance.** Every finding includes a prioritized,
  copy-pasteable fix and a one-line rationale. The tool **never modifies user
  files**.
- **FR-R6 — Output file safety.** Any file the tool writes is created with
  owner-only permissions (`0600`) where the OS supports it.

## 6. Scoring Rubric (proposed — confirm)

> *Assumption A-SCORE: thresholds below are a proposal; confirm or adjust.*

Start each server at **100**, deduct per finding, map to a grade:

| Severity | Deduction |
|---|---|
| Critical | −40 |
| High | −20 |
| Medium | −10 |
| Low | −3 |
| Info | 0 |

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| < 60 | F |

Floor at 0. Overall grade = worst server grade. Per-dimension sub-grades use the
same mapping over that dimension's findings.

## 7. Non-Functional Requirements

- **NFR-P1 — Performance.** A full localhost scan completes in **≤ 10s** on a
  typical dev machine with ≤ 50 listening sockets (probe concurrency bounded).
- **NFR-SEC1 — Offline by default.** Zero outbound connections and **zero
  telemetry** unless `--online`; `--online` only contacts OSV/PyPI and discloses
  this. Verified by a default-run network-isolation test.
- **NFR-SEC2 — No secret sinks.** Secrets are never logged, persisted, or
  emitted unredacted (ties to FR-R4). Logs are structured and secret-free.
- **NFR-SEC3 — Safe file handling.** Bounded file reads (size cap, see NFR-S3),
  no following symlinks outside scanned roots, path-traversal-safe.
- **NFR-SEC4 — Self-consistency.** The tool exposes no listening port and ships
  no plaintext-secret config — it must pass its own scan.
- **NFR-S3 — Robustness.** Malformed, oversized (> configurable cap, default
  5 MB), binary, or permission-denied files never crash a run; they become
  findings.
- **NFR-X1 — Cross-platform.** Functions on macOS, Linux, Windows; CI matrix
  covers all three.
- **NFR-A11Y — Accessible report.** HTML report meets WCAG AA contrast, uses
  semantic structure, and is readable without JS for core content.
- **NFR-DET — Deterministic & idempotent.** Same inputs → same report; running
  twice changes nothing on disk beyond an explicitly requested report file.
- **NFR-LIC — License & supply chain.** Apache-2.0; dependencies pinned;
  `mcpscan` itself ships with a pinned, audited dependency set.

## 8. Threat Model (tool-as-target, STRIDE-lite)

| Threat | Vector | Mitigation (requirement) |
|---|---|---|
| **Information disclosure** | Report leaks the secrets it finds | FR-R3/R4 redaction; FR-R6 `0600`; `--show-secrets` masked + warned |
| **Information disclosure** | Online mode leaks package names/inventory to third parties | D9/NFR-SEC1: offline default, `--online` opt-in + disclosed |
| **Tampering / traversal** | Malicious config path / symlink escapes scan root | NFR-SEC3 path-safety, no external symlink follow |
| **Denial of service** | Huge/pathological config or socket set hangs the tool | NFR-S3 size caps, NFR-P1 bounded concurrency + timeouts |
| **Elevation / overreach** | Probing other users'/system processes | D1 localhost-only; FR-D1 graceful permission degradation |
| **Supply chain** | `mcpscan`'s own deps compromised | NFR-LIC pinned + audited deps; self-scan (NFR-SEC4) |

Handoff: the **Security Reviewer** owns verification of this table each sprint.

## 9. Out of Scope (MVP)

- LAN / remote-host scanning (D1).
- Auto-remediation / writing to user files (D5).
- SARIF output (D7), CI marketplace action, scan history/trend (D13).
- Non-Claude host adapters beyond the pluggable seam (D4).
- Any paid/license-gated features, telemetry, or accounts.
- Runtime/behavioral analysis of MCP traffic (static + discovery only).

## 10. Assumptions Register — RESOLVED (2026-06-26)

All previously-open assumptions are now confirmed by the stakeholder:

| ID | Item | Resolution |
|---|---|---|
| A-REPO | Repo location | **Own repo** — `ai-agentic-mcpscan` (separate from `ai-dev-team`, which holds the team). |
| A-SCORE | Rubric thresholds (§6) | **Accepted** as written. |
| A-CHECKS | Check catalog (§5.2) breadth | **Accepted** — no additional checks for MVP. |
| A-PY | Python baseline | **3.11 floor** (stdlib `tomllib`, in security support, broad install base); CI tests 3.11→3.13. |
| A-NAME | Product name | **AI Agentic MCPscan**; CLI `mcpscan`; PyPI dist `ai-agentic-mcpscan`. |

No open assumptions remain. Per the analysis-phase Definition of Done, the spec
is ready for Principal Architect validation and full-team backlog review.

## 11. Risks

- **Thin moat (stakeholder-flagged).** Mitigation: depth of check catalog +
  remediation quality; pluggable adapters to out-pace copycats on breadth.
- **False positives erode trust.** Mitigation: conservative severity, clear
  rationale per finding, deterministic scoring, dogfood on the real lab.
- **Cross-platform path/edge cases.** Mitigation: 3-OS CI matrix, robustness
  NFRs, adapter pattern.
- **Slow monetization.** Acknowledged; MVP is Frontier/Portfolio-first, revenue
  deferred (open-core later).

## 12. Cost Considerations

- Build: solo, weekend-to-weeks (stakeholder estimate), Python + existing MCP
  lab. No paid infra (fully local/offline).
- Run: $0 to the user — no backend, no accounts, no telemetry.

## 13. Future Enhancements (post-MVP, sequenced)

1. `--online` deepening → SARIF + GitHub code-scanning action (CI hook).
2. LAN scanning behind an explicit authorization + audit gate (D1 expansion).
3. Additional host adapters (Cursor, Cline, VS Code, generic).
4. Opt-in `--fix` with dry-run + backup (D5 expansion).
5. Posture history / drift (D13 expansion) with secured at-rest store.

## 14. Definition of Done (MVP — "Public-adoption-ready", D15)

- [ ] All FRs implemented with passing tests incl. failure/edge/security cases.
- [ ] Dogfood: correctly discovers & grades the stakeholder's real MCP setups
      and pfSense/Suricata lab.
- [ ] Default-run network-isolation test proves zero egress / zero telemetry.
- [ ] Redaction proven: no raw secret in any output across the test corpus.
- [ ] `mcpscan` passes its own scan (NFR-SEC4).
- [ ] Cross-platform CI (macOS/Linux/Windows) green; coverage gate met.
- [ ] Published to PyPI; `pipx install mcpscan` works on a clean machine.
- [ ] README + docs + onboarding + issue templates (public-adoption bar).
- [ ] Security Reviewer sign-off on the §8 threat model.
- [ ] Every requirement traces to a ticket and a test ([`BACKLOG.md`](./BACKLOG.md)).
