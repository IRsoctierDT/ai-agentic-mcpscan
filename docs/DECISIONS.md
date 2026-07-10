# Architecture Decision Records — MCP Posture Scanner

Each ADR records a decision made during the System Analyst interrogation, the
options considered, the rationale, and the consequence. Status: **Accepted**
unless noted. These are inputs the Principal Architect validates before Sprint 1.

---

### ADR-1 — Scan surface: localhost only
- **Options:** localhost only · localhost + opt-in owned LAN · auto-discover LAN.
- **Decision:** Localhost only for MVP.
- **Why:** Eliminates third-party-system / legal risk entirely, smallest blast
  radius, fastest to ship. LAN is a later, explicitly-gated feature.
- **Consequence:** Discovery code targets loopback; no network-authorization
  subsystem needed yet. Drives FR-D*, NFR-SEC1.

### ADR-2 — Interface: CLI + static HTML report
- **Options:** CLI · CLI + local web dashboard · ship as an MCP server.
- **Decision:** CLI core + self-contained static HTML report.
- **Why:** Most natural for the dev audience and CI; avoids the irony of a
  security tool exposing its own server (rejected the MCP-server option for that
  reason). See ADR-8 for the static-file choice.
- **Consequence:** Architecture is a library + CLI front-end + renderers.

### ADR-3 — Found-secret handling: redact, opt-in reveal
- **Options:** redact always · redact + `--show-secrets` · location only.
- **Decision:** Redact by default; `--show-secrets` reveals masked/partial only.
- **Why:** Report must be safe to produce/share; operator still needs a triage
  path. Full plaintext is never emitted.
- **Consequence:** A central redaction layer is a hard control (FR-R4); the flag
  is gated, warned, and documented.

### ADR-4 — Audit surface: Claude-first, pluggable adapters
- **Options:** Claude-first · Claude+Cursor+generic · generic scanner.
- **Decision:** Deep Claude-ecosystem support behind a host-adapter interface.
- **Why:** Depth + correct remediation now; breadth (the moat) added later via a
  clean seam without rework.
- **Consequence:** `HostAdapter` abstraction from day one; Claude adapter is the
  first implementation.

### ADR-5 — Remediation: advise-only
- **Options:** advise-only · advise + `--fix` · advise + emit patch.
- **Decision:** Advise-only; the tool never writes to user config files.
- **Why:** Zero blast radius; keeps the security review tractable. `--fix`
  deferred behind dry-run + backup.
- **Consequence:** No file-mutation code path in MVP (FR-R5).

### ADR-6 — Scoring: letter grade from severity-weighted findings
- **Options:** letter grade + severities · numeric 0–100 · findings only.
- **Decision:** A–F grade derived from Critical/High/Medium/Low findings.
- **Why:** At-a-glance hook + clean "fix Criticals first" ordering; demo- and
  portfolio-friendly.
- **Consequence:** Deterministic rubric (§6 of SPEC); per-server + overall +
  per-dimension grades.

### ADR-7 — Machine output: JSON now, SARIF later
- **Options:** JSON now · JSON+SARIF now · human-only.
- **Decision:** Stable versioned JSON in MVP; SARIF deferred.
- **Why:** Covers scripting/automation immediately; SARIF lands with the CI
  integration it serves.
- **Consequence:** `schema_version`-stamped JSON contract owned by the engineer.

### ADR-8 — Report serving: static self-contained HTML file
- **Options:** static file · ephemeral localhost server · both.
- **Decision:** Single self-contained `.html`, no server, no port.
- **Why:** Zero new exposure surface; the tool dogfoods its own advice
  (NFR-SEC4). Inline assets, no external calls.
- **Consequence:** Renderer inlines CSS/JS; FR-R2 network-isolation test.

### ADR-9 — Network egress: offline default, opt-in `--online`
- **Options:** offline + opt-in online · fully offline · online by default.
- **Decision:** Zero egress / zero telemetry by default; `--online` enables
  OSV/PyPI enrichment, disclosed.
- **Why:** Trust is the product. Default must make no network call; deeper
  vuln/version checks are available on explicit consent.
- **Consequence:** Network layer is isolated and off unless flagged; NFR-SEC1
  default-run isolation test.

### ADR-10 — License: Apache-2.0
- **Options:** Apache-2.0 · AGPL-3.0 · MIT.
- **Decision:** Apache-2.0.
- **Why:** Permissive + patent grant; standard for credible dev-security tooling
  and best portfolio signal. Moat is check breadth + remediation quality, not
  license restriction.
- **Consequence:** `LICENSE` + headers; permissive contribution model.

### ADR-11 — Platforms: macOS + Linux + Windows
- **Options:** macOS+Linux · macOS only · all three.
- **Decision:** All three supported.
- **Why:** Broadest, most credible reach.
- **Consequence:** OS-aware config-path resolution; 3-OS CI matrix; path/FS
  edge-case robustness (NFR-X1, NFR-S3).

### ADR-12 — Discovery: socket enumeration + targeted probe
- **Options:** socket enum + probe · config-derived + probe · port-sweep.
- **Decision:** psutil socket/process enumeration, then probe `/mcp`,`/sse`.
- **Why:** The `0.0.0.0`-binding exposure check requires seeing real listening
  sockets; probing alone can't observe bind address.
- **Consequence:** psutil dependency; graceful degradation on permission limits
  (FR-D1); probes loopback-only.

### ADR-13 — State: fully stateless
- **Options:** opt-in save · local history store · fully stateless.
- **Decision:** Fully stateless; writes only the report explicitly requested.
- **Why:** Minimal sensitive-data-at-rest footprint for a tool that handles
  secrets.
- **Consequence:** No history subsystem; trend/drift deferred (D13 future).

### ADR-14 — Distribution: PyPI via pipx
- **Options:** PyPI/pipx · PyPI + standalone binaries · run-from-source.
- **Decision:** Publish to PyPI; `pipx install mcpscan`.
- **Why:** Standard for the dev audience, simplest cross-platform + CI story.
- **Consequence:** `pyproject.toml` packaging; console-script entry point.

### ADR-15 — Definition of done: public-adoption-ready
- **Options:** portfolio dogfood · public-adoption-ready · design-partner.
- **Decision:** Public-adoption-ready.
- **Why:** Maximizes portfolio + frontier credibility; aims at real users/stars.
- **Consequence:** Docs, onboarding, edge-case hardening, issue templates, clean
  PyPI install are in the Definition of Done (SPEC §14).

### ADR-16 — LAN SARIF: logical locations, not synthetic files
- **Options:** (a) keep `lan --sarif` failing closed; (b) synthesize a file path
  like `lan/192.168.1.20/8000` so GitHub annotates it; (c) emit SARIF
  `logicalLocations` for the network endpoint.
- **Decision:** (c). A LAN finding's location is a network endpoint
  (`host:port`), not a source file, so it is represented as a SARIF
  `logicalLocation` (`name` = `host:port`, `fullyQualifiedName` = `lan://host:port`,
  `kind` = `resource`), never a physical `artifactLocation`.
- **Consumer target (the gate that was pending):** *generic* SARIF consumers —
  SIEM/audit pipelines and SARIF tooling (`sarif-tools`, viewers) that read
  `logicalLocations`. **Not** GitHub code scanning: GitHub requires a
  `physicalLocation` (a checkout file) to raise an alert, and a LAN endpoint has
  none. `lan --sarif` therefore emits standards-valid SARIF for those consumers
  and says so; `scan --sarif` stays file-scoped for GitHub (its own non-file
  socket findings remain in the terminal/JSON/HTML views, unchanged).
- **Why not a synthetic file:** inventing `lan/<ip>/<port>` would fabricate a
  path that exists in no checkout — GitHub would either reject it or annotate a
  file that isn't there, and it would corrupt any file-based dedup. Absence of a
  physical location is the truth; SARIF has a first-class way to express it.
- **Consequence:** a shared `logicalLocations` code path in `report/sarif.py`
  (opt-in, off for the file-scoped `scan` view); `lan --sarif` no longer fails
  closed; stable per-result fingerprints key on the `fullyQualifiedName`.
