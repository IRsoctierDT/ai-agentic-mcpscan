# Vision — from scanner to AI Infrastructure Security Platform

**Status:** North-star direction (operator-set, 2026-07-10) · aspirational, not a
committed backlog · **Guardrail:** every capability below stays **read-only and
assessment-oriented**. The platform *discovers and evaluates*; it never
exploits, and — per the LAN proposal's governing principle — **discovery never
converts into authority.**

> mcpscan today is a local, offline MCP posture scanner. The direction: grow it
> into a platform for securing **agentic AI deployments** — discovering AI
> infrastructure, evaluating trust relationships, mapping AI-specific attack
> paths, assessing governance, and producing actionable security intelligence —
> while remaining assessment-only. This document records that target so
> individual features can be judged against it. Each tier becomes its own
> proposal + ADRs before any build.

---

## Positioning

The emerging enterprise need is to secure agentic AI: MCP servers, local model
runtimes, agent frameworks, and the trust/delegation relationships between them.
Traditional network scanners see "port 8000 open." An AI-aware assessment platform
sees "an unauthenticated MCP server exposing filesystem tools, reachable from a
host that also holds a GitHub token." That semantic gap is the differentiation.

## Capability tiers

### Tier 1 — AI & MCP discovery
Understand *what AI systems exist* (on the local host today; on authorized
networks via `mcpscan lan`). Targets to classify: MCP servers · AI inference
endpoints · LLM gateways · model registries · vector databases · agent runtimes ·
prompt gateways · AI-orchestration frameworks · local model servers (Ollama,
vLLM, LM Studio) · RAG endpoints.

### Tier 2 — AI security posture assessment
Go beyond "port open" to characterize exposure: authentication absent · anonymous
tool execution · excessive tool permissions · missing/weak transport encryption ·
no rate limiting · no audit logging · over-privileged service account · insecure
model-download config · missing prompt-injection protections · dangerous tool
chaining · unrestricted external internet access · exposed sensitive env vars.
Each finding carries: severity · CVSS · an AI-specific risk score · and mappings
to **MITRE ATT&CK**, **MITRE ATLAS**, **OWASP MCP Top 10**, **NIST AI RMF**, and
**CIS Controls**.

### Tier 3 — AI attack-path analysis
Build a graph of how an attacker could move through an AI environment — an **AI
attack graph**, not a network graph. E.g. `Laptop → Ollama → MCP server →
filesystem tool → GitHub token → private repo`. The differentiator: reasoning
about *tool and trust chaining*, not just host reachability.

### Tier 4 — agent trust analysis
Given the project's Agent-Trust-Broker center of gravity, evaluate: agent
identity · authentication method · tool permissions · secret access · memory
isolation · cross-agent trust · delegation chains · tool inheritance · context
boundaries · approval workflows. Output a **Trust Score** and surface excessive
privilege or risky trust relationships.

### Tier 5 — configuration-drift detection
Store a signed baseline; report change without intrusive re-scanning: new ports ·
new AI services · new MCP servers · certificate changes · TLS downgrades ·
permission changes · new tools · newly exposed APIs · **disappearing security
controls**. Enables continuous monitoring.

### Tier 6 — executive dashboards
Audience-specific views: CISO risk summary · SOC analyst findings · compliance
status · AI-governance scorecard · asset inventory · exposure heat maps · attack-
path visualization · trend analysis over time.

### Tier 7 — AI-assisted security advisor
An embedded assistant that *explains* findings and *prioritizes* remediation —
e.g. "This MCP server exposes filesystem tools without authentication; restrict to
authenticated clients, reduce tool permissions, enable audit logging." It
**complements analysts and takes no autonomous action.** (And, per the LAN
proposal §3.5, it never ingests un-sanitized remote content.)

## Command evolution

```
mcpscan
├── local        # today: localhost config + socket posture scan
├── lan          # authorized, exposure-only network assessment (proposal accepted)
├── baseline     # capture a signed posture baseline
├── diff         # drift vs a baseline (Tier 5)
├── inventory    # AI/MCP asset inventory (Tier 1)
├── trust        # agent trust analysis + Trust Score (Tier 4)
├── atlas        # ATT&CK / ATLAS / OWASP-MCP / NIST-AI-RMF mapping (Tier 2)
├── graph        # AI attack-path graph (Tier 3)
├── report       # multi-audience reporting (Tier 6)
├── policy       # authorization/enterprise policy management (LAN §3)
├── compliance   # governance scorecards (Tier 6)
├── monitor      # continuous, non-intrusive monitoring (Tier 5)
├── explain      # AI-assisted advisor (Tier 7)
└── enterprise   # org-wide orchestration
```

## Sequencing (suggested, not committed)

1. **`lan` Phase A** (accepted) — the safe, exposure-only network foundation.
2. **`inventory` + `atlas`** — turn discovery into classified, framework-mapped
   findings (Tiers 1–2). Highest signal-per-effort next step.
3. **`baseline` + `diff` + `monitor`** — continuous posture (Tier 5).
4. **`trust` + `graph`** — the differentiators (Tiers 3–4).
5. **`report` + `compliance` + `explain` + `enterprise`** — audience surfaces and
   the advisor (Tiers 6–7).

## Invariants that must survive the growth

- **Read-only / assessment-only.** No exploitation, ever. Advise; never act.
- **Discovery never converts into authority** (LAN governing principle).
- **Offline-by-default; egress is explicit and disclosed** (extends NFR-SEC1).
- **Secrets and remote bytes are hostile** until fingerprinted/sanitized.
- **Passes its own scan.** Each new module is held to the same bar.
- **Minimal, audited dependencies.** New deps are a decision, not a default.

These invariants are what make the platform trustworthy enough to point at real
AI infrastructure. Every tier above is subordinate to them.
