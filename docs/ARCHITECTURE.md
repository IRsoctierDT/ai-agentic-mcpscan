# AI Agentic MCPscan — Architecture & ADR Validation

> **Author:** Principal Architect (ai-dev-team)
> **Status:** ✅ Signed off for build — 2 refinements folded in, 0 blocking findings
> **Inputs:** [`SPEC.md`](./SPEC.md), [`DECISIONS.md`](./DECISIONS.md), [`BACKLOG.md`](./BACKLOG.md)

This document validates the System Analyst's decisions against a buildable
technical design, defines the component model and the dependency direction that
make the spec's trust properties hold *by construction*, and allocates the
non-functional budgets. Every Sprint 1–4 ticket is reachable from this design.

---

## 1. ADR validation verdict

All 15 ADRs are **architecturally sound and Accepted**. Two refinements (R1, R2)
are folded into the design below — they strengthen, not change, the decisions.
No blocking findings.

| ADR | Verdict | Architectural note |
|---|---|---|
| 1 Localhost-only | ✅ | Enforced by a loopback guard (§4). |
| 2 CLI + static HTML | ✅ | Clean layering: `cli → engine → domain → renderers`. |
| 3 Redact, opt-in reveal | ✅ **R1** | Strengthened: the raw secret **never enters the domain model** (§5). |
| 4 Claude-first, pluggable | ✅ | `HostAdapter` ABC; Claude is impl #1 (§6). |
| 5 Advise-only | ✅ | No file-write code path exists anywhere in MVP. |
| 6 A–F scoring | ✅ | Pure `scoring` module, deterministic (§7). |
| 7 JSON now | ✅ | `schema_version`-stamped; renderer consumes domain only. |
| 8 Static HTML | ✅ | Renderer inlines assets; no server, no sockets. |
| 9 Offline default, `--online` | ✅ **R2** | Egress isolated to one package, not imported by default (§4). |
| 10 Apache-2.0 | ✅ | LICENSE in place; SPDX headers on source. |
| 11 macOS/Linux/Windows | ✅ | OS branching isolated to the path resolver (§6). |
| 12 Socket enum + probe | ✅ | psutil is the one notable dep — justified (§8). |
| 13 Stateless | ✅ | No persistence layer; output is a pure function of inputs. |
| 14 PyPI/pipx | ✅ | `src/` layout + hatchling already scaffolded. |
| 15 Public-adoption-ready | ✅ | Testability + docs are first-class in the design. |

### Refinement R1 — secrets never enter the domain model
The spec requires redaction in all outputs (FR-R4). Architecturally I make that
**impossible to violate**: a detected secret's raw value lives only inside the
detecting check's local scope and is immediately reduced to a
`SecretFingerprint(masked, sha256_8, length)`. The `Finding` stores only the
fingerprint. Therefore no renderer — terminal, JSON, or HTML — can leak a secret,
because the value is gone before a `Report` exists. `--show-secrets` only toggles
whether the already-masked fingerprint is displayed; it never restores plaintext.

### Refinement R2 — "loopback probe" is not "egress"
FR-D3 (probe `/mcp`,`/sse`) and NFR-SEC1 (zero egress by default) could appear to
conflict. They don't, once separated: the discovery probe targets **loopback
only** (127.0.0.1/::1) and is guarded to reject any non-loopback target.
*Egress* (a call leaving the host) exists in exactly one place — the `enrichment`
package — which is **not imported** unless `--online` is passed.

---

## 2. Architectural drivers (from the spec)

1. **Trust by construction** — redaction, offline-default, and statelessness are
   structural, not behavioral promises.
2. **Determinism** — output is a pure function of (filesystem state, socket
   state); same inputs → same `Report`.
3. **Extensibility at one seam** — host coverage grows via `HostAdapter` with no
   core change (the moat: breadth).
4. **Testability** — pure core (domain, checks, scoring, redaction) needs no I/O;
   I/O lives at the edges behind narrow interfaces.

## 3. Component model

```
                    ┌──────────────┐
                    │     cli      │  arg parsing, orchestration, exit codes
                    └──────┬───────┘
                           │ calls
                    ┌──────▼───────┐
                    │    engine    │  scan() pipeline: discover → audit → score → report
                    └──┬───┬───┬───┘
        ┌──────────────┘   │   └──────────────┐
   ┌────▼─────┐      ┌──────▼──────┐     ┌─────▼──────┐
   │ discovery│      │  adapters   │     │   checks   │  exposure / credentials
   │ (psutil  │      │ HostAdapter │     │  /scope/   │  / tool_scope / pinning
   │  + probe)│      │  + Claude   │     │  pinning   │
   └────┬─────┘      └──────┬──────┘     └─────┬──────┘
        │                   │ uses             │ produces
        │            ┌──────▼──────┐    ┌───────▼───────┐
        └───────────►│   io_safe   │    │  redaction    │ secret → fingerprint
                     │ (bounded    │    └───────┬───────┘
                     │  reads)     │            │
                     └─────────────┘     ┌──────▼──────┐
                                         │   domain    │  Server, Finding, Report,
                                         │ (pure model)│  Severity, Dimension (frozen)
                                         └──────┬──────┘
                                                │ consumed by
                  ┌─────────────────────────────┼─────────────────────────────┐
            ┌─────▼─────┐                  ┌─────▼─────┐                  ┌─────▼─────┐
            │ report/   │                  │ report/   │                  │ report/   │
            │ terminal  │                  │  json     │                  │  html     │
            └───────────┘                  └───────────┘                  └───────────┘

      scoring  ── pure: Report grades                enrichment/ ── ONLY egress;
                                                     imported only when --online
```

**Dependency rule:** arrows point toward `domain`. `domain`, `scoring`,
`redaction`, and `checks` are **pure** (no network, no unbounded I/O) and depend
on nothing outward. Renderers depend only on `domain`. This keeps ~80% of the
code unit-testable without touching the filesystem or sockets.

## 4. Trust boundaries (enforced structurally)

| Boundary | Enforcement point | Backing requirement |
|---|---|---|
| **Localhost only** | `discovery.probe` rejects any non-loopback target; no module accepts a remote host param | ADR-1, FR-D3 |
| **Zero egress by default** | `enrichment` is the sole package importing an HTTP client; `cli` imports it only on `--online`; a test asserts no outbound socket in the default path | ADR-9, NFR-SEC1 |
| **No secret leak** | `redaction` converts secret→fingerprint at detection; `Finding` cannot hold raw value (R1) | FR-R4 |
| **No file mutation** | No write API in `adapters`/`checks`; only `report` writes, only to the user-named path, `0600` | ADR-5, FR-R6 |
| **Bounded, safe reads** | all file reads go through `io_safe` (size cap, no external symlink, perms-aware) | NFR-SEC3, NFR-S3 |
| **Self-consistency** | no listening socket opened anywhere; no secret in repo (CI secret-scan) | NFR-SEC4 |

## 5. Domain model (pure, frozen)

```python
class Severity(Enum):  CRITICAL, HIGH, MEDIUM, LOW, INFO
class Dimension(Enum): EXPOSURE, CREDENTIAL, TOOL_SCOPE, PINNING
@dataclass(frozen=True) SecretFingerprint: masked: str; sha256_8: str; length: int
@dataclass(frozen=True) Location: path: str; line: int | None
@dataclass(frozen=True) Finding: id; dimension; severity; title; location;
                                  remediation; rationale; secret: SecretFingerprint | None
@dataclass(frozen=True) Server: id; bind_addr; port; pid; proc_name; state;
                                 running: bool; inspection_incomplete: bool; findings: tuple[Finding]
@dataclass(frozen=True) Report: schema_version; servers; overall_grade; dimension_grades; generated_with_online: bool
```

Frozen + enums ⇒ invariants hold by construction (FR-S1, FR-R3/R4). No raw secret
field exists.

## 6. Key interfaces

- **`HostAdapter` (ABC)** — `name`, `default_config_paths(os) -> list[Path]`,
  `parse(path, raw) -> ParsedConfig`, `declared_servers(cfg) -> list[ServerDecl]`.
  Claude adapter is impl #1; Cursor/etc. slot in with zero core change
  (verified by a stub adapter test — T-205).
- **`Check` (protocol)** — `run(context) -> list[Finding]`, where `context`
  bundles parsed configs + discovered servers. Checks are pure and independently
  testable; the catalog (exposure/credential/tool_scope/pinning) is just a list.
- **`Renderer` (protocol)** — `render(report) -> str | bytes`. Consumes `domain`
  only.
- **Path resolution** is the *only* place OS branching lives (ADR-11); everything
  else is OS-agnostic via `pathlib`.

## 7. Non-functional budget allocation (NFR-P1 ≤ 10s)

| Stage | Budget | Mechanism |
|---|---|---|
| Socket/process enumeration | ≤ 1.0s | single psutil pass |
| Endpoint probing | ≤ 5.0s wall | bounded pool (≤ 20 workers), ≤ 2s/endpoint timeout |
| Config discovery + parse | ≤ 1.5s | bounded reads (io_safe), lazy |
| Checks + scoring + render | ≤ 1.0s | pure, in-memory |
| **Headroom** | ~1.5s | — |

Scoring rubric (SPEC §6) lives in `scoring` as a pure function: identical findings
⇒ identical grade (FR-S2 determinism, table-tested).

## 8. Dependency justification (least dependencies)

| Dep | Why | Risk control |
|---|---|---|
| `psutil` | Cross-platform listening-socket/process enumeration — the only portable way to observe `0.0.0.0` bindings (ADR-12) | Pinned; widely used; isolated to `discovery` |
| `tomllib` | TOML config parsing | **stdlib** (Python 3.11+) — zero added dep (the reason for the 3.11 floor) |
| `json` | JSON config + report | stdlib |
| HTTP client (probe) | loopback probe | stdlib `http.client`/`urllib` — no third-party; loopback-guarded |
| `--online` HTTP | OSV/PyPI enrichment | isolated to `enrichment`; not imported by default |

No web framework, no templating engine (HTML renderer emits a self-contained
string), no DB. This keeps the supply chain small — appropriate for a security
tool that scans for supply-chain risk.

## 9. Architecture Definition of Done — met

- [x] Every Sprint 1–4 ticket is reachable from a component above.
- [x] Trust boundaries are explicit and consistent with the §8 threat model.
- [x] Non-functional budgets are numeric and allocated (§7).
- [x] The pluggable seam (HostAdapter) and pure-core layering are defined.
- [x] Dependencies justified; supply chain minimized.
- [x] ADRs validated; rationale and refinements recorded.

**Sign-off:** cleared for the full-team backlog review and Sprint 1. The build
order in `BACKLOG.md` (Foundations → Engine → Reporting → Integration) is
consistent with the dependency direction here — `domain`/`io_safe` first is
correct.
