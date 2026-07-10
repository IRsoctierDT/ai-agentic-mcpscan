# Proposal — Real-lab dogfood (T-402)

**Status:** Draft, for review · **Implements** backlog T-402 (Sprint 4) ·
**Traces** SPEC §14 · **Target:** pre-1.0 gate

> Goal: prove mcpscan finds and grades **real** MCP setups correctly, and put a
> number on its false-positive / false-negative rate before we call it 1.0.
> Everything the tool ships is unit-tested against fixtures we wrote; this is the
> first time it meets configs and running servers we *didn't* author.

---

## 1. Why this matters now

The check heuristics (secret detection, unpinned-package detection, dangerous
tool-scope regexes, exposure classification) were tuned against synthetic
fixtures. Synthetic fixtures confirm the code does what we expected — they can't
tell us whether *what we expected* matches reality. A security tool that cries
wolf (false positives) gets muted; one that misses real exposure (false
negatives) is worse than nothing. T-402 is the reality check.

## 2. Scope: two surfaces

mcpscan has two independent detection surfaces; the dogfood must exercise both.

### 2.1 Static config audit (the file surface)
Run against a **corpus** of real MCP configs across every supported host:
Claude, Cursor, Windsurf, Cline, VS Code, Zed (and Continue once the YAML
question in §7 is decided). For each host we want:

- **Real "clean" configs** (well-run setups) → must produce **zero** findings.
  This is the false-positive test and the most important one.
- **Real "messy" configs** (plaintext keys, `npx -y` unpinned, `autoApprove`
  wildcards, `0.0.0.0` binds) → must produce the *correct* findings at the
  *correct* severity.

### 2.2 Running-server exposure (the socket surface)
Stand up a small lab with real MCP servers and validate discovery + exposure
grading against an independent ground truth:

- A handful of MCP servers bound to a mix of `127.0.0.1`, `0.0.0.0`, and a
  specific LAN interface.
- The **pfSense + Suricata lab** (from the T-402 AC) provides that independent
  ground truth: Suricata/pfSense sees which binds are actually reachable off-host,
  and we check mcpscan's exposure findings against what the network actually
  exposed. Agreement = exposure classifier validated; disagreement = a tuning
  bug we'd never see in a unit test.

## 3. Protocol (how a run is judged)

For every finding the tool emits, and every issue a human reviewer knows is
present, classify:

| Outcome | Meaning |
|---|---|
| **True positive** | Tool flagged a real issue, correct severity |
| **False positive** | Tool flagged a non-issue (or wrong severity up) |
| **False negative** | A real issue the tool missed |
| **Severity miss** | Right finding, wrong severity band |

From those, compute **per-check precision and recall**, plus overall grading
accuracy (did the A–F grade match a reviewer's judgment?). The unit of truth is
a human reviewer's manual verification, per the T-402 acceptance criterion
("findings manually verified").

## 4. Deliverables

1. **A dogfood findings report** — the matrix above, per host and per check, with
   every FP/FN written up (input → expected → actual → root cause).
2. **A heuristic-tuning backlog** — each FP/FN becomes a concrete, prioritized
   fix (e.g. "secret regex fires on `${env:VAR}` placeholders — add a
   reference-syntax allow-list").
3. **Regression fixtures** — every real FP/FN, minimized and anonymized, added to
   the test suite so it can never regress. This is how dogfood findings become
   permanent quality.
4. **A go/no-go for 1.0** — measured precision/recall against a pre-agreed bar
   (proposed in §5).

## 5. Success criteria (proposed thresholds)

The T-402 AC is qualitative ("discovers & grades real servers correctly"). I
propose we make it measurable before the run so the result is unambiguous:

- **Zero false positives on the clean corpus** (a clean setup must be silent —
  this is non-negotiable; a single FP here is a release blocker).
- **Recall ≥ 0.95** on the messy corpus for Critical/High findings (missing a
  plaintext secret or an `0.0.0.0` bind is unacceptable).
- **Exposure classifier agrees with the pfSense/Suricata ground truth on 100%**
  of the lab binds (it's a small, enumerable set — no excuse for disagreement).
- Any residual Medium/Low FP is documented and either fixed or accepted with a
  written rationale.

## 6. Division of labor

**What I can build to support the run (no external access needed):**
- A **dogfood harness**: a script that runs mcpscan over a directory of collected
  configs, emits the per-host/per-check matrix as JSON + a readable table, and
  diffs against a hand-labeled expectations file.
- A **triage template** (the FP/FN write-up format) and the anonymizer that turns
  a real finding into a safe regression fixture (secrets already never leave the
  tool, but config *structure* and paths need scrubbing before they enter the
  repo).
- A **synthetic lab**: docker-composed MCP servers on the three bind types, so the
  socket surface can be exercised without your physical lab — useful as a dry run.

**What needs you (the operator):**
- Access to (or exports of) the **real stakeholder MCP setups** — the configs we
  didn't author. These are the whole point; I can't synthesize "real."
- The **pfSense/Suricata lab** for the network ground truth (or a VM stand-in).
- The final **manual verification** sign-off on each finding — the AC requires a
  human, and for a security posture call that human should be you.

## 7. Open decision this run depends on — Continue's YAML config

Continue (continue.dev) has moved its primary config to **YAML** (`config.yaml`,
`.continue/mcpServers/*.yaml`). Supporting it means one of:

1. **Add `pyyaml`** as a dependency. Simplest, but adds a non-stdlib parser to a
   tool whose pitch is *minimal, offline, passes-its-own-scan*. Every dependency
   is attack surface and a supply-chain link a security tool must vouch for.
2. **Support only Continue's legacy JSON** (`config.json` /
   `experimental.modelContextProtocolServers`). Zero new deps, but it's the
   deprecated format — most current users are on YAML, so we'd advertise
   "Continue support" while missing the majority case. **False confidence is
   worse than no support** for a security tool.
3. **Defer Continue** until we decide on (1) vs the cost of a hardened,
   YAML-safe-subset parser.

My recommendation: **decide (1) vs (3) explicitly.** If we value breadth, add
`pyyaml` but pin it, include it in the SBOM, and note it in the threat model. If
we value the minimal-surface promise more, defer Continue and say so plainly in
the README rather than half-supporting it. I lean toward **(1) with a pinned,
audited `pyyaml`** — Continue is popular enough to justify one well-understood
dependency — but this is your call, and it's why Continue is not in the current
adapter PR.

## 8. Phasing

1. **Harness + synthetic lab** (I build) — dry-run the whole protocol against
   fixtures + docker MCP servers; shakes out the tooling.
2. **Config corpus pass** (you supply configs, I run + we triage) — the static
   surface; produces the first FP/FN backlog + regression fixtures.
3. **Network lab pass** (your pfSense/Suricata lab) — the socket surface;
   validates the exposure classifier against real reachability.
4. **Tune + re-run + sign off** — burn down the backlog, re-run to confirm, record
   the go/no-go for 1.0.

## 9. Recommendation

Green-light **Phase 1 immediately** — I can build the dogfood harness, synthetic
lab, and triage/anonymizer tooling now, with no external access, so the moment
you can share real configs we're ready to run. Decide §7 (Continue/YAML) when
convenient; it gates Continue coverage but nothing else. The measurable §5 bar is
the thing I'd most like your agreement on up front, because it turns "looks
right" into a defensible 1.0 gate.
