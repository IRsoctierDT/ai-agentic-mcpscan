# Full-Team Backlog Review — Pre-Development Gate

> **Gate:** charter requires the full team to review the backlog before Sprint 1.
> **Reviewers:** Product Council · Test Architect · Security Reviewer · Code Quality
> **Outcome:** ✅ Cleared for Sprint 1 with **3 accepted findings** folded into the
> spec/backlog (F1–F3). No blockers.

Each role applied its mandate to [`SPEC.md`](./SPEC.md),
[`DECISIONS.md`](./DECISIONS.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md), and
[`BACKLOG.md`](./BACKLOG.md).

---

## Product Council — data-handling compliance
**Verdict:** ✅ approve with F1.

- Data minimization is strong (stateless, redacted, offline-default). Good.
- **F1 (accepted) — filesystem paths are quasi-identifying.** Reports include
  `Location.path` like `/Users/<name>/...` or `C:\Users\<name>\...`, which leaks
  the OS username and is awkward for a "safe to share" report. → Add **FR-R7**:
  by default, relativize/abbreviate home in rendered paths (`~/…`); a
  `--absolute-paths` flag opts back in. New ticket **T-306**.
- Every collected data element still maps to a requirement; no overcollection.

## Test Architect — coverage completeness
**Verdict:** ✅ approve with F2.

- The critical proofs are already ticketed: network-isolation (T-203/T-401),
  redaction corpus (T-206), determinism (T-210). Good.
- **F2 (accepted) — false-positive guard is implied, not required.** A scanner
  that cries wolf loses trust (a named project risk). → Add to the Definition of
  Done and per-check ACs: each check ships with a **negative fixture** (a clean,
  well-configured input that must yield **zero** findings). Tracked as
  acceptance criteria on T-202/206/207/208/209 and a corpus task **T-212**.
- Add a cross-cutting **golden-report** test (fixed input → byte-stable JSON) to
  lock determinism + schema. Folded into T-302.

## Security Reviewer — threat model & boundaries
**Verdict:** ✅ approve with F3. Independent pass, adversarial lens.

- R1 (secret never in domain) and R2 (egress isolated) from ARCHITECTURE.md
  materially de-risk the two worst outcomes. Endorsed.
- **F3 (accepted) — three hardening requirements:**
  1. **Probe sends nothing sensitive.** The loopback probe must send no
     credentials/auth headers and no request body — a bare GET only. (AC on
     T-203.)
  2. **Enrichment minimizes outbound data.** `--online` may send only
     `{package, version}` to OSV/PyPI — never config contents, paths, or
     fingerprints. (AC on T-401.)
  3. **Fingerprint can't reconstruct low-entropy secrets.** `sha256_8` is a
     32-bit truncation for *operator triage only*; document that it is not a
     security control and must never be treated as one. Masked form reveals at
     most first-2/last-2 chars. (AC on T-206/T-305.)
- No hard-coded secrets, no weakened controls, no file-mutation path. Confirmed
  against the design.

## Code Quality (Spaghetti) — structural review of the plan
**Verdict:** ✅ approve.

- The architecture's pure-core/edge-I/O layering and single OS-branching point
  (path resolver) prevent the usual tangle. Naming is consistent with the spec.
- Watch item (not a blocker): keep `checks/` as small, single-responsibility
  functions behind the `Check` protocol — one check per concern, no mega-module.
  Will enforce at the post-Sprint-2 Code Quality pass (T-211).

---

## Accepted changes (apply before/within build)

| ID | Change | Where |
|---|---|---|
| F1 | **FR-R7**: default path privacy (relativize home; `--absolute-paths` opt-in) → **T-306** | SPEC §5.4, BACKLOG Sprint 3 |
| F2 | Negative/clean fixtures per check; golden-report determinism test → **T-212** | BACKLOG Sprint 2/3, DoD |
| F3 | Probe sends nothing sensitive; enrichment sends only `{package,version}`; fingerprint documented as non-control | ACs on T-203/T-401/T-206/T-305 |

**Sign-off:** all four reviewers clear the backlog. Sprint 1 (Foundations) may
begin; F1–F3 land in their respective sprints.
