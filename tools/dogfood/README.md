# Dogfood harness (T-402)

Turns "the scan *looks* right" into a **measurable pre-1.0 gate**: a curated set
of clean and messy MCP configs across every supported host, each hand-labeled
with the findings it must produce. The harness lays each fixture out at its real
discovery path and runs the full `scan` pipeline, then reports false positives
(flagged a non-issue) and false negatives (missed a real one).

## Run it

```bash
python tools/dogfood/run.py                 # matrix + per-check precision/recall
python tools/dogfood/run.py --json out.json # + machine-readable report
```

Exit code is non-zero if any fixture fails (a clean config that isn't silent, or
a messy config missing an expected finding). The same corpus runs in CI via
`tests/test_dogfood.py`, so a heuristic regression is caught permanently.

## The acceptance bar (dogfood proposal §5)

- **Zero false positives on the clean corpus** — a clean setup must be silent.
  A single FP here is a release blocker.
- **Zero false negatives on the messy corpus** for the labeled Critical/High
  findings (a missed plaintext secret or exposed bind is unacceptable).
- Any residual Medium/Low FP is documented and either fixed or accepted with a
  written rationale.

## Adding real configs (the stakeholder pass)

The bundled fixtures are synthetic and safe to commit. During the real-lab
dogfood, collected configs are **anonymized** before they enter the corpus:

1. Scrub host/user names and any real paths.
2. Replace real secrets with a synthetic placeholder that still trips the same
   check (the tool never emits a raw secret, but the config *structure* must be
   scrubbed before it lives in the repo).
3. Add a `Fixture(...)` entry in `corpus.py` with the expected finding ids you
   verified by hand.

Each real finding that surprised us (a false positive or false negative) becomes
a permanent fixture here — that is how a dogfood finding turns into durable
quality.

## What this does *not* cover

The socket/exposure surface (running MCP servers) and `mcpscan lan` are validated
separately against a real network lab (pfSense/Suricata) — see the dogfood
proposal, §2.2. This harness is the **static-config** surface only.
