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
dogfood, collected configs are **anonymized** before they enter the corpus —
and there's a tool for it: [`anonymize.py`](anonymize.py) reuses the scanner's
own detectors, so it scrubs exactly what a scan flags and derives a **verified**
`expects` set:

```bash
python tools/dogfood/anonymize.py real_config.json \
    --host cursor --scope project --relpath .cursor/mcp.json --emit-fixture
```

It (1) replaces every scanner-detected secret with a same-class synthetic — a
provider-shaped token still matches its provider regex; an entropy-flagged value
becomes a same-length high-entropy placeholder — so the fixture still trips the
identical check; (2) collapses home paths (`/home/<user>`, `/Users/<user>`,
`C:\Users\<user>`) to a generic user; and (3) prints a ready-to-paste
`Fixture(...)` whose `expects` is what the scanner really produces on the
scrubbed content. Paste it into `corpus.py`.

Each real finding that surprised us (a false positive or false negative) becomes
a permanent fixture here — that is how a dogfood finding turns into durable
quality. Write it up with the
[triage template](../../docs/dogfood/TRIAGE_TEMPLATE.md).

## The network surface (socket + `lan`)

This harness is the **static-config** surface (validated in CI). The **socket
exposure** surface and `mcpscan lan` are validated separately against a network
lab with pfSense/Suricata as the ground-truth oracle. The operator runbook —
exact binds, signed manifests, expected findings, and the safety *refusal*
controls — is [`docs/dogfood/NETWORK_LAB.md`](../../docs/dogfood/NETWORK_LAB.md);
a synthetic three-bind lab for a no-hardware dry run is in
[`lab/synthetic/`](../../lab/synthetic/docker-compose.yml).
