# Dogfood triage template (T-402, Phase 2)

One entry per finding that a run got **wrong** — a false positive, a false
negative, or a severity miss. A true positive at the right severity needs no
entry. Each row becomes (a) a line in the findings report and (b), once
minimized and anonymized, a permanent regression fixture in
[`tools/dogfood/corpus.py`](../../tools/dogfood/corpus.py) so it can never
regress (proposal §4.3).

The unit of truth is a **human reviewer's** manual verification — the T-402
acceptance criterion. Fill `Reviewer verdict` yourself; the tool's output is the
claim under test, not the answer.

---

## Entry

- **ID:** `DF-YYYYMMDD-NN`
- **Host / surface:** _(claude | cursor | … | socket | lan)_
- **Source:** _(anonymized config name, or lab bind `host:port`)_
- **Check id:** _(e.g. `CRED-PLAINTEXT`, `EXPOSE-BIND`, `LAN-EXPOSED`)_

| | |
|---|---|
| **Tool emitted** | _(finding + severity, or "nothing")_ |
| **Reviewer verdict** | _(the ground truth: real issue at severity X, or a non-issue)_ |
| **Classification** | ☐ false positive ☐ false negative ☐ severity miss |

**Minimal input** _(the smallest config/bind that reproduces it — this becomes the fixture)_:

```
<paste the minimized, anonymized input>
```

**Root cause** _(why the heuristic misfired — be specific)_:

> e.g. "the secret regex fires on `${env:VAR}` placeholder syntax; it should
> treat `${…}` / `$(…)` references as non-literal and skip them."

**Proposed fix** _(a concrete, prioritized change — links to the check module)_:

> e.g. "in `checks/secrets.py::_looks_secret`, add a reference-syntax guard
> before the entropy test."

**Regression fixture** _(the anonymized fixture id once added)_:

> `Fixture("cursor", "ref-placeholder", …)` — added in `corpus.py`, PR #NN.

---

## How to produce the anonymized fixture

Never paste a real config here. Run it through the anonymizer, which reuses the
scanner's own detectors so it scrubs exactly what a scan flags and derives a
**verified** `expects` set:

```bash
python tools/dogfood/anonymize.py real_config.json \
    --host cursor --scope project --relpath .cursor/mcp.json --emit-fixture
```

It prints the scrubbed config and a ready-to-paste `Fixture(...)`. Confirm the
scrubbed structure still reproduces the behavior you're capturing, then paste
the fixture into `corpus.py`. Every real secret is replaced by a same-class
synthetic (a provider-shaped token still matches its provider regex; an
entropy-flagged value becomes a same-length high-entropy placeholder), and home
paths collapse to `/home/user` — so the fixture is a real regression with
nothing sensitive in it.
