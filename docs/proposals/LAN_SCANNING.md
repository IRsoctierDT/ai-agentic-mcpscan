# Proposal — Authorized-LAN scanning behind an explicit gate

**Status:** Draft, for review · **Supersedes the "later" clause of** ADR-1 ·
**Relates to** FR-D*, NFR-SEC1, threat model §8 · **Target:** post-1.0

> This is a design proposal, not an accepted decision. It exists so the trade-offs
> are on the table **before** any code is written, because the feature deliberately
> touches the tool's single strongest promise: *"Localhost only — never touches the
> LAN or third-party systems."* Nothing here changes default behavior.

---

## 1. Why consider this at all

Today mcpscan finds MCP servers on **the machine it runs on**. But the real
exposure risk is a teammate's laptop, a shared dev box, or a CI runner that has
bound an MCP server to `0.0.0.0` and is now reachable across the office LAN or a
cloud VPC — often unauthenticated, often exposing shell/exec-class tools. The
person best placed to catch that is a security engineer sweeping *their own*
network, and today they have to run mcpscan host-by-host.

The ask: let an **authorized** operator point mcpscan at hosts **they own or are
explicitly permitted to test** and detect exposed MCP endpoints — without the
tool ever becoming a network scanner that a careless (or malicious) user can aim
at third parties.

## 2. The hard constraint

The tool's credibility rests on ADR-1 and the trust properties in the README.
A LAN feature that erodes "localhost only" by default would be a
self-inflicted wound on a *security* tool. Therefore the non-negotiables:

1. **Off by default, always.** A plain `mcpscan scan` must remain byte-for-byte
   localhost-only. No flag, no LAN. Ever.
2. **No implicit target expansion.** The tool must never discover-and-scan hosts
   the operator didn't name. No ARP sweeps, no "scan my whole subnet" as a side
   effect.
3. **Explicit authorization, recorded.** Turning it on requires the operator to
   *assert authorization* for the specific targets, and that assertion is written
   into the report as an audit trail.
4. **Least-intrusive probe only.** Same behavior as the existing loopback probe:
   a single TCP connect + minimal MCP/HTTP handshake to confirm "is an MCP
   server listening here?" No fuzzing, no auth attempts, no payloads, no port
   sweeps beyond the small known MCP port set.
5. **Refuse the obviously-wrong.** Public/routable IP ranges are refused by
   default; only RFC-1918 / RFC-4193 / loopback targets are eligible without a
   second, louder override.

If we cannot hold all five, we should not ship it.

## 3. Proposed design

### 3.1 The authorization gate

Three independent conditions must all be true for a single LAN probe to fire:

| Gate | Mechanism | Rationale |
|---|---|---|
| **Intent** | `--lan <target>` flag is present (repeatable) | No accidental LAN traffic |
| **Attestation** | `--i-am-authorized` *and* an interactive typed confirmation (skippable only with `--assume-yes` for CI, which is logged) | Forces a conscious "I own this" |
| **Scope** | target resolves to a private range; public IPs need `--allow-public-targets` | Fail-closed on the dangerous case |

`<target>` accepts a single IP, a hostname, or a **bounded** CIDR (e.g. `/24`
max by default; larger needs `--max-hosts N`). CIDR expansion is explicit and
capped, never open-ended.

### 3.2 What a probe actually does

Reuse `discovery/probe.py` unchanged in spirit, extended from `127.0.0.1` to the
authorized target:

- TCP connect to each MCP-candidate port (the existing small set: `/mcp`, `/sse`
  probe on the known ports), with a short timeout.
- On connect, send the **same** minimal handshake the loopback probe uses to
  decide `looks_like_mcp`. Nothing more.
- Record: reachable? looks like MCP? bind exposure (a remote host answering *is*
  the exposure finding). **We cannot read a remote filesystem**, so LAN mode
  produces **exposure findings only** — no credential/pinning/tool-scope checks
  (those need the config file, which is local). This is a feature: it keeps the
  remote interaction to the absolute minimum.

Concurrency is bounded (small worker pool), each host is rate-limited, and the
whole run has a global deadline. A `--dry-run` prints the exact target list and
port plan **without sending a packet**.

### 3.3 CLI surface (illustrative)

```
mcpscan scan \
  --lan 10.0.5.0/24 \
  --lan 192.168.1.42 \
  --i-am-authorized \
  --max-hosts 256 \
  --lan-timeout 1.5 \
  --dry-run           # show plan, send nothing
```

Refusals are loud and specific: `refusing to scan 8.8.8.8: public IP requires
--allow-public-targets (you are asserting authorization to test this host)`.

### 3.4 Report & audit trail

Every LAN run stamps the report (all renderers) with:

- the resolved target list and port plan,
- the attestation record ("operator asserted authorization at <caller-supplied
  label>"),
- per-host reachability + MCP-detection outcome,
- a machine-readable `lan_scan` block in JSON/SARIF.

Nothing about the *remote* host's secrets can appear, because we never read them.

## 4. Threat-model additions (§8 deltas)

| Risk | Mitigation |
|---|---|
| Tool used to scan third parties | Triple gate + private-range default + refusal messaging + recorded attestation. Not a technical guarantee of authorization, but a deliberate, logged, high-friction path — the operator owns the assertion. |
| Accidental broad sweep | No implicit expansion; CIDR capped; `--dry-run`; global host cap. |
| Intrusive/abusive probing | Least-intrusive connect+handshake only; bounded concurrency; rate limit; timeouts; no auth attempts, no payloads. |
| "Security tool ships a network weapon" optics | Feature is inert without explicit flags; docs frame it as *authorized self-assessment*; SECURITY.md + a dedicated `docs/LAN_SCANNING.md` operator page state the legal/ethical boundary plainly. |
| Egress claims broken | NFR-SEC1's "offline by default" still holds for `scan`; LAN mode is a distinct, opt-in egress path documented exactly like `--online`. |

## 5. Testing

- **No real network in the suite.** The probe transport is injected (as
  `enumerate_listening`/`osv_fetch` already are), so tests drive a fake socket
  layer: reachable/unreachable/looks-like-mcp/timeout, and assert gate refusals.
- Gate-logic tests: missing attestation → refuse; public IP → refuse; CIDR over
  cap → refuse; `--dry-run` sends nothing (asserted via a transport that fails
  the test if called).
- A golden "authorized private /30" run producing a deterministic report block.

## 6. Phasing

1. **Phase A — gate + single-host probe.** `--lan <ip>` for one private host, full
   attestation gating, exposure-only findings, audit stamp. Smallest safe slice.
2. **Phase B — bounded CIDR** with host cap + concurrency + rate limit.
3. **Phase C — reporting polish**: `lan_scan` JSON/SARIF block, `--dry-run` plan
   output, operator docs page.

Ship A, dogfood it (see the real-lab proposal), then B/C.

## 7. Open questions for you

1. **Attestation ergonomics.** Interactive typed confirmation by default with a
   logged `--assume-yes` for CI — acceptable, or do you want a stronger artifact
   (e.g. an authorization file listing targets + a signed-off owner)?
2. **Default scope.** RFC-1918 + RFC-4193 + loopback only, public IPs behind a
   second flag — right line? Or should public targets be refused outright, no
   override, keeping the tool categorically private-only?
3. **CIDR cap.** Default `/24` (256 hosts) with `--max-hosts` to raise — sensible
   default, or smaller (e.g. `/27`) to force intentionality?
4. **Scope creep guard.** Do you want LAN mode to be a *separate subcommand*
   (`mcpscan lan ...`) rather than flags on `scan`, so the localhost path can
   never grow a LAN code branch by accident? (I lean yes — cleaner blast-radius
   separation.)
5. **Naming.** `--lan` vs `--authorized-target` vs a `lan` subcommand — which
   framing best signals "this is for hosts you own"?

## 8. Recommendation

Proceed **only** if we commit to the five non-negotiables in §2 and the
separate-subcommand isolation in Q4. My recommendation: build **Phase A as a
distinct `mcpscan lan` subcommand**, exposure-only, triple-gated, with the audit
stamp — then validate it in the real-lab dogfood before expanding to CIDR. If any
of the §2 constraints feels shaky to you, the right call is to **not ship** and
keep "localhost only" absolute; the feature is worth having, but not at the cost
of the promise that makes the tool trustworthy.
