# AI Agentic MCPscan

> Local-first, **offline-by-default** security posture scanner for MCP /
> local-agent setups. Find exposed servers, plaintext secrets, over-broad tool
> scopes, and unpinned packages — then fix the highest-impact issues first.

**Status:** Beta (`v0.1.x`) — safe to run (read-only, offline by default), but
the CLI surface and check heuristics may still change before `v1.0.0`. CLI
command: `mcpscan`. License: Apache-2.0.

## What it does (MVP)

- **Discovers** MCP servers on the local machine via socket/process enumeration
  (directly catching `0.0.0.0` / non-loopback exposure) plus a loopback probe of
  `/mcp` and `/sse`.
- **Statically audits** Claude-ecosystem (`.claude/settings.json`, `.mcp.json`,
  `claude_desktop_config.json`), **Cursor** (`~/.cursor/mcp.json`,
  `.cursor/mcp.json`), **Windsurf** (`~/.codeium/windsurf/mcp_config.json`),
  **Cline** (VS Code `globalStorage/…/cline_mcp_settings.json`), **VS Code**
  (`.vscode/mcp.json`, user `mcp.json`), **Zed** (`.zed/settings.json`, user
  `~/.config/zed/settings.json`), and **Continue** (`~/.continue/config.yaml`,
  `.continue/config.yaml` — needs the `[yaml]` extra) agent configs — plus
  `.env` — for plaintext secrets, auto-approval flags, over-broad tool scopes,
  and unpinned versions.
- **Scores** each server **A–F** across four dimensions (exposure, credential
  hygiene, tool-scope breadth, version pinning).
- **Reports** a prioritized, **redacted**, advise-only remediation in four
  forms: terminal, a self-contained HTML file, stable JSON, and SARIF 2.1.0 for
  GitHub code scanning.

## Trust properties (by design)

- **Localhost only** — never touches the LAN or third-party systems.
- **Offline + zero telemetry by default** — `--online` opt-in adds OSV/PyPI
  enrichment and says so.
- **Secrets never leak** — redacted everywhere; `--show-secrets` reveals only a
  masked/partial value, with a warning.
- **Advise-only by default** — never writes to your config files unless you pass
  `--fix`, which applies only safe, reversible tool-scope edits and backs up
  every file it touches first.
- **Fully stateless** — writes only the report you explicitly ask for.
- **Passes its own scan** — exposes no port, ships no plaintext secret.

## Install

```bash
pipx install ai-agentic-mcpscan            # provides the `mcpscan` command
pipx install "ai-agentic-mcpscan[yaml]"    # + audit Continue's config.yaml
pipx install "ai-agentic-mcpscan[crypto]"  # + verify ed25519 LAN manifests
```

The base install is stdlib-only (plus `psutil`). The optional `[yaml]` and
`[crypto]` extras enable Continue config auditing and library-based Ed25519
manifest verification, respectively.

Or from source:

```bash
git clone https://github.com/IRsoctierDT/ai-agentic-mcpscan.git
cd ai-agentic-mcpscan && pipx install .
```

Requires **Python 3.11+** (macOS, Linux, Windows).

## Usage

```bash
mcpscan scan                          # scan localhost + cwd project configs
mcpscan scan --root ~/project         # scan a specific project root (repeatable)
mcpscan scan --json report.json       # also write a stable JSON report (0600)
mcpscan scan --html report.html       # also write a self-contained HTML report
mcpscan scan --sarif results.sarif    # also write SARIF 2.1.0 for code scanning
mcpscan scan --fail-on critical       # CI: exit non-zero only on Critical
mcpscan scan --online                 # opt-in OSV enrichment (discloses egress)
mcpscan scan --show-secrets           # reveal masked (first-2/last-2) values
mcpscan scan --absolute-paths         # show full paths instead of ~
mcpscan scan --fix                    # apply safe tool-scope fixes (backs up first)
mcpscan lan  --manifest auth.toml ... # authorized network assessment (see below)
```

Exit code is non-zero when a finding meets `--fail-on` (default: `high`), so it
drops straight into CI.

### Example output

```
AI Agentic MCPscan — overall posture: F
  dimensions: credential=D, exposure=A, pinning=A, tool_scope=C
  findings: 1 critical, 1 high, 2 medium

▶ ~/.mcp.json#weather  [grade F]
  [CRITICAL] Plaintext OpenAI API key in config
             where: ~/.mcp.json
             secret: [redacted len=37 sha256:c0cc596e]
             fix:   Remove the literal value from the file. Reference it from a
                    secret manager … and rotate the exposed credential.
  [MEDIUM  ] Server 'weather' runs an unpinned package via npx
             fix:   Pin the package to an exact version (e.g. npx some-pkg@1.2.3).
```

### Fixing findings (`--fix`)

The tool is advise-only by default. `--fix` is the one explicit exception that
writes to your configs, and it stays deliberately conservative:

- **Scope:** removes over-broad **tool-scope** grants only — dangerous
  (shell/exec-class) and wildcard entries from `permissions.allow` and each
  server's `autoApprove`, using the exact predicates the scanner flags with, so
  a fixed config re-scans clean.
- **Reversible:** every modified file is copied to `<path>.mcpscan.bak` before
  the edit, and the file's permissions are preserved.
- **Nothing invented:** credential and pinning findings are **not** auto-fixed —
  a safe rewrite would need a new home for the secret or a specific version the
  tool can't know offline, so those stay manual (the report tells you what to do).

```
$ mcpscan scan --root . --fix
note: --fix modifies config files in place (backup written to <path>.mcpscan.bak) …
fixed ./.mcp.json (1 change(s); backup: ./.mcp.json.mcpscan.bak)
    removed 'Bash(*)' from permissions.allow [SCOPE-DANGEROUS-ALLOW]
applied 1 fix(es). Re-run mcpscan to confirm.
```

### GitHub code scanning (SARIF)

`--sarif` writes a SARIF 2.1.0 log that GitHub ingests as code-scanning alerts on
the **Security** tab, with per-finding severity (`security-severity`) and stable
fingerprints so alerts track across commits. Paths inside the scanned repo are
emitted repo-relative so alerts annotate the offending line; secrets are never
present (only the redacted fingerprint). SARIF covers **config-file** findings;
running-socket exposure (no source file) stays in the terminal/JSON/HTML views.
Drop this into a workflow:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-python@v5
    with: { python-version: "3.11" }
  - run: pip install ai-agentic-mcpscan
  - run: mcpscan scan --sarif results.sarif --fail-on critical
    continue-on-error: true
  - uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: results.sarif }
```

This repo dogfoods it in [`.github/workflows/mcpscan.yml`](.github/workflows/mcpscan.yml).

### Authorized network assessment (`mcpscan lan`)

`mcpscan scan` is localhost-only. `mcpscan lan` is a **separate, gated** command
for assessing MCP exposure on hosts **you are authorized to test** — and it is
**inert without a signed authorization manifest**. Governing principle:
*discovery never converts into authority.* It is exposure-only (never reads a
remote config), private-address by default, and bounded by immutable budgets.

```bash
mcpscan lan --manifest auth.toml \
            --signature auth.toml.sig \
            --allowed-signers allowed_signers \
            --invoker human \
            --dry-run            # verify + print the plan; send no packets
```

The manifest is a signed TOML file naming exact targets, ports, operator, and
expiry:

```toml
authorization_id = "ENG-2026-0710"
operator         = "you@example.com"
expires_at       = "2026-07-10T23:59:59Z"
targets          = ["192.168.10.20/32"]   # exact hosts / /32 (a human may use a capped CIDR)
ports            = [3000, 8000]
```

Sign it with your SSH key (`ssh-keygen -Y sign -n mcpscan-lan -f key auth.toml`).
`--invoker agent` gets tighter budgets and exact-hosts-only. Public targets are
refused unless named in an `--enterprise-policy` file. Step-by-step:
[`docs/LAN_OPERATOR_GUIDE.md`](docs/LAN_OPERATOR_GUIDE.md); full design and threat
model: [`docs/proposals/LAN_SCANNING.md`](docs/proposals/LAN_SCANNING.md).

## Documentation

| Doc | What it is |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Full product & technical specification (testable requirements, scoring rubric, threat model, DoD). |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 15 architecture decision records. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component model, dependency direction, trust boundaries. |
| [docs/BACKLOG.md](docs/BACKLOG.md) | Sprint-tagged tickets + requirement→ticket traceability. |
| [docs/SECURITY_SIGNOFF.md](docs/SECURITY_SIGNOFF.md) | Threat-model verification matrix (security sign-off). |
| [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) | Reporting policy · contributor guide. |

## Status & roadmap

**v0.1.0 is released on [PyPI](https://pypi.org/project/ai-agentic-mcpscan/)** —
feature-complete across the four sprints (Foundations → Engine → Reporting →
Integration & hardening), behind a green CI gate (ruff, mypy --strict, bandit,
pytest on macOS/Linux/Windows × Python 3.11–3.13), with SBOM + checksums on every
release. It's **Beta**: safe to run, but the CLI surface and check heuristics may
still change before `v1.0.0`.

Roadmap toward 1.0: real-world dogfooding against stakeholder configs. **Done:**
SARIF 2.1.0 output + a GitHub code-scanning workflow, opt-in `--fix` for
over-broad tool scopes, **seven** host adapters (Claude, Cursor, Windsurf, Cline,
VS Code, Zed, Continue), `mcpscan lan` — authorized, exposure-only network
assessment behind a signed manifest — and a
[dogfood harness](tools/dogfood/README.md) that gates every check against a
clean+messy corpus across all hosts (0 false positives / 0 false negatives, run
in CI).

## License

[Apache-2.0](LICENSE).
