# AI Agentic MCPscan

> Local-first, **offline-by-default** security posture scanner for MCP /
> local-agent setups. Find exposed servers, plaintext secrets, over-broad tool
> scopes, and unpinned packages — then fix the highest-impact issues first.

**Status:** ✅ MVP feature-complete (Sprints 1–4 built, full gate green) ·
pending PyPI publish. CLI command: `mcpscan`. License: Apache-2.0.

## What it does (MVP)

- **Discovers** MCP servers on the local machine via socket/process enumeration
  (directly catching `0.0.0.0` / non-loopback exposure) plus a loopback probe of
  `/mcp` and `/sse`.
- **Statically audits** Claude-ecosystem agent configs (`.claude/settings.json`,
  `.mcp.json`, `claude_desktop_config.json`, `.env`) for plaintext secrets,
  auto-approval flags, over-broad tool scopes, and unpinned versions.
- **Scores** each server **A–F** across four dimensions (exposure, credential
  hygiene, tool-scope breadth, version pinning).
- **Reports** a prioritized, **redacted**, advise-only remediation in three
  forms: terminal, a self-contained HTML file, and stable JSON.

## Trust properties (by design)

- **Localhost only** — never touches the LAN or third-party systems.
- **Offline + zero telemetry by default** — `--online` opt-in adds OSV/PyPI
  enrichment and says so.
- **Secrets never leak** — redacted everywhere; `--show-secrets` reveals only a
  masked/partial value, with a warning.
- **Advise-only** — never writes to your config files.
- **Fully stateless** — writes only the report you explicitly ask for.
- **Passes its own scan** — exposes no port, ships no plaintext secret.

## Install

Once published to PyPI:

```bash
pipx install ai-agentic-mcpscan   # provides the `mcpscan` command
```

Or from source today:

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
mcpscan scan --fail-on critical       # CI: exit non-zero only on Critical
mcpscan scan --online                 # opt-in OSV enrichment (discloses egress)
mcpscan scan --show-secrets           # reveal masked (first-2/last-2) values
mcpscan scan --absolute-paths         # show full paths instead of ~
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

MVP is feature-complete across the four sprints (Foundations → Engine →
Reporting → Integration & hardening), built behind a green CI gate (ruff, mypy
--strict, bandit, pytest on macOS/Linux/Windows × Python 3.11–3.13). The only
remaining step is the human-gated PyPI publish.

Roadmap: SARIF + a GitHub code-scanning action, more host adapters (Cursor,
Cline, …), opt-in `--fix`, and authorized-LAN scanning behind an explicit gate.

## License

[Apache-2.0](LICENSE).
