# AI Agentic MCPscan

> Local-first, **offline-by-default** security posture scanner for MCP /
> local-agent setups. Find exposed servers, plaintext secrets, over-broad tool
> scopes, and unpinned packages — then fix the highest-impact issues first.

**Status:** 📐 Specification complete · build not yet started. CLI command:
`mcpscan`. License: Apache-2.0.

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

## Install (once published)

```bash
pipx install ai-agentic-mcpscan   # provides the `mcpscan` command
mcpscan scan
```

Requires **Python 3.11+** (macOS, Linux, Windows).

## Documentation

| Doc | What it is |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Full product & technical specification (testable requirements, scoring rubric, threat model, DoD). |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 15 architecture decision records. |
| [docs/BACKLOG.md](docs/BACKLOG.md) | Sprint-tagged tickets + requirement→ticket traceability. |

## Status & roadmap

The spec and decisions are confirmed. Build proceeds in four sprints —
Foundations → Engine → Reporting → Integration & hardening — only after Principal
Architect validation and a full-team backlog review (see `docs/BACKLOG.md`).

## License

[Apache-2.0](LICENSE).
