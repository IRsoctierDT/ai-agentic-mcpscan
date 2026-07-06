# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

First public release — a local-first, offline-by-default security posture
scanner for MCP / local-agent setups (CLI: `mcpscan`).

### Added

- **CLI** — `mcpscan scan` with `--root`, `--json`, `--html`, `--online`,
  `--show-secrets`, `--absolute-paths`, and `--fail-on {critical,high,medium,low}`;
  process exit code is driven by the highest finding severity versus the
  threshold.
- **Discovery** — listening-socket enumeration via psutil (degrades gracefully
  when the OS denies introspection), a loopback-only MCP confirmation probe
  (`/mcp`, `/sse`), and declared-server discovery from Claude Code / Claude
  Desktop configs through a `HostAdapter` seam.
- **Checks (four dimensions)** — exposure (non-loopback / `0.0.0.0` binds),
  credentials (plaintext secrets by provider pattern + entropy, and secret-at-rest
  file permission / git-tracking), tool scope (auto-approved and wildcard
  permission grants), and version pinning (unpinned `npx`/`uvx`/etc.).
- **Scoring** — deterministic A–F grading per server, per dimension, and overall.
- **Reports** — ANSI terminal output, stable machine-readable JSON
  (`schema_version` "1.0"), and a self-contained, offline HTML report.
- **Online enrichment** — opt-in `--online` OSV advisory lookups for pinned
  packages; the egress module is isolated and imported only on this path.
- **Self-scan** (`mcpscan` passes its own checks) and cross-platform CI
  (macOS/Linux/Windows × Python 3.11–3.13).

### Security & trust properties

- Offline by default; no network egress unless `--online` is passed.
- Loopback-only probing — non-loopback targets are refused (fail closed).
- Secrets are reduced to fingerprints at detection; raw values never reach the
  domain model, reports, or logs. `--show-secrets` reveals only a masked form and
  prints a warning.
- No file writes except the reports you explicitly request, created `0600` where
  supported.
- Home directories are relativized to `~/…` by default (`--absolute-paths` opts
  out).

### Packaging

- Apache-2.0 licensed, with a `NOTICE` file and per-file SPDX headers.
- Publishes to PyPI via Trusted Publishing (OIDC); the version is single-sourced
  from `pyproject.toml`.

[0.1.0]: https://github.com/IRsoctierDT/ai-agentic-mcpscan/releases/tag/v0.1.0
