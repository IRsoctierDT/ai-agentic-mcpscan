# Security Policy

AI Agentic MCPscan is a security tool, so we hold its own posture to a high bar.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Open a [GitHub security advisory](https://github.com/IRsoctierDT/IANUA-Broker/security/advisories/new)
  (preferred), or
- Open a regular issue **without** sensitive details and ask for a private
  channel.

Please do **not** disclose publicly until a fix is available. We aim to
acknowledge reports within a few days.

## What we care about most

Because this tool reads configuration files and may handle secrets, the highest-
severity classes for us are:

1. **Secret leakage** — any path where a raw secret value could reach output,
   logs, or disk. (By design, secrets are fingerprinted at detection and never
   stored; a regression here is critical.)
2. **Unexpected egress** — any outbound network activity on a default
   (non-`--online`) run. The default must be fully offline.
3. **Path traversal / unsafe file handling** — reading outside the intended
   scope, following symlinks out of root, or crashing on hostile input.
4. **Privilege/scope overreach** — anything that reaches beyond localhost.

## Design guarantees (and how they're enforced)

- **Offline by default, zero telemetry.** Egress lives only in `enrichment/`,
  imported solely under `--online`.
- **Localhost only.** The probe refuses any non-loopback target.
- **Secrets redacted everywhere.** `--show-secrets` reveals at most first-2/last-2
  characters, never the raw value.
- **Advise-only.** The tool never modifies your config files.
- **Stateless.** It writes only the report you explicitly request, with `0600`
  permissions.

See [`docs/SECURITY_SIGNOFF.md`](docs/SECURITY_SIGNOFF.md) for the threat model
and verification matrix.

## Supported versions

Pre-1.0: only the latest released version is supported.
