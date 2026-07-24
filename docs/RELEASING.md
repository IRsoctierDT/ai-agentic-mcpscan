# Releasing AI Agentic MCPscan

Publishing is **human-gated** and uses PyPI **Trusted Publishing** (OIDC), so no
API token is ever stored in the repo. The `Release` workflow
(`.github/workflows/release.yml`) runs only when you publish a GitHub Release.

## One-time setup (you, once)

1. **Create the PyPI Trusted Publisher** (no project needs to exist yet —
   use "pending publisher"):
   - PyPI → your account → *Publishing* → *Add a pending publisher*.
   - Project name: `ai-agentic-mcpscan`
   - Owner: `IRsoctierDT` · Repository: `IANUA-Broker`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
2. **(Recommended) Protect the `pypi` environment** in GitHub:
   - Repo → Settings → Environments → `pypi` → add yourself as a required
     reviewer. This makes the actual upload require your one-click approval even
     after a release is published.

## Each release

1. Ensure `main` is green (CI passes on all OS / Python versions).
2. Bump the version in `pyproject.toml` (`[project].version`) — the single
   source of truth. `mcpscan.__version__` is derived from it via the installed
   package metadata, so there is nothing else to keep in sync. The release
   workflow fails if the git tag doesn't match this field.
3. Commit the bump and push to `main`.
4. Tag and create the release:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   gh release create v0.1.0 --title "v0.1.0" --notes "First public release."
   ```
5. The `Release` workflow builds the sdist+wheel, verifies the tag matches the
   version, and (after your environment approval, if enabled) publishes to PyPI.
6. Verify: `pipx install ai-agentic-mcpscan` on a clean machine.

## Notes

- The version-vs-tag guard prevents publishing a mismatched build.
- To do a dry run first, publish to TestPyPI by adding a `repository-url` to the
  publish step and a corresponding TestPyPI trusted publisher.
