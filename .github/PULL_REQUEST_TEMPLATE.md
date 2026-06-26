## What & why
Briefly: what this changes and the motivation.

## Checklist
- [ ] `ruff check .`, `ruff format --check .`, `mypy src`, `bandit -r src`,
      `pytest` all pass locally
- [ ] New logic has tests, including failure/edge cases
- [ ] New check ships with a clean/negative fixture (zero findings on good input)
- [ ] No raw secret can reach output, logs, or disk
- [ ] No egress added outside `enrichment/` / outside `--online`
- [ ] No writes to user config files (advise-only preserved)
- [ ] Docs updated if behavior/flags changed

## Notes for the reviewer
Anything you want a second set of eyes on (trust boundaries, false-positive risk).
