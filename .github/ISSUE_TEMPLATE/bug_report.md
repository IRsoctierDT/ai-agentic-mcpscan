---
name: Bug report
about: Report incorrect behavior (including false positives / false negatives)
title: "[bug] "
labels: bug
---

**⚠️ Do not paste real secrets or full config contents.** Redact anything
sensitive — `mcpscan` is designed so you never need to share a secret to report
a bug.

## What happened
A clear description of the bug.

## Expected
What you expected instead.

## Finding accuracy (if relevant)
- [ ] False positive (flagged something that is actually fine)
- [ ] False negative (missed something it should have flagged)

A **minimal, sanitized** config that reproduces it:

```json
{ }
```

## Environment
- mcpscan version (`mcpscan --version`):
- OS:
- Python version:
- Command used (with flags):
