"""Online enrichment — the ONLY package that performs network egress.

It is imported lazily by the engine **only** when ``--online`` is passed, so a
default scan never even loads this code (ARCHITECTURE R2, NFR-SEC1). Outbound
requests carry only ``{package, version, ecosystem}`` — never config contents,
paths, or secret fingerprints (review F3).
"""
