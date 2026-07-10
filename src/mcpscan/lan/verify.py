# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Authorization-manifest signature verification (LAN proposal §3.1).

A LAN run is inert until the manifest's detached signature verifies. Two schemes
are supported (operator decision): ``ssh`` (default, dependency-free) via
``ssh-keygen -Y verify``, and ``ed25519`` (a ``[crypto]`` extra, not in this
build — refused, never downgraded). The verifier is injectable so tests never
shell out.
"""

from __future__ import annotations

# Justification for the bandit suppressions below: ssh-keygen is invoked with a
# fixed argument vector and shell=False, so nothing here is shell-interpreted; the
# only variable inputs (operator, file paths) are passed as argv items, not a
# command string, and cannot inject.
import subprocess  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .sanitize import sanitize_remote

SSH_NAMESPACE = "mcpscan-lan"

# (manifest_bytes, signature_path, allowed_signers, operator) -> VerifyResult
Verifier = Callable[[bytes, Path, Path, str], "VerifyResult"]


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of verifying a manifest signature."""

    ok: bool
    detail: str


def verify_ssh(
    manifest_bytes: bytes,
    signature_path: Path,
    allowed_signers: Path,
    operator: str,
) -> VerifyResult:
    """Verify a detached SSH signature over the manifest via ``ssh-keygen``.

    Runs ``ssh-keygen -Y verify`` with a fixed argument vector (no shell), the
    signature and allowed-signers files, the operator identity, and a fixed
    namespace. The manifest bytes are fed on stdin so the signature binds to the
    exact content that was parsed.
    """
    cmd = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed_signers),
        "-I",
        operator,
        "-n",
        SSH_NAMESPACE,
        "-s",
        str(signature_path),
    ]
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            input=manifest_bytes,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        return VerifyResult(False, "ssh-keygen not found; install OpenSSH to use the 'ssh' scheme")
    except (OSError, subprocess.SubprocessError) as exc:
        return VerifyResult(False, f"signature verification could not run: {exc}")

    if proc.returncode == 0:
        return VerifyResult(True, "signature verified (ssh)")
    # ssh-keygen output is external; sanitize before surfacing.
    detail = sanitize_remote(proc.stderr or proc.stdout or b"verification failed", max_len=160)
    return VerifyResult(False, f"signature rejected: {detail}")


def verify_manifest(
    *,
    scheme: str,
    manifest_bytes: bytes,
    signature_path: Path | None,
    allowed_signers: Path | None,
    operator: str,
    verifier: Verifier | None = None,
) -> VerifyResult:
    """Verify a manifest under its declared scheme (dispatch + fail-closed)."""
    if scheme == "ed25519":
        return VerifyResult(
            False,
            "manifest uses the 'ed25519' scheme; install the '[crypto]' extra to verify it",
        )
    if scheme != "ssh":  # pragma: no cover - manifest validation already constrains this
        return VerifyResult(False, f"unsupported signature scheme {scheme!r}")
    if signature_path is None or allowed_signers is None:
        return VerifyResult(False, "the 'ssh' scheme requires --signature and --allowed-signers")
    verify = verifier or verify_ssh
    return verify(manifest_bytes, signature_path, allowed_signers, operator)
