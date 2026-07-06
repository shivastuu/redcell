"""Content-addressed identifiers.

The attempt_id is what makes crash-resume safe against a live target: the
orchestrator's idempotent reducer keys on it, so replaying a checkpoint never
re-fires an attack that already ran.
"""
from __future__ import annotations

import hashlib


def attempt_id(technique: str, rendered_payload: str, target_hash: str,
               corpus_version: str = "dev") -> str:
    """Stable id = sha256(technique | payload | target | corpus_version)."""
    h = hashlib.sha256()
    for part in (technique, rendered_payload, target_hash, corpus_version):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def source_version(*paths: str) -> str:
    """verifier_version = sha256 over the verifier source + policy files.

    Pinned per frozen corpus so pre/post-defense runs score under identical
    criteria. Pass the paths of the files that define the verdict.
    """
    h = hashlib.sha256()
    for p in sorted(paths):
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except OSError:
            h.update(p.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:16]
