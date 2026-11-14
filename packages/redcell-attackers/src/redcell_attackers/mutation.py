"""Mutation operators: which transform to try next when an attack fails.

The transforms themselves are deterministic text rewrites (see
`specs._apply_operators`). The ESCALATION ORDER is deliberate: cheap framing first,
then the operators aimed at filters (encoding hides trigger words from an input
filter, obfuscation spaces out the leaked secret to slip exact-match redaction).
"""
from __future__ import annotations

from dataclasses import replace

from redcell_attackers.specs import AttackSpec

ESCALATION = ("delimiter", "persona", "encoding", "obfuscation")


def mutate(spec: AttackSpec) -> AttackSpec | None:
    """Apply the next unused operator, or None when the operator bank is exhausted."""
    for op in ESCALATION:
        if op not in spec.operators:
            return replace(spec, operators=spec.operators + (op,))
    return None
