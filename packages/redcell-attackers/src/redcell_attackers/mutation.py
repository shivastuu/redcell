"""RLVR mutation operators.

In the real build a cheap SLM (Qwen/Gemma) generates these variants — the
high-volume, ~90%-cheaper workload. Here they are deterministic string
transforms so the search runs offline and reproducibly. The ESCALATION ORDER is
deliberate: cheap framing first, then the operators that defeat probabilistic
filters (encoding bypasses the input classifier, obfuscation bypasses redaction).
"""
from __future__ import annotations

from dataclasses import replace

from redcell_attackers.specs import AttackSpec

ESCALATION = ("delimiter", "persona", "encoding", "obfuscation", "language")


def mutate(spec: AttackSpec) -> AttackSpec | None:
    """Apply the next unused operator, or None when the operator bank is exhausted."""
    for op in ESCALATION:
        if op not in spec.operators:
            return replace(spec, operators=spec.operators + (op,))
    return None
