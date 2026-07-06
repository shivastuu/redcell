"""The verifier registry — runs every deterministic oracle and aggregates.

Purity contract: no network, no LLM, no clock in the reward path. Same
AttackTrace in -> same Verdict out, forever. That is what makes the headline
before/after number reproducible and CI-gateable.
"""
from __future__ import annotations

import os

from redcell_core.ids import source_version
from redcell_core.schemas import AttackTrace, Verdict
from redcell_core.tracing import traced
from redcell_verifiers import canary, pii_secret, schema, unauthorized_tool

# verifier_version pins the exact criteria a corpus was scored under.
_HERE = os.path.dirname(__file__)
VERIFIER_VERSION = source_version(
    os.path.join(_HERE, "canary.py"),
    os.path.join(_HERE, "unauthorized_tool.py"),
    os.path.join(_HERE, "pii_secret.py"),
    os.path.join(_HERE, "schema.py"),
)


@traced("verifier.run_all", run_type="tool")
def run_all(trace: AttackTrace) -> Verdict:
    results = (
        canary.verify(trace, VERIFIER_VERSION),
        unauthorized_tool.verify(trace, verifier_version=VERIFIER_VERSION),
        pii_secret.verify(trace, VERIFIER_VERSION),
        schema.verify(trace, VERIFIER_VERSION),
        # TODO Phase 3: precondition-bypass verifier (V5)
    )
    return Verdict(attempt_id=trace.attempt_id, results=results)
