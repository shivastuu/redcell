"""The RLVR worker loop: seed -> render -> execute -> verify -> mutate -> harvest.

The reward IS the deterministic verifier verdict. The loop terminates on a
confirmed breach OR when the operator bank / budget is exhausted — never
"run until it works". This is the generic engine every attack worker shares.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from redcell_attackers.mutation import mutate
from redcell_attackers.specs import AttackGoal, AttackSpec
from redcell_core.config import Budget
from redcell_core.schemas import AttackTrace, DefenseConfig, Verdict
from redcell_core.tracing import traced
from redcell_verifiers.registry import run_all


@dataclass(frozen=True)
class Attempt:
    goal: AttackGoal
    spec: AttackSpec
    breached: bool
    mutations: int          # mutations-to-breach (or to exhaustion)
    target_calls: int
    trace: AttackTrace
    verdict: Verdict


@traced("rlvr.search")
def search(goal: AttackGoal, harness, defense: DefenseConfig,
           budget: Optional[Budget] = None) -> Attempt:
    budget = budget or Budget()
    spec = AttackSpec(goal)
    calls = mutations = 0
    verdict = None
    while True:
        trace = harness.run(spec, defense)
        verdict = run_all(trace)
        calls += 1
        if verdict.breach:
            return Attempt(goal, spec, True, mutations, calls, trace, verdict)
        nxt = mutate(spec)
        if nxt is None or mutations >= budget.max_mutations or calls >= budget.max_target_calls:
            return Attempt(goal, spec, False, mutations, calls, trace, verdict)
        spec, mutations = nxt, mutations + 1


def replay(spec: AttackSpec, goal: AttackGoal, harness, defense: DefenseConfig) -> Attempt:
    """Score a FROZEN spec against a defense config with mutation DISABLED.

    This is the scientific control: same corpus, both conditions, no stronger
    attacker — so the ASR delta is attributable to the defenses alone.
    """
    trace = harness.run(spec, defense)
    verdict = run_all(trace)
    return Attempt(goal, spec, verdict.breach, 0, 1, trace, verdict)
