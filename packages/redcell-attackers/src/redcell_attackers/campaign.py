"""Campaign orchestration (the runnable reference of the LangGraph supervisor).

Controlled agency in plain Python: a fixed worker set, per-attack budgets,
bounded loops, and a deterministic reward oracle. `coordinator.py` is the
production LangGraph version of exactly this control flow.

Three phases:
  discover  — undefended, mutation ON  -> builds the corpus + baseline ASR
  replay    — frozen corpus, mutation OFF, vs a defense -> the scientific control
  adaptive  — mutation ON vs the DEFENDED target -> the honest number
"""
from __future__ import annotations

from redcell_attackers.rlvr import Attempt, replay, search
from redcell_attackers.specs import AttackGoal, build_catalog
from redcell_core.config import Budget
from redcell_core.schemas import DefenseConfig


def discover(harness, goals: list[AttackGoal] | None = None,
             budget: Budget | None = None) -> list[Attempt]:
    goals = goals or build_catalog()
    return [search(g, harness, DefenseConfig.baseline(), budget) for g in goals]


def replay_corpus(corpus: list[Attempt], harness, defense: DefenseConfig) -> list[Attempt]:
    return [replay(a.spec, a.goal, harness, defense) for a in corpus]


def adaptive(corpus: list[Attempt], harness, defense: DefenseConfig,
             budget: Budget | None = None) -> list[Attempt]:
    """Turn the mutation loop loose on the DEFENDED target — ASR recovery."""
    return [search(a.goal, harness, defense, budget) for a in corpus]
