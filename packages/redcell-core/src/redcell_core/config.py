"""Central config + the model router (the one file the routing policy lives in).

Model tier is assigned by ROLE, never chosen by a worker — that is both the cost
lever (~90% cheaper mutation) and a control mechanism. Swap the ids here after
verifying them against the current provider docs (they drift).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# NOTE: verify these ids/prices against provider docs before quoting them anywhere.
PLANNER_MODEL = os.getenv("REDCELL_PLANNER_MODEL", "claude-opus-4-8")
JUDGE_MODEL = os.getenv("REDCELL_JUDGE_MODEL", "claude-sonnet-5")
TARGET_MODEL = os.getenv("REDCELL_TARGET_MODEL", "claude-haiku-4-5")
MUTATOR_MODEL = os.getenv("REDCELL_MUTATOR_MODEL", "Qwen/Qwen3-8B")


@dataclass(frozen=True)
class Budget:
    max_mutations: int = 256
    max_target_calls: int = 400
    max_usd: float = 5.0
    max_wallclock_s: float = 1800.0


def route(task_kind: str) -> str:
    """task_kind -> model id. The whole routing policy, in one place."""
    return {
        "plan": PLANNER_MODEL,     # rare, quality-critical
        "mutate": MUTATOR_MODEL,   # high-volume, cheap
        "target": TARGET_MODEL,    # the system under test
        "judge": JUDGE_MODEL,      # audited secondary instrument
    }.get(task_kind, TARGET_MODEL)
