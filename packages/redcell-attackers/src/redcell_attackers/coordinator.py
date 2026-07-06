"""Attacker orchestration — the REAL LangGraph supervisor.

Requires deps:  uv sync   (installs `langgraph`)
Run:            uv run python -m redcell_attackers.coordinator

This is the production `StateGraph` version of `campaign.discover`: a supervisor
that fans out one worker per goal via `Send()` (map) and reduces their attempts
into an additive channel (reduce). It embodies the controlled-agency invariants:

  * supervisor topology — the graph has ZERO worker->worker edges
  * fixed worker step, no runtime agent spawning
  * additive `attempts` channel with a reducer (safe under parallel fan-out)
  * a durable checkpointer (resume a crashed campaign by thread_id)
  * the reward is the deterministic verifier (inside `search`), never an LLM

The plain-Python `campaign.py` runs the identical control flow offline (no deps)
so the whole system is demonstrable without installing LangGraph.
"""
from __future__ import annotations

from operator import add
from typing import Annotated, TypedDict

from redcell_attackers.rlvr import Attempt, search
from redcell_attackers.specs import AttackGoal, build_catalog
from redcell_core.config import Budget
from redcell_core.schemas import DefenseConfig


class CampaignState(TypedDict):
    goals: list                      # coordinator-owned (workers never write it)
    attempts: Annotated[list, add]   # additive: each worker appends its Attempt


def build_graph(harness, defense: DefenseConfig, budget: Budget, checkpointer=None):
    """Compile the supervisor graph. `checkpointer` (e.g. AsyncPostgresSaver /
    InMemorySaver) enables durable resume; pass None for a one-shot run."""
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Send

    def plan(state: CampaignState) -> dict:
        # In discover-mode the plan IS the catalog; in replay-mode it's a frozen corpus.
        return {}

    def fan_out(state: CampaignState):
        # conditional edge -> one Send per goal (the map). No worker->worker edges exist.
        return [Send("worker", {"goal": g}) for g in state["goals"]]

    def worker(payload: dict) -> dict:
        # the RLVR loop; reward = deterministic verifier. Returns one Attempt.
        attempt = search(payload["goal"], harness, defense, budget)
        return {"attempts": [attempt]}

    g = StateGraph(CampaignState)
    g.add_node("plan", plan)
    g.add_node("worker", worker)
    g.add_edge(START, "plan")
    g.add_conditional_edges("plan", fan_out, ["worker"])
    g.add_edge("worker", END)
    return g.compile(checkpointer=checkpointer)


def discover(harness, goals: list[AttackGoal] | None = None,
             defense: DefenseConfig | None = None, budget: Budget | None = None,
             thread_id: str = "campaign-1") -> list[Attempt]:
    """LangGraph-driven discovery — the drop-in equivalent of campaign.discover."""
    goals = goals or build_catalog()
    graph = build_graph(harness, defense or DefenseConfig.baseline(), budget or Budget())
    final = graph.invoke({"goals": goals, "attempts": []},
                         config={"configurable": {"thread_id": thread_id}})
    return final["attempts"]


if __name__ == "__main__":
    import sys
    try:
        import langgraph  # noqa: F401
    except ImportError:
        sys.exit("LangGraph not installed. Run `uv sync`, then re-run. "
                 "(The offline equivalent is `python3 scripts/run_campaign.py`.)")
    from redcell_target.harness import SimHarness
    attempts = discover(SimHarness())
    breached = sum(a.breached for a in attempts)
    print(f"LangGraph campaign: {breached}/{len(attempts)} goals breached (undefended). "
          f"ASR={breached / len(attempts) * 100:.1f}%")
