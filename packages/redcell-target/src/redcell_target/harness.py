"""TargetHarness — the seam between attackers and the system under test.

Two implementations behind one interface:
  * SimHarness  — the deterministic offline simulator (runs now, no deps).
  * LiveHarness — the real Claude Haiku agent, driving the FastMCP server via an
                  in-memory MCP client + a Claude tool-use loop (see live_agent.py).
Because both return the same AttackTrace, the verifier, RLVR loop, and scorecard
never change when you swap the target.
"""
from __future__ import annotations

from typing import Protocol

from redcell_core.schemas import AttackTrace, DefenseConfig
from redcell_target import live_agent, sim_agent


class TargetHarness(Protocol):
    def run(self, spec, defense: DefenseConfig) -> AttackTrace: ...


class SimHarness:
    """Deterministic vulnerable-target simulator (offline, no deps)."""
    def run(self, spec, defense: DefenseConfig) -> AttackTrace:
        return sim_agent.run(spec, defense)


class LiveHarness:
    """The real Claude Haiku fintech agent. Needs `anthropic` + ANTHROPIC_API_KEY.
    Returns the identical AttackTrace, so nothing downstream changes."""
    def run(self, spec, defense: DefenseConfig) -> AttackTrace:
        return live_agent.run(spec, defense)


def get_harness(live: bool = False) -> TargetHarness:
    return LiveHarness() if live else SimHarness()
