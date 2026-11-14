"""TargetHarness — the seam between attackers and the system under test.

Two implementations behind one interface:
  * SimHarness  — the deterministic offline simulator (runs now, no deps).
  * LiveHarness — a real model (local via Ollama, or Claude) driving the FastMCP
                  server through an in-memory MCP client (see live_agent.py).
Because both return the same AttackTrace, the verifier, mutation loop, and
scorecard never change when you swap the target.
"""
from __future__ import annotations

from typing import Protocol

from redcell_core.config import TARGET_MODEL
from redcell_core.schemas import AttackTrace, DefenseConfig
from redcell_target import live_agent, sim_agent


class TargetHarness(Protocol):
    def run(self, spec, defense: DefenseConfig) -> AttackTrace: ...


class SimHarness:
    """Deterministic vulnerable-target simulator (offline, no deps)."""
    def run(self, spec, defense: DefenseConfig) -> AttackTrace:
        return sim_agent.run(spec, defense)


class LiveHarness:
    """A real model behind the fintech MCP server. `claude-*` needs ANTHROPIC_API_KEY;
    anything else goes to Ollama. Returns the identical AttackTrace."""
    def __init__(self, model: str = TARGET_MODEL):
        self.model = model

    def run(self, spec, defense: DefenseConfig) -> AttackTrace:
        return live_agent.run(spec, defense, self.model)


def get_harness(live: bool = False, model: str | None = None) -> TargetHarness:
    return LiveHarness(model or TARGET_MODEL) if live else SimHarness()
