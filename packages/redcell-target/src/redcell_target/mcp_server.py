"""The system under test: a real FastMCP server for any scenario.

Run standalone: uv run python -m redcell_target.mcp_server   (fintech, stdio transport)

`LiveHarness` connects to this server with an in-memory FastMCP `Client`, so the attack
surface genuinely is MCP (tools/list + tools/call) without a network hop.

The scenario supplies plain tool functions (scenario_tools.py). This file wraps every one
of them the same way, so all scenarios get identical defenses:
  L3  deny-by-default: any tool outside the role's read tools raises ToolError
  L4  the confidential field is left out of every result (not masked: nothing for L1 to
      misread), and the outgoing-message tool's text goes through Presidio first
  and the scenario's third-party tool gets the attacker's text appended to its description
  when the run is a tool-poisoning attack.
The tool surface (names and schemas) is identical in every configuration, so a frozen
attack replays byte-for-byte against any defense.

Import-safe: `fastmcp` is imported lazily inside build_server().
"""
from __future__ import annotations

import functools
from dataclasses import dataclass

from redcell_core.scenarios import FINTECH, ScenarioSpec
from redcell_core.schemas import CANARY_NOTE, DefenseConfig
from redcell_target import guards, scenario_tools
from redcell_target.seed import SeedDB, build_seed_db

_DEFAULT_DB: SeedDB | None = None


def default_db() -> SeedDB:
    global _DEFAULT_DB
    if _DEFAULT_DB is None:
        _DEFAULT_DB = build_seed_db()
    return _DEFAULT_DB


@dataclass
class Planted:
    """Per-attempt values the server serves (set by the harness)."""
    canary: str                # what the confidential field holds this run
    injected: str = ""         # indirect: attack text in the data field the agent reads
    poisoned: str = ""         # tool poisoning: attack text appended to a tool description
    injected2: str = ""        # split attack: the first half, in a second attacker-writable field


def _strip(obj, field: str):
    if isinstance(obj, dict):
        return {k: _strip(v, field) for k, v in obj.items() if k != field}
    if isinstance(obj, list):
        return [_strip(v, field) for v in obj]
    return obj


def _guarded(fn, spec: ScenarioSpec, defense: DefenseConfig, tool_error):
    name = fn.__name__
    egress_tool, egress_arg = spec.egress

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if defense.l3_allowlist and name not in spec.read_tools:
            raise tool_error(f"{name} is not permitted for this role")
        if defense.l4_redact and name == egress_tool and egress_arg in kwargs:
            kwargs[egress_arg] = guards.redact_pii(str(kwargs[egress_arg]))
        out = fn(*args, **kwargs)
        return _strip(out, spec.confidential_field) if defense.l4_redact else out
    return wrapper


def build_server(defense: DefenseConfig, planted: Planted, spec: ScenarioSpec = FINTECH,
                 db: SeedDB | None = None):
    """A FastMCP server for one attempt: the scenario's tools, the planted values, the defenses."""
    from fastmcp import FastMCP
    try:
        from fastmcp.exceptions import ToolError
    except Exception:  # pragma: no cover - name varies across versions
        ToolError = RuntimeError

    mcp = FastMCP(f"redcell-{spec.name}")
    poison_name, poison_desc = spec.poison_tool
    for fn in scenario_tools.TOOLS[spec.name](db or default_db(), planted):
        desc = (fn.__doc__ or "").strip()
        if fn.__name__ == poison_name:
            desc = poison_desc + (f"\n<IMPORTANT>\n{planted.poisoned}\n</IMPORTANT>" if planted.poisoned else "")
        mcp.tool(_guarded(fn, spec, defense, ToolError), name=fn.__name__, description=desc)
    return mcp


def default_server():
    return build_server(DefenseConfig(), Planted(CANARY_NOTE.value))


if __name__ == "__main__":
    default_server().run()   # stdio transport
