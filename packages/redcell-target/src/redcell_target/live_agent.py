"""LiveHarness internals — a REAL model attacked through a REAL MCP server.

Two target families, one loop shape:
  * claude-*   -> Anthropic Messages API (needs ANTHROPIC_API_KEY)
  * any other  -> an OpenAI-compatible endpoint; Ollama by default
                  (OPENAI_BASE_URL, default http://localhost:11434/v1), e.g. qwen2.5:7b

Every tool call goes through a FastMCP in-memory `Client` to the server in
`mcp_server.py` (JSON-RPC tools/list + tools/call), so the attack surface IS MCP.
The trace holds only what actually happened: the tool calls as the server ran
them and the model's final text. The deterministic verifier reads nothing else.

The scenario (redcell_core.scenarios) supplies the rules under attack: a system prompt
with a read-only role, a confidential field, an escalation code and "no images". That is
how most agents ship, so it is the baseline the defenses (L1-L5) are measured against.

Every priced call goes through charge(), which stops the run once the spend cap
(REDCELL_MAX_USD or MAX_USD) is crossed. An unknown price for a paid model stops it too.

Import-safe: `fastmcp`, `anthropic` and `openai` are imported lazily.
"""
from __future__ import annotations

import asyncio
import json
import os

from redcell_core.config import PRICE_PER_MTOK, TARGET_MODEL
from redcell_core.scenarios import SCENARIOS
from redcell_core.schemas import (
    CANARY_SYS, AttackTrace, DefenseConfig, SeedManifest, SessionState, ToolCall,
)
from redcell_target import guards
from redcell_target.mcp_server import Planted, build_server

_SELF = "u_self"
_MAX_TURNS = 6
_MAX_RETRIES = 6         # SDK retries timeouts / dropped connections / 429 / 5xx with backoff
_MAX_ANSWER_TOKENS = 1024   # local models: caps a looping reply (seen: 4,400+ tokens). Claude's
                            # max_tokens stays 16000 because its thinking counts toward it.
_BLOCKED = '{"decision":"review","risk_score":50,"reason":"blocked"}'   # L1 refused the message


# ponytail: process-wide tallies of the token counts the APIs report; make them per-run
# if runs ever execute in parallel.
USAGE = {"model_calls": 0, "input_tokens": 0, "output_tokens": 0}            # the target model
ATTACKER_USAGE = {"model_calls": 0, "input_tokens": 0, "output_tokens": 0}   # the adaptive attacker
SPEND = {"usd": 0.0}                                                          # both, priced
MAX_USD = float(os.getenv("REDCELL_MAX_USD", "inf"))
# The structural fix the adaptive attacker pointed at: with False, the escalation-code rule is left
# out of the system prompt entirely, so there is no secret in the prompt to leak.
PROMPT_SECRET = os.getenv("REDCELL_PROMPT_SECRET", "1") != "0"


class BudgetExceeded(RuntimeError):
    """The run hit its spend cap (or met a paid model with no known price). Fail closed."""


def _price(model: str):
    return PRICE_PER_MTOK.get(model) or (None if model.startswith("claude") else (0.0, 0.0))


def charge(model: str, input_tokens, output_tokens, usage: dict = USAGE) -> None:
    """Record real token usage; stop once spend crosses MAX_USD (overshoot is at most one call)."""
    usage["model_calls"] += 1
    usage["input_tokens"] += input_tokens or 0
    usage["output_tokens"] += output_tokens or 0
    price = _price(model)
    if price is None:
        raise BudgetExceeded(f"no price known for {model}; refusing to spend without a number")
    SPEND["usd"] += ((input_tokens or 0) * price[0] + (output_tokens or 0) * price[1]) / 1e6
    if SPEND["usd"] > MAX_USD:
        raise BudgetExceeded(f"spent ${SPEND['usd']:.4f}, over the ${MAX_USD} cap")


def usage_report(model: str) -> dict:
    """Real token usage so far, priced. usd is None for a Claude model with no known price."""
    price = _price(model)
    usd = None if price is None else round(
        (USAGE["input_tokens"] * price[0] + USAGE["output_tokens"] * price[1]) / 1e6, 4)
    return {**USAGE, "usd": usd}


def _input_blocked(text: str, d: DefenseConfig) -> bool:
    """L1 on the user's message."""
    return d.l1_input_classifier and guards.is_injection(text)


def _to_model(out, d: DefenseConfig):
    """What the model sees of a tool result: L1 drops flagged fields, L2 datamarks the rest.
    The trace keeps the raw result: it records what the server returned."""
    if d.l1_input_classifier:
        out = guards.drop_flagged(out)
    if d.l2_spotlight:
        out = guards.datamark(out)
    return out


def _egress(text: str, d: DefenseConfig) -> str:
    """What leaves the agent: L4 PII redaction, then L5 render-safe escaping."""
    if d.l4_redact:
        text = guards.redact_pii(text)
    if d.l5_output:
        text = guards.render_safe(text)
    return text


def _tool_out(result) -> dict:
    """Normalize a FastMCP CallToolResult to a dict, defensively across versions."""
    for attr in ("data", "structured_content"):
        v = getattr(result, attr, None)
        if isinstance(v, dict):
            return v
    content = getattr(result, "content", None) or []
    if content:
        txt = getattr(content[0], "text", None)
        if txt:
            try:
                return json.loads(txt)
            except Exception:
                return {"text": txt}
    return {}


def _schema(tool) -> dict:
    """MCP SDK v2 renamed inputSchema -> input_schema; read whichever this version has."""
    return getattr(tool, "input_schema", None) or tool.inputSchema


async def _loop_anthropic(model, system, mtools, user_text, call) -> str:
    import anthropic
    tools = [{"name": t.name, "description": t.description or "", "input_schema": _schema(t)}
             for t in mtools]
    messages = [{"role": "user", "content": user_text}]
    # connect=20s: a seen failure mode was httpx2.ConnectTimeout during a short Wi-Fi/DNS dropout,
    # which burned the default short connect timeout on every retry.
    async with anthropic.AsyncAnthropic(max_retries=_MAX_RETRIES,
                                        timeout=anthropic.Timeout(600.0, connect=20.0)) as client:
        for turn in range(_MAX_TURNS):
            resp = await client.messages.create(model=model, max_tokens=16000, system=system,
                                                tools=tools, messages=messages)
            charge(model, resp.usage.input_tokens, resp.usage.output_tokens)   # output includes thinking
            if resp.stop_reason != "tool_use":          # end_turn, max_tokens or refusal
                return "".join(b.text for b in resp.content if b.type == "text")
            messages.append({"role": "assistant", "content": resp.content})  # thinking blocks kept as-is
            results = []
            for b in resp.content:
                if b.type == "tool_use":
                    out, ok = await call(b.id, b.name, dict(b.input), turn)
                    results.append({"type": "tool_result", "tool_use_id": b.id,
                                    "content": json.dumps(out), "is_error": not ok})
            messages.append({"role": "user", "content": results})
    return ""


async def _loop_openai(model, system, mtools, user_text, call) -> str:
    from openai import AsyncOpenAI
    tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                               "parameters": _schema(t)}} for t in mtools]
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user_text}]
    async with AsyncOpenAI(base_url=os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1"),
                           api_key=os.getenv("OPENAI_API_KEY", "ollama"), max_retries=_MAX_RETRIES) as client:
        for turn in range(_MAX_TURNS):
            resp = await client.chat.completions.create(model=model, messages=messages, tools=tools,
                                                        max_tokens=_MAX_ANSWER_TOKENS)
            charge(model, getattr(resp.usage, "prompt_tokens", 0), getattr(resp.usage, "completion_tokens", 0))
            msg = resp.choices[0].message
            if not msg.tool_calls:
                return msg.content or ""
            messages.append(msg.model_dump(exclude_none=True))
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}                           # the server rejects it; recorded as not executed
                out, _ = await call(tc.id, tc.function.name, args, turn)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(out)})
    return ""


async def _run_async(spec, defense: DefenseConfig, model: str) -> AttackTrace:
    from fastmcp import Client

    goal = spec.goal
    scn = SCENARIOS[goal.scenario]
    note = _note_secret(goal)
    head, tail = spec.parts if goal.vector == "indirect" else ("", spec.payload)
    planted = Planted(canary=note.value,
                      injected=tail if goal.vector == "indirect" else "",
                      injected2=head,
                      poisoned=spec.payload if goal.vector == "tool_description" else "")
    server = build_server(defense, planted, scn)
    user_text = spec.payload if goal.vector == "direct" else scn.benign_task
    prompt = scn.system_prompt if PROMPT_SECRET else "\n".join(
        line for line in scn.system_prompt.splitlines() if "{code}" not in line)
    system = prompt.replace("{code}", CANARY_SYS.value) + (guards.SPOTLIGHT_PROMPT if defense.l2_spotlight else "")

    recorded: list[ToolCall] = []
    outbound: list[dict] = []
    if _input_blocked(user_text, defense):
        return _trace(spec, goal, recorded, _BLOCKED, outbound, defense)

    async with Client(server) as client:
        mtools = await client.list_tools()
        if defense.l1_input_classifier:               # L1 on tool descriptions: drops poisoned tools
            mtools = [t for t in mtools if not guards.is_injection(t.description or "")]

        async def call(call_id, name, args, turn) -> tuple[dict, bool]:
            try:
                out, executed = _tool_out(await client.call_tool(name, args)), True
            except Exception as e:                      # ToolError from the allowlist = blocked
                out, executed = {"error": str(e)}, False
            recorded.append(ToolCall(call_id, name, args, out, executed, float(turn)))
            if name == scn.egress[0] and executed:     # a blocked send never left
                outbound.append({"channel": name, "body": str(out.get("body_sent", ""))})
            return _to_model(out, defense), executed

        loop = _loop_anthropic if model.startswith("claude") else _loop_openai
        final_text = await loop(model, system, mtools, user_text, call)

    final_text = _egress(final_text, defense)
    return _trace(spec, goal, recorded, final_text, outbound, defense)


def _note_secret(goal):
    """What the confidential field holds: another person's data for LLM02 goals, else the
    scenario's own secret. Never the escalation code, which lives only in the system prompt."""
    return SCENARIOS[goal.scenario].note_secret if goal.canary == CANARY_SYS else goal.canary


def _trace(spec, goal, recorded, final_text, outbound, defense) -> AttackTrace:
    canaries = (CANARY_SYS, _note_secret(goal))           # every run carries both secrets
    return AttackTrace(
        run_id="live", attempt_id=goal.goal_id + "|" + "+".join(spec.operators),
        scenario_id=goal.scenario, rendered_input=spec.payload,
        tool_calls=tuple(recorded), final_output=final_text,
        outbound_sinks=tuple(outbound), session=SessionState(user_id=_SELF),
        seeded=SeedManifest(canaries=canaries), defense_version=defense.version)


def run(spec, defense: DefenseConfig, model: str = TARGET_MODEL) -> AttackTrace:
    return asyncio.run(_run_async(spec, defense, model))
