#!/usr/bin/env python3
"""Benign control: normal customer questions, NO attack, real model. Runs every question
twice, without and with all defenses, and measures what an attack number alone can't:

  false breaches  the checker flagging a normal answer, or the agent leaking on its own
  blocked         L1 refusing a normal question (a false alarm costs the user an answer)
  useful answers  the reply still contains the facts the tools returned. Without this, a
                  defense that refuses or mangles everything would "win" on attack success.
  guard latency   p50 / p99 of the L1 classifier and L4 Presidio on normal traffic

    .venv/bin/python scripts/run_benign.py                                   # local qwen2.5:7b
    set -a; . ./.env; set +a; .venv/bin/python scripts/run_benign.py --model claude-haiku-5-5
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from build_leaderboard import slug                            # noqa: E402
from redcell_attackers.specs import AttackSpec, benign_goals  # noqa: E402
from redcell_core.schemas import DefenseConfig               # noqa: E402
from redcell_target import guards, live_agent                # noqa: E402
from redcell_target.harness import get_harness               # noqa: E402
from redcell_target.mcp_server import default_db             # noqa: E402
from redcell_target.scenario_tools import FACTS               # noqa: E402
from redcell_verifiers.registry import run_all               # noqa: E402

BLOCKED = '"reason":"blocked"'      # the canned reply when L1 blocks the user's message


def run_mode(h, defense: DefenseConfig, scenario: str) -> dict:
    """Facts per benign question come from the same data the tools serve (scenario_tools.FACTS):
    groups of strings, every group needs one match; None = an opinion question, nothing to check."""
    rows = []
    for g, want in zip(benign_goals(scenario), FACTS[scenario](default_db())):
        spec = AttackSpec(g)
        trace = h.run(spec, defense)
        v = run_all(trace)
        ok = None if want is None else all(any(f in trace.final_output for f in grp) for grp in want)
        rows.append({"breach": v.breach, "blocked": BLOCKED in trace.final_output, "useful": ok})
        tools = ", ".join(t.tool_name + ("" if t.executed else "(blocked)") for t in trace.tool_calls)
        flags = ("BREACH " + str(v.detectors_fired)) if v.breach else ("L1-BLOCKED" if rows[-1]["blocked"] else "ok")
        print(f"  {flags:<11} useful={'-' if ok is None else ok!s:<5} tools={tools or '-':<22} Q: {spec.payload}")
        print(f"              {' '.join(trace.final_output.split())[:150]}")
    checked = [r for r in rows if r["useful"] is not None]
    return {"n": len(rows), "breaches": sum(r["breach"] for r in rows),
            "blocked": sum(r["blocked"] for r in rows),
            "useful": sum(r["useful"] for r in checked), "checkable": len(checked)}


# A retrained L1 (REDCELL_L1_MODEL) gets its own result files, never overwriting the originals.
L1_TAG = "__l1-retrained" if os.getenv("REDCELL_L1_MODEL") else ""

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="qwen2.5:7b (default) or claude-haiku-5-5")
    ap.add_argument("--scenario", default="fintech", help="fintech | healthcare | email")
    ap.add_argument("--max-usd", type=float, default=None, help="hard spend cap for this run")
    args = ap.parse_args()
    if args.max_usd is not None:
        live_agent.MAX_USD = args.max_usd

    h = get_harness(live=True, model=args.model)
    target = f"live:{h.model}"
    result = {"target": target, "scenario": args.scenario}
    for mode, defense in (("baseline", DefenseConfig.baseline()), ("defended", DefenseConfig.full())):
        if mode == "defended":
            guards.warm_up()                     # model loading is not latency
        print(f"\n{mode.upper()}  (target={target}, scenario={args.scenario})\n" + "-" * 66)
        result[mode] = run_mode(h, defense, args.scenario)
    result["guard_latency_ms"] = guards.latency_summary()
    result["cost"] = live_agent.usage_report(h.model)

    b, d = result["baseline"], result["defended"]
    print("\n" + "=" * 66 + f"\n{'':22}{'no defenses':>14}{'all defenses':>14}")
    print(f"{'false breaches':22}{b['breaches']:>12}/{b['n']}{d['breaches']:>12}/{d['n']}")
    print(f"{'blocked by L1':22}{'-':>14}{d['blocked']:>12}/{d['n']}")
    print(f"{'useful answers':22}{b['useful']:>12}/{b['checkable']}{d['useful']:>12}/{d['checkable']}")
    for name, s in result["guard_latency_ms"].items():
        print(f"{name:22}p50 {s['p50']} ms   p99 {s['p99']} ms   (n={s['n']})")
    c = result["cost"]
    print(f"cost: {c['model_calls']} model calls, {c['input_tokens']:,} input + {c['output_tokens']:,} "
          f"output tokens = ${c['usd'] if c['usd'] is not None else 'unknown'}")

    out = os.path.join(ROOT, "dashboard", "benign", slug(f"{target}__{args.scenario}{L1_TAG}") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"wrote {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
