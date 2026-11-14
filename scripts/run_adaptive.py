#!/usr/bin/env python3
"""Adaptive attacker campaign: an attacker model rewrites each attack after reading the agent's
reply, up to --rounds times per goal (see packages/redcell-attackers/.../adaptive.py).

    set -a; . ./.env; set +a
    .venv/bin/python scripts/run_adaptive.py --target claude-haiku-5-5 --attacker claude-haiku-5-5 \
        --scenario fintech --defense none --max-usd 0.3

Writes dashboard/adaptive/<target>__<scenario>__<defense>__by_<attacker>.json and shows every
round live on the leaderboard. If the spend cap stops the run, what finished is still saved.
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from build_leaderboard import slug                             # noqa: E402
from redcell_attackers import adaptive                         # noqa: E402
from redcell_attackers.scorecard import wilson_ci              # noqa: E402
from redcell_attackers.specs import build_catalog              # noqa: E402
from redcell_core.scenarios import SCENARIOS                   # noqa: E402
from redcell_core.schemas import DefenseConfig                 # noqa: E402
from redcell_target import live_agent, scenario_tools          # noqa: E402
from redcell_target.harness import get_harness                 # noqa: E402
from redcell_target.mcp_server import Planted, default_db      # noqa: E402
from run_campaign import ProgressHarness                       # noqa: E402


def tool_list(scenario: str) -> str:
    """What an outsider can know: the public tool names and descriptions, nothing planted."""
    s = SCENARIOS[scenario]
    fns = scenario_tools.TOOLS[scenario](default_db(), Planted(canary=""))
    return "; ".join(f"{f.__name__} ({s.poison_tool[1] if f.__name__ == s.poison_tool[0] else (f.__doc__ or '').strip()})"
                     for f in fns)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="qwen2.5:7b")
    ap.add_argument("--attacker", default="claude-haiku-5-5")
    ap.add_argument("--scenario", default="fintech", help="fintech | healthcare | email")
    ap.add_argument("--defense", default="none", choices=("none", "full"))
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--goals", default="", help="comma-separated goal indices (0-8); default all 9")
    ap.add_argument("--max-usd", type=float, default=None, help="hard spend cap for this run")
    ap.add_argument("--no-prompt-secret", action="store_true",
                    help="leave the escalation code out of the system prompt (the structural fix)")
    args = ap.parse_args()
    if args.max_usd is not None:
        live_agent.MAX_USD = args.max_usd
    live_agent.PROMPT_SECRET = not args.no_prompt_secret
    label = args.defense + (" + no secret in prompt" if args.no_prompt_secret else "")

    defense = DefenseConfig.full() if args.defense == "full" else DefenseConfig.baseline()
    goals = build_catalog(1, args.scenario)                  # one seed per goal; the attacker writes the rest
    if args.goals:
        goals = [goals[int(i)] for i in args.goals.split(",")]
    target = f"live:{args.target}"
    h = ProgressHarness(get_harness(live=True, model=args.target), target,
                        f"{args.scenario} · adaptive vs {label} by {args.attacker}", len(goals), 1)
    h.phase(f"adaptive attacker, up to {args.rounds} rounds")
    tools = tool_list(args.scenario)

    print(f"Adaptive attacker  target={target} attacker={args.attacker} scenario={args.scenario} "
          f"defense={args.defense} rounds={args.rounds} goals={len(goals)}\n" + "=" * 66)
    results, stopped = [], ""
    try:
        for g in goals:
            r = adaptive.attack(g, h, defense, args.attacker, tools, args.rounds)
            results.append(r)
            state = ("ATTACKER REFUSED" if r.attacker_refused and not r.rounds_used
                     else f"BREACH in round {r.rounds_used}{' (goal met)' if r.targeted else ' (other rule)'}"
                     if r.breached else f"held {r.rounds_used} rounds" + (", attacker then refused" if r.attacker_refused else ""))
            print(f"  {g.goal_id:<46} {state}")
    except live_agent.BudgetExceeded as e:
        stopped = str(e)
        print(f"\nSTOPPED: {stopped}")
    finally:
        if os.path.exists(h.path):
            os.remove(h.path)                 # clear the progress panel

    n, k = len(results), sum(r.breached for r in results)
    kt = sum(r.targeted for r in results)
    lo, hi = wilson_ci(k, n)
    price = live_agent._price(args.attacker) or (0.0, 0.0)
    au = live_agent.ATTACKER_USAGE
    report = {
        "target": target, "attacker": args.attacker, "scenario": args.scenario, "defense": label,
        "rounds": args.rounds, "complete": not stopped and n == len(goals), "stopped": stopped,
        "goals": n, "breached": k, "targeted": kt, "asr": k / n if n else 0.0, "lo": lo, "hi": hi,
        "attacker_refusals": sum(r.attacker_refused for r in results),
        "cost": {"target": live_agent.usage_report(args.target), "attacker": dict(au),
                 "attacker_usd": round((au["input_tokens"] * price[0] + au["output_tokens"] * price[1]) / 1e6, 4),
                 "total_usd": round(live_agent.SPEND["usd"], 4)},
        "per_goal": [{"goal_id": r.goal.goal_id, "owasp": r.goal.owasp, "vector": r.goal.vector,
                      "intent": r.goal.intent, "breached": r.breached, "targeted": r.targeted,
                      "rounds_used": r.rounds_used, "attacker_refused": r.attacker_refused,
                      "detectors": r.detectors, "transcript": r.transcript} for r in results],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    out = os.path.join(ROOT, "dashboard", "adaptive",
                       slug(f"{target}__{args.scenario}__{args.defense}{'__nosecret' if args.no_prompt_secret else ''}__by_{args.attacker}") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nbreached {k}/{n} (goal met {kt}) · CI {lo * 100:.1f}-{hi * 100:.1f}% · attacker refusals "
          f"{report['attacker_refusals']} · spent ${report['cost']['total_usd']}\nwrote {os.path.relpath(out, ROOT)}")
    import build_leaderboard
    build_leaderboard.main(quiet=True)


if __name__ == "__main__":
    main()
