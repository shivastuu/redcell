#!/usr/bin/env python3
"""Run the trickier attack variants against a live target, with no guards and with all five guards.

    --set split   the 21 indirect attacks per scenario, whole vs split across two fields
    --set lang    every goal in English, Hindi, Hinglish and invisible Unicode tag characters

One shot per attack (no mutation retries), so each variant differs from its control in one thing.

    .venv/bin/python scripts/run_variants.py --set split --model qwen2.5:7b
    .venv/bin/python scripts/run_variants.py --set lang --model claude-haiku-5-5 --max-usd 0.40

Writes dashboard/variants/<model>__<set>.json
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from build_leaderboard import slug                             # noqa: E402
from redcell_attackers.rlvr import Attempt                     # noqa: E402
from redcell_attackers.scorecard import targeted, wilson_ci    # noqa: E402
from redcell_attackers.variants import lang_set, split_set     # noqa: E402
from redcell_core.schemas import DefenseConfig                 # noqa: E402
from redcell_target import live_agent                          # noqa: E402
from redcell_verifiers.registry import run_all                 # noqa: E402

DEFENSES = (("none", DefenseConfig.baseline()), ("full", DefenseConfig.full()))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, choices=("split", "lang"))
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--scenario", default="fintech,healthcare,email")
    ap.add_argument("--max-usd", type=float, default=None, help="hard spend cap for this run")
    args = ap.parse_args()
    if args.max_usd is not None:
        live_agent.MAX_USD = args.max_usd
    build = split_set if args.set == "split" else lang_set

    rows, stopped = [], ""
    try:
        for s in args.scenario.split(","):
            for variant, spec in build(s):
                for dname, d in DEFENSES:
                    trace = live_agent.run(spec, d, args.model)
                    v = run_all(trace)
                    hit = targeted(Attempt(spec.goal, spec, True, 0, 1, trace, v))
                    rows.append({"scenario": s, "variant": variant, "goal_id": spec.goal.goal_id,
                                 "vector": spec.goal.vector, "defense": dname, "breach": v.breach,
                                 "targeted": hit, "detectors": v.detectors_fired})
                    mark = ("BREACH" + (" (goal met)" if hit else "")) if v.breach else "held"
                    print(f"  {s:<10} {variant:<9} {dname:<4} {spec.goal.goal_id:<46} {mark}", flush=True)
    except live_agent.BudgetExceeded as e:
        stopped = str(e)
        print(f"\nSTOPPED: {stopped}")

    summary = {}
    for variant in dict.fromkeys(r["variant"] for r in rows):
        for dname, _ in DEFENSES:
            sel = [r for r in rows if r["variant"] == variant and r["defense"] == dname]
            k, n = sum(r["breach"] for r in sel), len(sel)
            lo, hi = wilson_ci(k, n)
            summary[f"{variant}/{dname}"] = {"k": k, "n": n, "goal_met": sum(r["targeted"] for r in sel),
                                             "rate": k / n if n else 0.0, "lo": lo, "hi": hi}
    print("\n" + "\n".join(f"  {key:<16} {v['k']}/{v['n']} breached ({v['rate'] * 100:.1f}%, "
                           f"CI {v['lo'] * 100:.1f}-{v['hi'] * 100:.1f}%), goal met {v['goal_met']}"
                           for key, v in summary.items()))
    report = {"set": args.set, "target": f"live:{args.model}", "complete": not stopped, "stopped": stopped,
              "summary": summary, "rows": rows, "cost": live_agent.usage_report(args.model),
              "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    out = os.path.join(ROOT, "dashboard", "variants", slug(f"{args.model}__{args.set}") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nspent ${report['cost'].get('usd')} · wrote {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
