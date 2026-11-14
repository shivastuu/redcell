#!/usr/bin/env python3
"""Repeat the undefended baseline N times. Models sample their words, so the same attack can land
on one run and not the next; one run is one sample. This reports the spread.

    .venv/bin/python scripts/run_repeats.py --scenario fintech --repeats 3          # Qwen, free
    set -a; . ./.env; set +a
    .venv/bin/python scripts/run_repeats.py --model claude-haiku-5-5 --repeats 2 --max-usd 0.3

Writes dashboard/repeats/<target>__<scenario>.json.
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from build_leaderboard import slug                              # noqa: E402
from redcell_attackers import campaign                          # noqa: E402
from redcell_attackers.scorecard import targeted, wilson_ci     # noqa: E402
from redcell_attackers.specs import STYLES, build_catalog       # noqa: E402
from redcell_core.config import Budget                          # noqa: E402
from redcell_target import live_agent                           # noqa: E402
from redcell_target.harness import get_harness                  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="qwen2.5:7b (default) or claude-haiku-5-5")
    ap.add_argument("--scenario", default="fintech")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--max-usd", type=float, default=None)
    args = ap.parse_args()
    if args.max_usd is not None:
        live_agent.MAX_USD = args.max_usd

    h = get_harness(live=True, model=args.model)
    target = f"live:{h.model}"
    goals = build_catalog(STYLES, args.scenario)
    runs = []
    for i in range(args.repeats):
        base = campaign.discover(h, goals, Budget(max_target_calls=8))
        k, kt, n = sum(a.breached for a in base), sum(targeted(a) for a in base), len(base)
        lo, hi = wilson_ci(k, n)
        runs.append({"k": k, "n": n, "asr": k / n, "lo": lo, "hi": hi, "targeted": kt})
        print(f"  run {i + 1}/{args.repeats}: {k}/{n} = {k / n * 100:.1f}%  (goal met {kt})  CI {lo * 100:.1f}-{hi * 100:.1f}%")
    rates = [r["asr"] for r in runs]
    report = {"target": target, "scenario": args.scenario, "repeats": len(runs), "runs": runs,
              "mean": sum(rates) / len(rates), "min": min(rates), "max": max(rates),
              "cost": live_agent.usage_report(h.model), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    out = os.path.join(ROOT, "dashboard", "repeats", slug(f"{target}__{args.scenario}") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"mean {report['mean'] * 100:.1f}%  range {report['min'] * 100:.1f}-{report['max'] * 100:.1f}%  "
          f"over {len(runs)} runs  ·  wrote {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
