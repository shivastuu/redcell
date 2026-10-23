#!/usr/bin/env python3
"""RedCell end-to-end campaign — the money shot.

    python3 scripts/run_campaign.py            # deterministic simulator (no installs)
    uv run python scripts/run_campaign.py --live   # real Claude Haiku (needs ANTHROPIC_API_KEY)

Runs the full loop, prints the scorecard, and writes dashboard/scorecard.json
(which the leaderboard renders and CI diffs).
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers import campaign, scorecard          # noqa: E402
from redcell_attackers.corpus import corpus_version, freeze  # noqa: E402
from redcell_attackers.scorecard import asr, pct            # noqa: E402
from redcell_attackers.specs import build_catalog           # noqa: E402
from redcell_core.config import Budget                      # noqa: E402
from redcell_core.schemas import DefenseConfig              # noqa: E402
from redcell_target.harness import get_harness              # noqa: E402

LAYERS = [
    ("L1 input classifier", DefenseConfig(l1_input_classifier=True)),
    ("L2 spotlighting",      DefenseConfig(l2_spotlight=True)),
    ("L3 tool allowlist",    DefenseConfig(l3_allowlist=True)),
    ("L4 PII/canary redact", DefenseConfig(l4_redact=True)),
    ("L5 schema validation", DefenseConfig(l5_schema=True)),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use the real Claude agent (needs API key)")
    ap.add_argument("--n", type=int, default=None, help="goals per template (default 6; use 1-2 for --live)")
    args = ap.parse_args()

    h = get_harness(live=args.live)
    target = "live:claude-haiku" if args.live else "sim"
    goals = build_catalog(args.n) if args.n else build_catalog()
    budget = Budget(max_target_calls=8) if args.live else Budget()

    print(f"RedCell — full campaign  (target={target}, goals={len(goals)})")
    print("=" * 66)

    baseline = campaign.discover(h, goals, budget)
    freeze(baseline, ROOT)
    full = DefenseConfig.full()
    defended = campaign.replay_corpus(baseline, h, full)
    adaptive = campaign.adaptive(baseline, h, full, budget)

    print("\n" + "-" * 66 + "\nATTACK-SUCCESS RATE\n" + "-" * 66)
    print(scorecard.format_headline(baseline, defended, adaptive))
    print("\n" + "-" * 66 + "\nPER-OWASP CATEGORY  (baseline -> defended)\n" + "-" * 66)
    print(scorecard.format_owasp(baseline, defended))

    print("\n" + "-" * 66 + "\nPER-LAYER ATTRIBUTION  (add-one-in)\n" + "-" * 66)
    layer_attempts = []
    for name, cfg in LAYERS:
        one = campaign.replay_corpus(baseline, h, cfg)
        layer_attempts.append((name, one))
        killed = asr(baseline) - asr(one)
        print(f"  {name:<24} ASR {pct(asr(one))}   kills {pct(killed)}  {'█' * round(max(0, killed) * 20)}")

    plan_calls = len(goals)
    mut_calls = sum(a.mutations for a in baseline)
    all_frontier = (plan_calls + mut_calls) * 0.03
    routed = plan_calls * 0.03 + mut_calls * 0.003
    cost = {"all_frontier_usd": round(all_frontier, 2), "routed_usd": round(routed, 2),
            "mutation_cost_cut_pct": round((1 - routed / all_frontier) * 100) if all_frontier else 0,
            "attacks_per_usd": round(sum(a.target_calls for a in baseline) / routed) if routed else 0}
    print("\n" + "-" * 66 + "\nCOST (illustrative routing math)\n" + "-" * 66)
    print(f"  all-frontier ${cost['all_frontier_usd']}   routed ${cost['routed_usd']}   "
          f"mutation cost cut ~{cost['mutation_cost_cut_pct']}%   attacks/$ = {cost['attacks_per_usd']}")

    report = scorecard.report_dict(baseline, defended, adaptive, layer_attempts, cost,
                                   corpus_version(baseline), target)
    out_dir = os.path.join(ROOT, "dashboard")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "scorecard.json"), "w") as f:
        json.dump(report, f, indent=2)
    print("\nwrote dashboard/scorecard.json  ->  `python3 scripts/build_leaderboard.py`")
    print("=" * 66)
    print("Frozen number = headline; ADAPTIVE number = truth. Structural controls")
    print("(L2/L3/L5) hold under adaptation; content filters (L1/L4) fall to")
    print("encoding+obfuscation — report both.")


if __name__ == "__main__":
    main()
