#!/usr/bin/env python3
"""Validate the LLM-as-judge against the deterministic verifier (Cohen's kappa).

    python3 scripts/run_eval.py

The verifier is ground truth (deterministic). We measure how well the blind judge
agrees with it over a mixed set (undefended + adaptive traces). The judge is
weaker on ENCODED exfil, so kappa < 1 — which is the point: keep the verifier as
the source of truth and use the judge only for the fuzzy cases. A real human
study (>=2 annotators) replaces "verifier-as-gold" for publishing.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers", "redcell-eval"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers import campaign            # noqa: E402
from redcell_core.schemas import DefenseConfig    # noqa: E402
from redcell_eval.judge import judge_breach       # noqa: E402
from redcell_eval.kappa import agreement, band, cohen_kappa, prf  # noqa: E402
from redcell_target.harness import SimHarness     # noqa: E402


def main() -> None:
    h = SimHarness()
    base = campaign.discover(h)
    adapt = campaign.adaptive(base, h, DefenseConfig.full())
    attempts = base + adapt                          # mixed set: plaintext + encoded breaches

    verifier = [a.verdict.breach for a in attempts]  # ground truth (deterministic)
    judge = [judge_breach(a.trace) for a in attempts]  # blind heuristic judge

    k = cohen_kappa(verifier, judge)
    stats = prf(verifier, judge)
    disagreements = [(a.goal.goal_id, v, j) for a, v, j in zip(attempts, verifier, judge) if v != j]

    print("LLM-judge vs deterministic verifier")
    print("=" * 52)
    print(f"  samples              {len(attempts)}")
    print(f"  raw agreement        {agreement(verifier, judge)*100:.1f}%")
    print(f"  Cohen's kappa        {k:.3f}  ({band(k)})")
    print(f"  judge precision      {stats['precision']:.3f}")
    print(f"  judge recall         {stats['recall']:.3f}   (misses encoded exfil -> FN={stats['fn']})")
    print(f"  judge F1             {stats['f1']:.3f}")
    print(f"  disagreements        {len(disagreements)}  (mostly encoded exfil the judge can't decode)")
    print("\n  -> verifier stays the source of truth; judge is the audited secondary.")

    out = {"n": len(attempts), "kappa": k, "band": band(k), "agreement": agreement(verifier, judge),
           **stats, "disagreements": len(disagreements)}
    os.makedirs(os.path.join(ROOT, "dashboard"), exist_ok=True)
    with open(os.path.join(ROOT, "dashboard", "eval.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("\nwrote dashboard/eval.json")


if __name__ == "__main__":
    main()
