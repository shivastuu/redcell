#!/usr/bin/env python3
"""RedCell end-to-end campaign — the money shot.

    python3 scripts/run_campaign.py                                      # simulator (pipeline check only)
    uv run python scripts/run_campaign.py --live --n 1                   # local qwen2.5:7b via Ollama
    uv run --env-file .env python scripts/run_campaign.py --live --model claude-haiku-5-5 --n 1

Runs the full loop, prints the scorecard, and writes dashboard/scorecard.json
(which the leaderboard renders and CI diffs).
"""
import argparse
import json
import os
import sys
import time

import build_leaderboard                                    # same folder
from build_leaderboard import slug                          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers import campaign, scorecard          # noqa: E402
from redcell_attackers.corpus import corpus_version, freeze  # noqa: E402
from redcell_attackers.scorecard import asr, pct            # noqa: E402
from redcell_attackers.specs import build_catalog           # noqa: E402
from redcell_core.config import Budget                      # noqa: E402
from redcell_core.schemas import DefenseConfig              # noqa: E402
from redcell_target import guards, live_agent               # noqa: E402
from redcell_target.harness import get_harness              # noqa: E402
from redcell_verifiers.registry import run_all              # noqa: E402

LAYERS = [
    ("L1 input classifier", DefenseConfig(l1_input_classifier=True)),
    ("L2 spotlighting",      DefenseConfig(l2_spotlight=True)),
    ("L3 tool allowlist",    DefenseConfig(l3_allowlist=True)),
    ("L4 PII/canary redact", DefenseConfig(l4_redact=True)),
    ("L5 render-safe output", DefenseConfig(l5_output=True)),
]


class ProgressHarness:
    """Wraps the live harness. After every model run it writes how far the campaign has
    got to dashboard/progress/<target>.json and rebuilds the board, so
    `leaderboard.html?live` shows the run moving. Partial progress, never a result."""

    def __init__(self, inner, target: str, attacks: int):
        self.inner, self.model = inner, inner.model
        self.path = os.path.join(ROOT, "dashboard", "progress", slug(target) + ".json")
        self.state = {"target": target, "phase": "", "phase_no": 0, "phases": 3 + len(LAYERS),
                      "attack": 0, "attacks": attacks, "started": time.time(), "feed": []}
        self._goal = None

    def phase(self, name: str) -> None:
        self.state.update(phase=name, phase_no=self.state["phase_no"] + 1, attack=0)
        self._goal = None
        self._write()

    def run(self, spec, defense):
        if spec.goal.goal_id != self._goal:              # attacks run one after another
            self._goal = spec.goal.goal_id
            self.state["attack"] += 1
        trace = self.inner.run(spec, defense)
        v = run_all(trace)                               # deterministic; same verdict the loop gets
        event = {"t": time.time(), "attack": spec.goal.goal_id, "ops": list(spec.operators),
                 "defense": defense.label, "payload": spec.payload[:180],
                 "tools": [[c.tool_name, c.executed] for c in trace.tool_calls],
                 "breach": v.breach, "detectors": v.detectors_fired, "answer": trace.final_output[:220]}
        self.state["feed"] = [event] + self.state["feed"][:24]     # newest 25
        self._write()
        return trace

    def _write(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump({**self.state, "updated": time.time(), **live_agent.usage_report(self.model)}, f)
        build_leaderboard.main(quiet=True)

    def done(self) -> None:
        os.remove(self.path)
        build_leaderboard.main()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="attack a real model instead of the simulator")
    ap.add_argument("--model", default=None, help="with --live: qwen2.5:7b (default) or claude-haiku-5-5")
    ap.add_argument("--n", type=int, default=None, help="attack styles per goal (default 6; use 1-2 for --live)")
    args = ap.parse_args()

    h = get_harness(live=args.live, model=args.model)
    target = f"live:{h.model}" if args.live else "sim"
    goals = build_catalog(args.n) if args.n else build_catalog()
    budget = Budget(max_target_calls=8) if args.live else Budget()
    if args.live:
        h = ProgressHarness(h, target, len(goals))
    phase = h.phase if args.live else (lambda name: None)

    print(f"RedCell — full campaign  (target={target}, goals={len(goals)})")
    print("=" * 66)

    phase("baseline (undefended)")
    baseline = campaign.discover(h, goals, budget)
    freeze(baseline, ROOT)
    full = DefenseConfig.full()
    phase("frozen replay (defended)")
    defended = campaign.replay_corpus(baseline, h, full)
    phase("adaptive (defended)")
    adaptive = campaign.adaptive(baseline, h, full, budget)

    print("\n" + "-" * 66 + "\nATTACK-SUCCESS RATE\n" + "-" * 66)
    print(scorecard.format_headline(baseline, defended, adaptive))
    print("\n" + "-" * 66 + "\nPER-OWASP CATEGORY  (baseline -> defended)\n" + "-" * 66)
    print(scorecard.format_owasp(baseline, defended))

    print("\n" + "-" * 66 + "\nPER-LAYER ATTRIBUTION  (add-one-in)\n" + "-" * 66)
    layer_attempts = []
    for name, cfg in LAYERS:
        phase(f"{name} only")
        one = campaign.replay_corpus(baseline, h, cfg)
        layer_attempts.append((name, one))
        killed = asr(baseline) - asr(one)
        print(f"  {name:<24} ASR {pct(asr(one))}   kills {pct(killed)}  {'█' * round(max(0, killed) * 20)}")

    cost = live_agent.usage_report(getattr(h, "model", "sim"))
    print("\n" + "-" * 66 + "\nCOST (token counts reported by the model API)\n" + "-" * 66)
    print(f"  {cost['model_calls']} model calls   {cost['input_tokens']:,} input + "
          f"{cost['output_tokens']:,} output tokens   ${cost['usd'] if cost['usd'] is not None else 'unknown'}")

    report = scorecard.report_dict(baseline, defended, adaptive, layer_attempts, cost,
                                   corpus_version(baseline), target)
    report["guard_latency_ms"] = guards.latency_summary()
    out_dir = os.path.join(ROOT, "dashboard")
    paths = [os.path.join(out_dir, "scorecard.json")]          # latest run (Next.js app reads this)
    if args.live:                                              # one file per real model for the leaderboard
        paths.append(os.path.join(out_dir, "scorecards", slug(target) + ".json"))
    for path in paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
    print("\nwrote dashboard/scorecard.json")
    if args.live:
        h.done()                                    # clears the progress panel, rebuilds the board
    print("=" * 66)


if __name__ == "__main__":
    main()
