"""Freeze the discovered attacks into a content-addressed corpus.

corpus_version = sha256(sorted spec keys). Baseline and defended runs load the
SAME frozen specs — the guarantee behind an apples-to-apples before/after.
"""
from __future__ import annotations

import hashlib
import json
import os

from redcell_attackers.rlvr import Attempt


def corpus_version(corpus: list[Attempt]) -> str:
    keys = sorted(f"{a.goal.goal_id}|{'+'.join(a.spec.operators)}" for a in corpus)
    return "v1.0.0+" + hashlib.sha256("\n".join(keys).encode()).hexdigest()[:12]


def freeze(corpus: list[Attempt], root: str) -> str:
    version = corpus_version(corpus)
    out = os.path.join(root, "corpus", version)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "attacks.jsonl"), "w") as f:
        for a in corpus:
            f.write(json.dumps({
                "goal_id": a.goal.goal_id, "owasp": a.goal.owasp,
                "technique": a.goal.technique, "vector": a.goal.vector,
                "intent": a.goal.intent, "operators": list(a.spec.operators),
                "baseline_breach": a.breached,
            }) + "\n")
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump({"corpus_version": version, "count": len(corpus)}, f, indent=2)
    return version
