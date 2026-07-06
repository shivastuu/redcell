"""Metrics + reporting. ASR is never a bare point estimate — Wilson CI always."""
from __future__ import annotations

import math
from collections import defaultdict

from redcell_attackers.rlvr import Attempt


def asr(attempts: list[Attempt]) -> float:
    return sum(a.breached for a in attempts) / len(attempts) if attempts else 0.0


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval — correct near the 0%/100% edges."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def by_owasp(attempts: list[Attempt]) -> dict[str, tuple[int, int]]:
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for a in attempts:
        agg[a.goal.owasp][0] += a.breached
        agg[a.goal.owasp][1] += 1
    return {k: (v[0], v[1]) for k, v in sorted(agg.items())}


def pct(x: float) -> str:
    return f"{x * 100:4.1f}%"


def format_headline(baseline: list[Attempt], defended: list[Attempt],
                    adaptive_: list[Attempt]) -> str:
    b, d, ad = asr(baseline), asr(defended), asr(adaptive_)
    n = len(baseline)
    lo_b, hi_b = wilson_ci(sum(a.breached for a in baseline), len(baseline))
    lo_d, hi_d = wilson_ci(sum(a.breached for a in defended), len(defended))
    lo_a, hi_a = wilson_ci(sum(a.breached for a in adaptive_), len(adaptive_))
    L = []
    L.append(f"  baseline (undefended)      {pct(b)}   95% CI [{pct(lo_b)},{pct(hi_b)}]   n={n}")
    L.append(f"  defended  (frozen replay)  {pct(d)}   95% CI [{pct(lo_d)},{pct(hi_d)}]   <- the money shot")
    L.append(f"  defended  (ADAPTIVE)       {pct(ad)}   95% CI [{pct(lo_a)},{pct(hi_a)}]   <- the honest number")
    return "\n".join(L)


def _ci(attempts: list[Attempt]) -> dict:
    n = len(attempts)
    k = sum(a.breached for a in attempts)
    lo, hi = wilson_ci(k, n)
    return {"asr": asr(attempts), "lo": lo, "hi": hi, "k": k, "n": n}


def report_dict(baseline, defended, adaptive_, layers: list[tuple[str, list]],
                cost: dict, corpus_version: str, target: str) -> dict:
    """The JSON the leaderboard renders and CI diffs. Every number is here."""
    b_ow, d_ow = by_owasp(baseline), by_owasp(defended)
    return {
        "target": target,
        "corpus_version": corpus_version,
        "asr": {
            "baseline": _ci(baseline),
            "defended_frozen": _ci(defended),
            "defended_adaptive": _ci(adaptive_),
        },
        "owasp": [
            {"category": k, "baseline": b_ow[k][0] / b_ow[k][1],
             "defended": d_ow.get(k, (0, b_ow[k][1]))[0] / b_ow[k][1], "n": b_ow[k][1]}
            for k in sorted(b_ow)
        ],
        "layers": [
            {"name": name, "asr": asr(att), "kills": asr(baseline) - asr(att)}
            for name, att in layers
        ],
        "cost": cost,
    }


def format_owasp(baseline: list[Attempt], defended: list[Attempt]) -> str:
    b, d = by_owasp(baseline), by_owasp(defended)
    L = [f"  {'OWASP':<8}{'baseline':>10}{'defended':>10}   collapse"]
    for k in sorted(b):
        bk, bn = b[k]
        dk = d.get(k, (0, bn))[0]
        bar_b = "█" * round(bk / bn * 12)
        L.append(f"  {k:<8}{pct(bk/bn):>10}{pct(dk/bn):>10}   {bar_b}")
    return "\n".join(L)
