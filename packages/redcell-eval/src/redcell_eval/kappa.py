"""Cohen's kappa + agreement stats (stdlib).

Chance-corrected agreement. Landis & Koch bands: 0.21-0.40 fair, 0.41-0.60
moderate, 0.61-0.80 substantial, 0.81-1.00 almost perfect.
"""
from __future__ import annotations

from collections import Counter


def cohen_kappa(a: list, b: list) -> float:
    n = len(a)
    if n == 0:
        return 0.0
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    labels = set(a) | set(b)
    pe = sum((ca[k] / n) * (cb[k] / n) for k in labels)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def agreement(a: list, b: list) -> float:
    return sum(x == y for x, y in zip(a, b)) / len(a) if a else 0.0


def prf(gold: list[bool], pred: list[bool]) -> dict:
    """Precision/recall/F1 of `pred` treating `gold` as truth."""
    tp = sum(g and p for g, p in zip(gold, pred))
    fp = sum((not g) and p for g, p in zip(gold, pred))
    fn = sum(g and (not p) for g, p in zip(gold, pred))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def band(k: float) -> str:
    for lo, name in ((0.81, "almost perfect"), (0.61, "substantial"), (0.41, "moderate"),
                     (0.21, "fair"), (0.0, "slight"), (-1.0, "poor")):
        if k >= lo:
            return name
    return "poor"
