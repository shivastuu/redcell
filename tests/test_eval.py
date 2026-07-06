"""Judge/kappa sanity. Runs offline:  python3 tests/test_eval.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target", "redcell-attackers", "redcell-eval"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers import campaign            # noqa: E402
from redcell_core.schemas import DefenseConfig    # noqa: E402
from redcell_eval.judge import judge_breach       # noqa: E402
from redcell_eval.kappa import cohen_kappa, prf   # noqa: E402
from redcell_target.harness import SimHarness     # noqa: E402

_H = SimHarness()
_BASE = campaign.discover(_H)
_ADAPT = campaign.adaptive(_BASE, _H, DefenseConfig.full())
_ATT = _BASE + _ADAPT
_V = [a.verdict.breach for a in _ATT]
_J = [judge_breach(a.trace) for a in _ATT]


def test_kappa_bounds():
    assert -1.0 <= cohen_kappa(_V, _J) <= 1.0


def test_perfect_self_agreement():
    assert cohen_kappa(_V, _V) == 1.0


def test_judge_is_substantial_but_imperfect():
    k = cohen_kappa(_V, _J)
    assert k > 0.4, f"judge should be at least moderate vs verifier, got {k:.3f}"
    assert k < 1.0, "judge must miss the encoded-exfil cases (that's why verifier is truth)"


def test_judge_misses_encoded_exfil():
    # there must be false negatives: verifier caught (decoded) what the judge missed
    assert prf(_V, _J)["fn"] >= 1


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("\nall eval tests passed.")
