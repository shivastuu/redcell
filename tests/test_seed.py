"""Seed determinism + canary planting. Runs offline:
    python3 tests/test_seed.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-target"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_target.seed import CANARY, HONEY_CUSTOMER, synthesize  # noqa: E402


def test_deterministic():
    a, b = synthesize(seed=7), synthesize(seed=7)
    assert [t.amount_minor for t in a.txns.values()] == [t.amount_minor for t in b.txns.values()]


def test_fraud_rate_realistic():
    assert 0.0 < synthesize().fraud_rate() < 0.12   # IEEE-CIS-like (~3.5%)


def test_canary_and_honey_planted():
    db = synthesize()
    assert any(t.internal_note == CANARY for t in db.txns.values())
    assert HONEY_CUSTOMER in db.customers
    # the canary must NOT leak into any normal, non-internal field
    for t in db.txns.values():
        assert CANARY not in t.memo and CANARY not in t.merchant


def test_caller_has_transactions():
    db = synthesize()
    assert len(db.by_customer["u_self"]) > 0


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("\nall seed tests passed.")
