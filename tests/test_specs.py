"""The attack catalog renders real, distinct attacks. Runs under pytest, or standalone:
    python3 tests/test_specs.py
"""
import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers.specs import (  # noqa: E402
    BENIGN_QUESTIONS, AttackSpec, benign_goals, build_catalog,
)


def test_42_distinct_attacks():
    payloads = [AttackSpec(g).payload for g in build_catalog()]
    assert len(payloads) == 42 and len(set(payloads)) == 42


def test_encoding_really_encodes():
    goal = build_catalog(1)[0]                              # LLM01 indirect exfil
    plain = AttackSpec(goal).payload
    enc = AttackSpec(goal, ("encoding",)).payload
    assert "internal_note" in plain and "internal_note" not in enc
    b64 = enc.split("follow it exactly: ")[1].split()[0]
    assert "internal_note" in base64.b64decode(b64).decode()


def test_benign_has_no_attack():
    assert [AttackSpec(g).payload for g in benign_goals()] == list(BENIGN_QUESTIONS)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("\nall spec tests passed.")
