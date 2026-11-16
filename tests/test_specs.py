"""The attack catalog renders real, distinct attacks. Runs under pytest, or standalone:
    python3 tests/test_specs.py
"""
import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-attackers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_attackers.specs import AttackSpec, benign_goals, build_catalog  # noqa: E402
from redcell_core.scenarios import SCENARIOS  # noqa: E402


def test_63_distinct_attacks_per_scenario():
    # The same words delivered as the user, inside a memo, or inside a poisoned tool description
    # are different attacks, so distinctness is (where it is delivered, what it says).
    for name in SCENARIOS:
        attacks = [(g.vector, AttackSpec(g).payload) for g in build_catalog(scenario=name)]
        assert len(attacks) == 63 and len(set(attacks)) == 63, name


def test_every_scenario_has_the_same_goal_shape():
    shapes = {name: [(t.owasp, t.vector, t.intent) for t in s.goals] for name, s in SCENARIOS.items()}
    assert len({tuple(v) for v in shapes.values()}) == 1          # comparable across scenarios
    for s in SCENARIOS.values():
        for t in s.goals:
            assert t.intent != "unauth_tool" or t.unauth_tool not in s.read_tools   # it must be forbidden


def test_encoding_really_encodes():
    goal = build_catalog(1)[0]                              # fintech LLM01 indirect exfil
    plain = AttackSpec(goal).payload
    enc = AttackSpec(goal, ("encoding",)).payload
    assert "internal_note" in plain and "internal_note" not in enc
    b64 = enc.split("follow it exactly: ")[1].split()[0]
    assert "internal_note" in base64.b64decode(b64).decode()


def test_benign_has_no_attack():
    for name, s in SCENARIOS.items():
        assert [AttackSpec(g).payload for g in benign_goals(name)] == list(s.benign)


def test_custom_payload_is_sent_as_is():
    goal = build_catalog(1)[0]
    assert AttackSpec(goal, ("encoding",), custom="hello").payload == "hello"


def test_split_halves_rejoin_and_each_is_partial():
    from redcell_attackers.variants import split_set
    for s in SCENARIOS:
        for variant, spec in split_set(s):
            head, tail = spec.parts
            if variant == "whole":
                assert head == "" and tail == spec.payload
            else:
                assert head and tail and head + " " + tail == spec.payload
                assert spec.goal.text not in head and spec.goal.text not in tail   # neither half holds the goal


def test_language_variants_cover_every_goal():
    from redcell_attackers.variants import lang_set, tags
    for s in SCENARIOS:
        specs = lang_set(s)                                   # a missing translation raises KeyError here
        assert len(specs) == 4 * len(SCENARIOS[s].goals)
        for variant, spec in specs:
            if variant == "invisible":                        # the attack is there, but not visibly
                assert tags(spec.goal.text) in spec.payload and spec.goal.text not in spec.payload


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("\nall spec tests passed.")
