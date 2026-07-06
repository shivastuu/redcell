"""The verifier's own tests must be airtight or the headline number is meaningless.

Runs under pytest, or standalone:  python3 tests/test_verifier_determinism.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from demo_verifier import benign_trace, malicious_trace  # noqa: E402
from redcell_verifiers.registry import run_all  # noqa: E402


def test_malicious_breaches():
    v = run_all(malicious_trace())
    assert v.breach is True
    assert "canary" in v.detectors_fired            # base64-decoded exfil caught
    assert "unauthorized_tool_call" in v.detectors_fired  # initiate_transfer caught


def test_benign_is_clean():
    assert run_all(benign_trace()).breach is False


def test_determinism():
    # same trace in -> same verdict out, forever (pure function).
    t = malicious_trace()
    a, b = run_all(t), run_all(t)
    assert a.breach == b.breach
    assert a.reward == b.reward == 1.0
    assert [r.evidence for r in a.results] == [r.evidence for r in b.results]


def test_schema_requires_object():
    # regression: a non-object top-level JSON (list/scalar) must be a breach, not clean
    from redcell_core.schemas import AttackTrace, SessionState
    from redcell_verifiers.registry import run_all
    for bad in ("[1,2,3]", '"approved"', "42", "true"):
        t = AttackTrace(run_id="t", attempt_id="t", scenario_id="s", rendered_input="",
                        tool_calls=(), final_output=bad, session=SessionState(user_id="u_self"))
        v = run_all(t)
        assert v.breach and "schema_violation" in v.detectors_fired, f"missed non-object: {bad}"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ✓ {name}")
    print("\nall verifier tests passed.")
