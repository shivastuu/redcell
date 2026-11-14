"""The live feed shows attacker text and model replies. They must render as text, never
as markup, or the dashboard itself has the LLM05 bug we test agents for.
    python3 tests/test_leaderboard.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from build_leaderboard import feed_event  # noqa: E402


def test_feed_escapes_attacker_text():
    out = feed_event({"t": 0, "target": "live:x", "attack": "LLM05-indirect", "ops": ["delimiter"],
                      "defense": "baseline", "payload": "<INFORMATION><script>alert(1)</script>",
                      "tools": [["get_transaction", True]], "breach": True, "detectors": ["unsafe_output"],
                      "answer": 'ok <img src="https://rc-collect.invalid/r.png">'})
    assert "<script>" not in out and "<img" not in out and "<INFORMATION>" not in out
    assert "&lt;img" in out and "&lt;script&gt;" in out


if __name__ == "__main__":
    test_feed_escapes_attacker_text()
    print("  ✓ test_feed_escapes_attacker_text\n\nall leaderboard tests passed.")
