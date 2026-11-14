"""Cost is computed from real token counts. Runs under pytest, or standalone:
    python3 tests/test_cost.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-target"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_target import live_agent  # noqa: E402


def test_usage_priced_per_model():
    live_agent.USAGE.update(model_calls=2, input_tokens=1_000_000, output_tokens=1_000_000)
    try:
        assert live_agent.usage_report("claude-haiku-5-5")["usd"] == 0.60   # 0.10 + 0.50
        assert live_agent.usage_report("claude-opus-5-5")["usd"] == 24.0    # 4 + 20
        assert live_agent.usage_report("qwen2.5:7b")["usd"] == 0.0          # local
        assert live_agent.usage_report("claude-unknown")["usd"] is None     # never a silent $0
    finally:
        live_agent.USAGE.update(model_calls=0, input_tokens=0, output_tokens=0)


if __name__ == "__main__":
    test_usage_priced_per_model()
    print("  ✓ test_usage_priced_per_model\n\nall cost tests passed.")
