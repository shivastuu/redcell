#!/usr/bin/env python3
"""Generate clean, realistic tool-result text (memos, emails, clinic notes) as negatives for
retraining L1. Many include ordinary instructions to the human reader ("Please pay by Friday"),
the hard cases a classifier must not flag. None address an AI.

    .venv/bin/python scripts/gen_clean_text.py --max-usd 0.10      # writes data/clean_text.jsonl
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-verifiers", "redcell-target"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_target import live_agent  # noqa: E402

MODEL = "claude-haiku-5-5"
CATEGORIES = [
    ("bank transaction memos", "a bank's transaction records"),
    ("merchant names as printed on card statements", "a card statement"),
    ("payment reference notes", "a payments system"),
    ("fraud-review analyst notes", "a bank's internal review queue"),
    ("customer notifications from a bank", "a banking app"),
    ("appointment messages from a clinic", "a patient portal"),
    ("notes from a health insurer on a claim", "a patient portal"),
    ("lab result summaries", "a patient portal"),
    ("medication instructions for patients", "a pharmacy system"),
    ("clinic reminders", "a patient portal"),
    ("work email subject lines", "a company inbox"),
    ("short work email bodies", "a company inbox"),
    ("IT helpdesk notices", "a company inbox"),
    ("invoice and billing emails", "a company inbox"),
    ("calendar invite descriptions", "a work calendar"),
]
PROMPT = ("Write 40 realistic, varied {cat} as they would appear in {where}. One per line, no numbering, "
          "no quotes, no blank lines. Mix lengths from 3 to 60 words. About half should contain an ordinary "
          "request or instruction to the human reader (a deadline, a step to take, a reminder). None may "
          "address an AI or assistant, or mention AI.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-usd", type=float, default=0.10)
    live_agent.MAX_USD = ap.parse_args().max_usd
    import anthropic
    client = anthropic.Anthropic(max_retries=6, timeout=anthropic.Timeout(600.0, connect=20.0))
    rows, seen = [], set()
    for cat, where in CATEGORIES:
        r = client.messages.create(model=MODEL, max_tokens=4000,
                                   messages=[{"role": "user", "content": PROMPT.format(cat=cat, where=where)}])
        live_agent.charge(MODEL, r.usage.input_tokens, r.usage.output_tokens)
        text = "".join(b.text for b in r.content if b.type == "text")
        lines = [ln.strip().lstrip("-•* ").strip() for ln in text.splitlines()]
        new = [ln for ln in lines if len(ln) > 2 and ln.lower() not in seen]
        seen.update(ln.lower() for ln in new)
        rows += [{"text": ln, "category": cat} for ln in new]
        print(f"  {cat:<48} {len(new)}", flush=True)
    out = os.path.join(ROOT, "data", "clean_text.jsonl")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    print(f"{len(rows)} texts · ${live_agent.SPEND['usd']:.4f} · wrote {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()
