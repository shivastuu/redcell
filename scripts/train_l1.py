#!/usr/bin/env python3
"""Retrain L1 on the attacks that beat it, and test it on attacks it never saw.

Continues fine-tuning L1's own model (Protect AI deberta-v3-base-prompt-injection-v2).
  Train: adaptive-attacker payloads from every run EXCEPT the three that breached guarded Qwen,
         plus 80% of data/clean_text.jsonl (scripts/gen_clean_text.py).
  Test (never trained on): those three runs (incl. the 10 winning payloads), the static catalog,
         the split / multilingual / invisible variants, the 36 real clean texts, the other 20%.
Writes models/l1-redcell/ (not in git) and dashboard/l1_retrain.json. Use the result with
REDCELL_L1_MODEL=models/l1-redcell.

    .venv/bin/python scripts/train_l1.py            # TRAIN_DEVICE=cpu if the GPU is busy
"""
import glob
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from compare_classifiers import SCENARIOS, rate, split_set, texts  # noqa: E402
from redcell_target.guards import L1_MODEL                         # noqa: E402

HELD_OUT_RUNS = "live_qwen2.5_7b__*__full__by_claude-haiku-5-5.json"   # where the 10 winners came from
OUT = os.path.join(ROOT, "models", "l1-redcell")
SEED, EPOCHS, LR, BATCH, MAX_LEN = 7, 3, 2e-5, 16, 256


def payloads(files) -> list[str]:
    return sorted({t["payload"] for f in files for g in json.load(open(f))["per_goal"] for t in g.get("transcript", [])})


def main() -> None:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    random.seed(SEED)
    torch.manual_seed(SEED)

    all_runs = glob.glob(os.path.join(ROOT, "dashboard", "adaptive", "*.json"))
    held = set(glob.glob(os.path.join(ROOT, "dashboard", "adaptive", HELD_OUT_RUNS)))
    clean = [json.loads(line)["text"] for line in open(os.path.join(ROOT, "data", "clean_text.jsonl"))]
    random.shuffle(clean)
    cut = int(len(clean) * 0.8)

    base_sets = texts()
    tests = {"10 winning payloads": base_sets["adaptive payloads that breached all five guards"],
             "held-out runs (all payloads)": payloads(held),
             "static catalog": base_sets["static catalog"],
             "split attacks, whole": base_sets["split attacks, whole (control)"],
             **{k: v for k, v in base_sets.items() if k.startswith("language:")},
             "real clean texts (36)": base_sets["benign texts"],
             "held-out generated clean": clean[cut:]}
    pairs = [p.parts for s in SCENARIOS for v, p in split_set(s) if v == "split"]
    unseen = {t for v in tests.values() for t in v} | {h for pr in pairs for h in pr}
    pos = [t for t in payloads(set(all_runs) - held) if t not in unseen]
    neg = [t for t in clean[:cut] if t not in unseen]
    train = [(t, 1) for t in pos] + [(t, 0) for t in neg]
    random.shuffle(train)
    print(f"train: {len(pos)} attacks + {len(neg)} clean · tests never trained on", flush=True)

    # TRAIN_DEVICE=cpu when Ollama holds the Mac GPU (MPS ran out of memory alongside a 7B model).
    device = os.getenv("TRAIN_DEVICE") or ("mps" if torch.backends.mps.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(L1_MODEL)

    def flags(model, inj, items, batch=32) -> list[bool]:
        model.eval()
        out = []
        with torch.no_grad():
            for i in range(0, len(items), batch):
                enc = tok(items[i:i + batch], truncation=True, max_length=512, padding=True,
                          return_tensors="pt").to(device)
                out += (model(**enc).logits.argmax(-1) == inj).tolist()
        return out

    def evaluate(model, inj) -> dict:
        res = {k: rate(flags(model, inj, v)) for k, v in tests.items()}
        h, t = flags(model, inj, [p[0] for p in pairs]), flags(model, inj, [p[1] for p in pairs])
        res["split attacks, either half"] = rate([a or b for a, b in zip(h, t)])
        return res

    model = AutoModelForSequenceClassification.from_pretrained(L1_MODEL).to(device)
    inj = model.config.label2id["INJECTION"]
    before = evaluate(model, inj)
    opt = torch.optim.AdamW(model.parameters(), lr=LR)
    for epoch in range(EPOCHS):
        model.train()
        random.shuffle(train)
        total = 0.0
        for i in range(0, len(train), BATCH):
            chunk = train[i:i + BATCH]
            enc = tok([t for t, _ in chunk], truncation=True, max_length=MAX_LEN, padding=True,
                      return_tensors="pt").to(device)
            labels = torch.tensor([inj if y else 1 - inj for _, y in chunk], device=device)
            loss = model(**enc, labels=labels).loss
            loss.backward()
            opt.step()
            opt.zero_grad()
            total += loss.item() * len(chunk)
        print(f"  epoch {epoch + 1}: loss {total / len(train):.4f}", flush=True)
    after = evaluate(model, inj)
    model.save_pretrained(OUT)
    tok.save_pretrained(OUT)

    print(f"\n{'flagged as injection':<34} {'L1 before':>14} {'L1 retrained':>14}")
    for k in before:
        b, a = before[k], after[k]
        print(f"{k:<34} {b['k']:>5}/{b['n']:<4} {b['rate'] * 100:3.0f}% {a['k']:>5}/{a['n']:<4} {a['rate'] * 100:3.0f}%")
    report = {"base": L1_MODEL, "train": {"attacks": len(pos), "clean": len(neg), "epochs": EPOCHS, "lr": LR,
              "seed": SEED, "held_out_runs": HELD_OUT_RUNS}, "before": before, "after": after}
    with open(os.path.join(ROOT, "dashboard", "l1_retrain.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nsaved {os.path.relpath(OUT, ROOT)} · wrote dashboard/l1_retrain.json")


if __name__ == "__main__":
    main()
