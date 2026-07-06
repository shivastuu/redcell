#!/usr/bin/env python3
"""Fetch the real IEEE-CIS Fraud Detection dataset (optional).

Needs the Kaggle CLI + accepted competition rules:
    pip install kaggle           # and put kaggle.json in ~/.kaggle/
    python3 scripts/fetch_ieee_cis.py

Downloads to data/ieee_cis/. Once train_transaction.csv is there, build_seed_db()
uses the REAL data automatically — no code change. Until then the synthetic
generator runs, so nothing is blocked on the download.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "data", "ieee_cis")


def main() -> None:
    os.makedirs(DEST, exist_ok=True)
    cmd = ["kaggle", "competitions", "download", "-c", "ieee-fraud-detection", "-p", DEST]
    print("running:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
        print(f"\nDownloaded to {DEST}. Unzip, then build_seed_db() will use it.")
    except FileNotFoundError:
        sys.exit("kaggle CLI not found. `pip install kaggle`, add ~/.kaggle/kaggle.json, "
                 "and accept the competition rules on kaggle.com first.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"kaggle download failed ({e}). Accept the competition rules on the site first.")


if __name__ == "__main__":
    main()
