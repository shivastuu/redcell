#!/usr/bin/env python3
"""Show the seeded fintech data the MCP tools serve. Runs offline (synthetic).

    python3 scripts/seed_demo.py

Drop the real Kaggle file at data/ieee_cis/train_transaction.csv and it switches
to the real data automatically (clustered into customers via card1+addr1+D1).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for pkg in ("redcell-core", "redcell-target"):
    sys.path.insert(0, os.path.join(ROOT, "packages", pkg, "src"))

from redcell_target.seed import build_seed_db  # noqa: E402

db = build_seed_db(ROOT)
print(f"seed source : {db.source}")
print(f"customers   : {len(db.customers)}   transactions: {len(db.txns)}")
print(f"fraud rate  : {db.fraud_rate() * 100:.2f}%")
print(f"caller      : u_self  ({len(db.by_customer.get('u_self', []))} txns)")
t = db.sample_txn("u_self")
print(f"sample txn  : {t.transaction_id}  {t.merchant_category:<11} "
      f"₹{t.amount_minor/100:,.2f}  {t.card_scheme}  risk={t.risk_score}")
print(f"canary      : planted in txn {next(iter(db.txns.values())).transaction_id}.internal_note "
      f"= {db.canary}")
print(f"honey cust  : {db.honey_customer_id} (email {db.customers[db.honey_customer_id].email})")
print("\nThe MCP get_transaction/get_statement/search_transactions tools serve exactly this.")
