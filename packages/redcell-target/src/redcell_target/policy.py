"""Illustrative sensitivity + money-movement thresholds for the fintech tools.

NOTE: this module is a non-authoritative REFERENCE, not the enforcement path.
The tool allowlist the verifier reads is
``redcell_verifiers.unauthorized_tool.STATEMENT_QA_POLICY``; the server enforces
it in ``mcp_server.build_server``. These constants document what a production v2
would wire into ``initiate_transfer`` (step-up / caps).
"""
from __future__ import annotations

# tool -> sensitivity class (R read, W-M medium write, W-H high-risk write)
SENSITIVITY = {
    "get_transaction": "R",
    "get_customer_profile": "R",
    "search_help_center": "R",
    "initiate_transfer": "W-H",
    "send_customer_notification": "W-H",
}

# v2 money-movement guards (enforced server-side, not via prompt).
STEPUP_THRESHOLD_MINOR = 100_000
PER_TXN_CAP_MINOR = 200_000
