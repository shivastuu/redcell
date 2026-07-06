# Coordinated Disclosure Policy

Applies to real vulnerabilities found in third-party MCP servers (Class B/C). Class A is self-fix. Grounded in ISO/IEC 29147:2018 & 30111:2019 with a CERT/CC-style timeline.

**Timeline**
- **T0** = vendor notified. Default public disclosure at **T0 + 90 days**, or the moment a patch ships (whichever is first).
- Ack target: **3 business days**. No ack by **day 14** → escalate to CERT/CC.
- Good-faith fix extensions granted, hard-capped at **T0 + 120 days**.

**Where to report**
1. Open-source MCP server → the repo's GitHub private vulnerability reporting / Security Advisory (GHSA). GitHub is a CNA, so a genuine finding can earn a **CVE**.
2. Vendor with `security.txt` (RFC 9116) → its `Contact`/`Policy`.
3. Bug-bounty / VDP program → submit there (also the Class-C permission basis).
4. Unresponsive / multi-vendor / protocol-level → CERT/CC.

**Auto-generated artifacts** (human reviews and sends — nothing auto-submits): `report.md` (ISO 29147 fields), `finding.json` (OSV/CSAF-flavored), `advisory.draft.md` (GHSA body), and a **one-command deterministic reproducer** (`redcell repro <finding_id>`) driven by the frozen winning mutation.

**Embargo.** Winning mutations against Class-B/C targets are flagged `embargoed=true` in attack memory and excluded from the leaderboard/README/exports until `PUBLIC_DISCLOSURE`. CI fails if an embargoed mutation appears in a published artifact.

**Reporting a vuln in RedCell itself:** open a GitHub security advisory on this repo.
