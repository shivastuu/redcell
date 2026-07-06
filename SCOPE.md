# Scope

Every target RedCell can point at is exactly one class. The class sets what permission evidence is required and what attack profile is allowed. The **design** enforces this with a fail-closed **Target Authorization Gate (TAG)** in the coordinator (default `DENY`, exact endpoint match, `scope_hash` stamped in every trace) plus a `scope-guard` CI job. In the current runnable build the only targets are the author's own agent and the offline simulator, so the TAG and scope-guard are specified here but not yet wired.

| Class | Definition | Permission basis | Attack profile | Disclosure |
|---|---|---|---|---|
| **A — Owned** | The author's own fintech agent + FastMCP server | Ownership | Full | Self-fix |
| **B — Self-hosted third-party** | A registry package pulled and run as *your own* sandboxed instance | You own the running instance + license permits | Full vs *your* instance | CVD to maintainer |
| **C — Remote / hosted** | A live third-party endpoint | Explicit: safe-harbor bug-bounty scope, or signed written authorization | Read-only, rate-limited, budget-capped | Full CVD + embargo |

**Class B is the default and the star.** Almost every "public MCP server" ships as an installable package, not a hosted endpoint — so you pull it and attack your own instance. The CFAA unauthorized-access element is never met, and you keep the "I pentested real public MCP servers" headline.

Adding/promoting a **Class C** target requires a **GPG-signed human commit** to `scope.lock.yaml` plus a permission evidence bundle in `permissions/`. No agent — not even the planner — can widen scope.

Harm-avoidance controls (always on): egress-locked sandbox network, synthetic data + planted honeytokens only (no real PII, ever), per-run budget/rate caps, degraded profile for anything not fully owned, auto-stop-on-real-data.
