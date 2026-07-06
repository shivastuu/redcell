# Architecture

Depth on **one** workflow, not breadth across half-built demos.

```
        ATTACKER PLANE                          TARGET PLANE (system under test)
  plan -> dispatch --Send() per goal--> [ generic worker ]  Fintech triage / Q&A agent
       ^  RLVR mutate loop                   |             (Claude Haiku 4.5, LangGraph)
       |  RLVR mutate (SLM) <----------------+                 |  tools via
       |                                                       v
  verify  <----- DETERMINISTIC VERIFIER (reads the trace)   CUSTOM MCP SERVER (FastMCP)
       |         Verdict{breach, detector, reward}           get_customer_profile
  join -> route (budget?) --> Langfuse traces / leaderboard  initiate_transfer ...
                                                             ^ planted canaries / PII
   add layered defense (v2) -> re-run the SAME frozen corpus -> ASR collapse
```

## The four load-bearing ideas
1. **The verifier is deterministic code, not an LLM** — reads a server-recorded trace, never self-report. Makes it a true RLVR system (verifiable reward).
2. **A frozen, content-addressed corpus is the scientific control** — mutator disabled during scoring; `verifier_version` pinned; v1/v2 run byte-identical.
3. **Controlled agency** — supervisor topology, zero worker↔worker edges, typed handoffs, hierarchical budgets, bounded loops.
4. **Shipped & observable** — Langfuse/OTel traces, leaderboard mapped to OWASP LLM Top-10 + EU AI Act, CI gate that fails on guardrail regression.

## Five defense layers (v2)
L0 provenance labels · L1 input/output classifier (Llama Prompt Guard 2 + Llama Guard 4) · L2 spotlighting/datamarking · L3 tool allowlist + arg validation · L4 Presidio PII redaction · L5 schema validation. Attribution via add-one-in ablation (baseline + each layer enabled alone; see `scripts/run_campaign.py`); full Shapley over the 2⁵ coalitions is a documented future extension.

## The honest caveats (bring them up first)
- Report the **adaptive** number too (mutation loop vs the *defended* agent), not just the frozen-corpus collapse.
- Put a **dollar cost** on a full run (target-agent executions dominate, not mutation tokens).
- IEEE-CIS has **no free-text fields** — memo/note injection carriers are synthesized.
- A dramatic ~62% baseline is hard against a safety-trained Claude target; accept an honest smaller collapse or add a weaker open target.

See the RedCell build-bible artifact for the full 8-subsystem design + fact-check.
