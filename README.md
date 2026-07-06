# RedCell 🎯

**An autonomous multi-agent red-team that breaks other AI agents — and proves the fix with a number.**

A coordinator delegates to specialized attack workers that jailbreak, poison, and exfiltrate against a real fintech agent whose tools live behind a custom MCP server. Every breach is confirmed by **deterministic code reading a server-recorded trace** — never a model's self-report. Then you harden the target and re-run the *identical frozen corpus* to show the attack-success rate collapse.

> Full design doc / build bible: the RedCell artifact (architecture, 8 subsystems, fact-check, 12-week roadmap).

---

## ⚠️ Scope & Safety (read first)

RedCell only ever attacks **(A)** the author's own agent, **(B)** public MCP servers pulled from the official registry and run as the author's own *sandboxed instances*, or **(C)** remote services with explicit written permission / an active safe-harbor bug-bounty. Scope is enforced by a **fail-closed gate** (`scope.lock.yaml` → the Target Authorization Gate) and re-verified in CI. **No third-party production service is ever attacked without authorization.** See [`SCOPE.md`](SCOPE.md), [`ETHICS.md`](ETHICS.md), [`DISCLOSURE.md`](DISCLOSURE.md).

---

## Quickstart — the WHOLE loop runs with ZERO installs

Everything below is pure stdlib and deterministic — no API keys, no `pip install`, no cost. It runs against a faithful vulnerable-target **simulator**; swap `SimHarness` → `LiveHarness` (real Claude + FastMCP) later and nothing else changes.

```bash
python3 scripts/run_campaign.py              # ← the money shot: full attack→defend→measure loop
python3 scripts/build_leaderboard.py         # renders dashboard/leaderboard.html (open in browser)
python3 scripts/seed_demo.py                 # the seeded fintech data the MCP tools serve
python3 scripts/demo_verifier.py             # the breach oracle on a single trace
python3 tests/test_verifier_determinism.py && python3 tests/test_campaign_asr_collapse.py && python3 tests/test_seed.py
```

With dependencies (`uv sync`) you also get the real target and the real orchestrator:

```bash
export ANTHROPIC_API_KEY=...                          # real Claude Haiku target
uv run python scripts/run_campaign.py --live --n 1    # LiveHarness instead of the simulator
uv run python -m redcell_attackers.coordinator        # the real LangGraph supervisor (Send() fan-out)
```

`run_campaign.py` runs the real thing end-to-end and prints:

```
ATTACK-SUCCESS RATE
  baseline (undefended)      59.5%   95% CI [44.5%,73.0%]   n=42
  defended  (frozen replay)   0.0%   95% CI [ 0.0%, 8.4%]   <- the money shot
  defended  (ADAPTIVE)       31.0%   95% CI [19.1%,46.0%]   <- the honest number
```

Plus per-OWASP collapse, per-layer attribution (add-one-in), and the cost/routing math. The lesson it *demonstrates*, not just claims: **structural controls (L2 spotlight, L3 allowlist, L5 schema) hold under adaptive pressure; probabilistic filters (L1 classifier, L4 redaction) fall to encoding+obfuscation** — which is why you report both numbers. Every verdict comes from deterministic code reading a trace, no LLM in the reward path.

### Full stack (needs [uv](https://docs.astral.sh/uv/))

```bash
cp env.example .env         # fill in keys
docker compose up -d        # postgres+pgvector, ollama
uv sync                     # install all workspace packages
uv run pytest -q            # full test suite
uv run python -m redcell_target.mcp_server   # the target MCP server
```

---

## Layout

```
packages/
  redcell-core/        schemas, ids, config, model router   (stdlib)
  redcell-verifiers/   DETERMINISTIC breach oracle          ← the crown jewel
  redcell-target/      the System Under Test: agent + FastMCP server (v1→v2)
  redcell-attackers/   LangGraph supervisor + generic RLVR worker (per-goal fan-out)
taxonomy/techniques/   versioned attack catalog (YAML, the join key)
corpus/                frozen, content-addressed attack corpus
scripts/demo_verifier.py   ← run this first
tests/                 verifier determinism + correctness
docs/                  architecture, ADRs, OWASP + EU-AI-Act mappings
```

## Status

**The entire attack→verify→mutate→defend→measure loop runs today** against the deterministic simulator:

- [x] Monorepo + core schemas + **deterministic verifier** (canary w/ decode-battery+tokenization, unauthorized-tool, PII/Luhn, schema)
- [x] Attack taxonomy/catalog + **prompt-injection & policy-evasion techniques** (RLVR mutation search)
- [x] Vulnerable-target **simulator** + `TargetHarness` seam (swap in the real LLM unchanged)
- [x] **Layered defense (L1–L5)** + frozen content-addressed corpus + before/after **ASR collapse** + per-layer attribution
- [x] **Adaptive-attack** measurement (the honest number the design review demanded)
- [x] Wilson CIs, cost/routing math, a green test suite (4 suites: verifier/campaign/seed/eval), CI skeleton
- [x] **`LiveHarness`** — real Claude Haiku agent, **genuinely over MCP** (FastMCP server + in-memory MCP client); needs `uv sync` + API key
- [x] **Real LangGraph supervisor** (`coordinator.py`) — `StateGraph` + `Send()` fan-out + additive reducer
- [x] **LangSmith tracing** — auto-instruments the LangGraph coordinator; `@traced` adds spans to the RLVR loop + verifier (no-op offline)
- [x] **Leaderboard** — `scorecard.json` export + self-contained `dashboard/leaderboard.html`
- [x] **IEEE-CIS seeding** (`redcell_target.seed`) — synthetic generator by default, real Kaggle CSV auto-detected; MCP tools serve it (`scripts/seed_demo.py`, `scripts/fetch_ieee_cis.py`)
- [x] **LLM-judge + Cohen's κ** (`redcell-eval`) — audited secondary instrument; `scripts/run_eval.py` (κ≈0.68 vs the verifier; judge misses encoded exfil → why the verifier is truth)
- [x] **CI gate that blocks on ASR regression** (`scripts/run_gate.py` + `guardrails.lock.json` + `.github/workflows/redteam-gate.yml`) — "blocked-attacks-must-stay-blocked" set-difference; demo: `--drop L1 L4` turns it red
- [x] **Next.js leaderboard** (`apps/dashboard/`) — reads the same `scorecard.json`; `npm run sync && npm run dev`

**Everything above runs offline with zero installs and zero API keys.** `--live` (real Claude over FastMCP), the LangGraph coordinator, LangSmith tracing, and the Next.js app activate with `uv sync` / `npm install` + keys.

### Observability (LangSmith)

Set the env (in `.env`, never in code) and the LangGraph coordinator traces itself:

```bash
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY=lsv2_...      # rotate immediately if it ever leaks
export LANGSMITH_PROJECT=redcell
uv run python -m redcell_attackers.coordinator   # traces appear in LangSmith
```

`@traced` (in `redcell_core.tracing`) also spans the RLVR search + deterministic verifier, so even the offline sim campaign is observable. Langfuse/OTel remains a drop-in alternative.

> The simulator is a faithful, deterministic **stand-in for the LLM target** so the whole architecture is demonstrable offline. Swapping it for the real agent changes one class (`SimHarness` → `LiveHarness`); the verifier, RLVR loop, defenses, corpus, and scorecard are untouched.

## Positioning

Built *next to* NVIDIA garak & Microsoft PyRIT, not on top: the differentiators are a **deterministic programmatic verifier**, a **verifiable-reward mutation loop**, and a **frozen-corpus CI gate** — the three things those tools don't give you.
