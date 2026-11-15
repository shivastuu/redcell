# Flow

## 2026-11-14 — Phase 1: attack a real model

```mermaid
flowchart TD
  A["Read every file; ran sim campaign<br/>+ 4 test suites"] --> B{"Are the numbers real?"}
  B -->|"no: results hard-coded<br/>in sim_agent.py"| C["decision.md: Phase 1 plan"]
  C --> D["Ollama 0.40.16 in ~/.local<br/>(no admin) + qwen2.5:7b"]
  D --> E["specs.py: 7 goals × 6 published styles<br/>live_agent.py: Claude + Ollama loops<br/>output_channel.py replaces schema check"]
  E --> F{"pytest + ruff"}
  F -->|"1 fail: my own test<br/>assumed every question ends in '?'"| G["fixed the test"]
  G --> F2{"pytest + ruff"}
  F2 -->|"20/20, clean"| H{"Benign control on Qwen"}
  H -->|"0/6 false breaches"| I{"7-attack Qwen run"}
  I -->|"6/7 breached; spot-check:<br/>two secrets shared one value"| J["CANARY_NOTE added;<br/>blocked sends no longer count as sent"]
  J --> K["Anthropic key in .env<br/>(user created it; agent writes to .env are denied)"]
  K --> L{"Haiku benign + 7-attack run"}
  L -->|"0/6 false, 0/7 breached, $0.04;<br/>spot-check: memo read, ignored"| M["Real cost from API usage;<br/>leaderboard: per-target, live feed,<br/>progress panel, escaped output"]
  M --> N{"Full Qwen run (42)"}
  N -->|"81.0% [66.7, 90.0]"| O["Phase 1 done<br/>(full Haiku baseline still running)"]
```

## 2026-11-15 — Phase 2: real guardrails

```mermaid
flowchart TD
  A["decision.md: Phase 2 plan"] --> B["uv pip: torch, transformers,<br/>presidio, spaCy sm (no admin)"]
  B --> C["guards.py: L1 Protect AI DeBERTa,<br/>L2 datamarking, L4 Presidio,<br/>L5 render-safe"]
  C --> D{"Smoke test"}
  D -->|"L1 caught all attacks incl. base64;<br/>0 benign flagged;<br/>Presidio misses business secrets"| E{"Latency: GPU vs CPU"}
  E -->|"GPU p50 12 / max 150 ms<br/>CPU p50 33 / max 38 ms"| F["L1 on CPU"]
  F --> G["Wired into live_agent + mcp_server;<br/>l5_schema renamed l5_output"]
  G --> H{"Tests"}
  H -->|"found verifier blind spot:<br/>reference-style images"| I["output_channel.py fixed;<br/>test_guards.py added (25/25)"]
  I --> J{"Benign + utility on Qwen"}
  J -->|"L1 flagged L4's '[REDACTED]';<br/>model told customer<br/>'prompt injection issue'"| K["L4 omits the field;<br/>L1 blanks silently"]
  K --> L{"Benign + utility, both models"}
  L -->|"0/6 false, 0/6 blocked,<br/>useful 4/4 → 4/4"| M["Full Qwen campaign<br/>with real guards: running"]
```

```mermaid
flowchart TD
  A{"Full campaigns, real guards"} -->|"Haiku crashed twice:<br/>httpx2.ConnectTimeout (Wi-Fi/DNS)"| B["6 retries + 20 s connect timeout;<br/>runs wrapped in caffeinate"]
  A -->|"Qwen stalled:<br/>one reply at 4,400+ tokens"| C["1,024-token answer cap<br/>for local models"]
  B --> D{"Haiku, 42 attacks"}
  C --> E{"Qwen, 42 attacks"}
  D -->|"0% undefended, 0% defended;<br/>815 calls, $0.21"| F{"Spot-check by hand"}
  E -->|"83.3% undefended → 0% defended;<br/>L1 alone blocks 83.3%"| F
  F -->|"L4 only: Qwen leaked the code<br/>while refusing"| G["Relabelled 'adaptive' (4 fixed mutations)<br/>and L4 on the board"]
  G --> H["README, why.md, screenshots updated"]
  H --> I["Committed; pushed to<br/>github.com/shivastuu/redcell main"]
```

## 2026-11-15 — Phases 3–5 (in progress)

```mermaid
flowchart TD
  A["decision.md: Phases 3–5 plan<br/>(budget ~$4, user chose)"] --> B["Scenarios as data: fintech,<br/>healthcare, email (core + target)"]
  B --> C["Tool poisoning + combined attack;<br/>L1 scans tool descriptions"]
  C --> D{"Tests"}
  D -->|"48/63 distinct: same words, different<br/>delivery = different attack"| E["Test fixed (vector, payload)"]
  E --> F["Adaptive attacker (PAIR-style)<br/>+ AgentDojo runner (helper agent)"]
  F --> G{"Haiku static ×3 scenarios"}
  G -->|"0/189, useful 4/4 → 4/4, $0.51"| H{"Adaptive vs guarded Qwen"}
  H -->|"10/27 breached, all the<br/>system-prompt code"| I["--no-prompt-secret experiment"]
  I -->|"0/27"| J{"Adaptive vs Haiku"}
  J -->|"0/54; Opus refused (cyber)"| K{"AgentDojo on Haiku"}
  K -->|"0/144; its classifier<br/>halved utility"| L["Verifier fix: card shape before Luhn"]
  L --> M["Ollama restarted: 2 parallel, 8K context"]
  M --> N["Committed locally; Qwen campaigns,<br/>repeats and AgentDojo-Qwen still running"]
```

## 2026-11-15 — fold the finished Qwen runs into the write-up

```mermaid
flowchart TD
  A["decision.md: headline = all 189 + per agent;<br/>per-layer results in points"] --> B["Read result files: scorecards,<br/>repeats, AgentDojo, benign"]
  B --> C{"Every rate matches its counts?"}
  C -->|"no: goal-met rate was the any-breach rate<br/>(84.1% next to 46/63)"| D["scorecard._ci: rate = k/n<br/>+ regression test"]
  D --> E{"Test fails on old code,<br/>passes on new?"}
  E -->|"yes; all 9 test files pass"| F["Stored files corrected from their counts<br/>(3 Qwen scorecards + scorecard.json)"]
  F --> G["docs/results.md rewritten;<br/>why.md updated + Q48; README"]
  G --> H["Leaderboard: 'cuts X pts', subtitle,<br/>reading note, wider layout; rebuilt"]
  H --> I{"Screenshot (headless Chrome)"}
  I -->|"cost column clipped: widened, retaken"| J["docs/img/leaderboard-results.png"]
  J --> K["Next.js dashboard: 'cuts X pts' label"]
  K --> L{"npm run build"}
  L -->|"exported; new numbers in out/index.html"| M["Study page v3: 48 questions;<br/>node --check OK"]
  M --> N["Not committed: waiting for the user"]
```
