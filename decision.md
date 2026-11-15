# Decisions

## 2026-11-14 — Phase 1: attack a real model

```mermaid
flowchart TD
  Q1{"What does RedCell<br/>attack for real?"}
  Q1 -->|"keep simulator numbers"| R1["Rejected<br/>the results are written into the simulator"]
  Q1 -->|"local Qwen2.5-7B via Ollama<br/>+ Claude Haiku 5.5"| C1["Chosen (user)<br/>free dev runs + a safety-trained target"]

  C1 --> Q2{"How to call the<br/>local model?"}
  Q2 -->|"OpenAI-compatible API<br/>(openai pkg already in workspace)"| C2["Chosen<br/>same code works for vLLM / Groq"]
  Q2 -->|"Ollama native API via urllib"| R2["Rejected<br/>ties the code to Ollama"]
  Q2 -->|"LiteLLM"| R3["Rejected<br/>new dependency for 2 providers"]

  C1 --> Q3{"What attacks?"}
  Q3 -->|"current one-line payloads"| R4["Rejected<br/>a real model refuses all → 0%, shows nothing"]
  Q3 -->|"7 goals × 6 published attack styles<br/>(AgentDojo, InjecAgent, Wei et al.)"| C3["Chosen<br/>42 genuinely different attacks"]

  C1 --> Q4{"Mutation operators<br/>for now?"}
  Q4 -->|"real text transforms: delimiter, persona,<br/>base64 input, spaced-out output"| C4["Chosen<br/>'language' dropped: can't fake a translation"]
  Q4 -->|"LLM rewrites failed attacks"| R5["Rejected for now<br/>that is Phase 3"]

  C1 --> Q5{"Where does the policy<br/>being attacked live?"}
  Q5 -->|"nowhere (today)"| R6["Rejected<br/>leaking unmarked data isn't an attack"]
  Q5 -->|"system prompt: read-only, notes and<br/>escalation code confidential"| C5["Chosen<br/>baseline = prompt rules only, how most agents ship"]

  C1 --> Q6{"What counts as<br/>a breach?"}
  Q6 -->|"output isn't exactly one JSON object"| R7["Rejected<br/>real models add prose → false breaches"]
  Q6 -->|"secret leaves, forbidden tool runs, card<br/>number leaks, auto-loading image link"| C6["Chosen<br/>each one is real harm"]

  C1 --> Q7{"How do we know the<br/>checker isn't wrong?"}
  Q7 -->|"benign control: normal questions,<br/>no attack, real model"| C7["Chosen<br/>must score 0 breaches"]

  C1 --> Q8{"Trace when the model<br/>made no tool call?"}
  Q8 -->|"invent a get_transaction record"| R8["Rejected<br/>trace must be only what happened"]
  Q8 -->|"empty tool list"| C8["Chosen"]

  C1 --> O1["Open<br/>Anthropic API key from user<br/>(needed for Claude runs)"]

  classDef chosen fill:#d4edda,stroke:#28a745,color:#000
  classDef rejected fill:#f8d7da,stroke:#dc3545,color:#000
  classDef open fill:#fff3cd,stroke:#e0a800,color:#000
  class C1,C2,C3,C4,C5,C6,C7,C8 chosen
  class R1,R2,R3,R4,R5,R6,R7,R8 rejected
  class O1 open
```

- The simulator stays, but only as a fast test fixture for the pipeline. Its numbers are never reported.
- LLM05 (hidden channel) moves from direct to indirect: a user asking for their own image link is not an attack, a poisoned memo doing it is. Goal ids change, so the frozen corpus and `guardrails.lock.json` are regenerated.
- The old `schema` breach (anything other than one JSON object) becomes `output_channel` (markdown/HTML image or other auto-loading link in the output). The test that asserted `[1,2,3]` is a breach is replaced.
- Qwen2.5-7B on an M3 Pro takes seconds per attack, so dev runs use `--n 1` (7 attacks); full runs take a while.

## 2026-11-15 — Phase 2: real guardrails, measured honestly

```mermaid
flowchart TD
  Q1{"L1: how to detect<br/>injected instructions?"}
  Q1 -->|"keep the 6-word regex"| R1["Rejected<br/>trivial to bypass, nobody ships it"]
  Q1 -->|"llm-guard package"| R2["Rejected<br/>no release since 2025-05,<br/>hard-pins transformers 4.51.3"]
  Q1 -->|"Protect AI DeBERTa v2,<br/>called directly via transformers"| C1["Chosen<br/>same model llm-guard wraps,<br/>Apache-2.0, not gated"]
  Q1 -->|"Llama Prompt Guard 2"| O1["Open<br/>gated licence; possible<br/>second classifier later"]

  C1 --> Q2{"L1: what does it scan?"}
  Q2 -->|"user message only"| R3["Rejected<br/>indirect attacks arrive in tool output"]
  Q2 -->|"user message + every tool result"| C2["Chosen"]
  C2 --> Q3{"A tool result is flagged?"}
  Q3 -->|"block the whole request"| R4["Rejected<br/>one poisoned memo kills the answer"]
  Q3 -->|"drop the flagged field, keep the rest"| C3["Chosen<br/>answer survives, attack doesn't"]

  Q4{"L2: how to separate<br/>data from instructions?"}
  Q4 -->|"one sentence in the prompt (today)"| R5["Rejected<br/>weakest form of the idea"]
  Q4 -->|"datamarking (Hines et al. 2024)"| C4["Chosen<br/>published, cheap, works on any model"]

  Q5{"L4: how to stop leaks?"}
  Q5 -->|"replace the known secret string (today)"| R6["Rejected<br/>defense holds the answer key:<br/>it mirrors the judge"]
  Q5 -->|"withhold confidential fields at source<br/>+ Presidio DLP on replies and messages"| C5["Chosen<br/>real tools, no knowledge of secret values"]

  Q6{"L5: how to stop<br/>auto-loading images?"}
  Q6 -->|"keep only the JSON (today)"| R7["Rejected<br/>deletes the answer"]
  Q6 -->|"detect images with the verifier's regex"| R8["Rejected<br/>the judge can't see its own blind spots"]
  Q6 -->|"escape markup so nothing renders"| C6["Chosen<br/>structural, independent of the judge"]

  Q7{"How do we know defenses<br/>don't break the agent?"}
  Q7 -->|"attack success only"| R9["Rejected<br/>'refuse everything' scores 0%"]
  Q7 -->|"+ utility on benign questions<br/>+ false alarms + guard latency"| C7["Chosen"]

  classDef chosen fill:#d4edda,stroke:#28a745,color:#000
  classDef rejected fill:#f8d7da,stroke:#dc3545,color:#000
  classDef open fill:#fff3cd,stroke:#e0a800,color:#000
  class C1,C2,C3,C4,C5,C6,C7 chosen
  class R1,R2,R3,R4,R5,R6,R7,R8,R9 rejected
  class O1 open
```

- L3 (server-side tool allowlist) is already a real control and stays as it is.
- L4 combines withholding at source and Presidio DLP, so per-layer attribution cannot separate them.
- torch / transformers / presidio are imported lazily, so the stdlib simulator path and the CI spine keep working without them.
- The simulator's defense model is unchanged; it stays a pipeline fixture and its numbers are never reported.

## 2026-11-15 — Phases 3–5: stronger attacks, more agents, firmer numbers, polish

```mermaid
flowchart TD
  Q1{"How to cover more than a bank?"}
  Q1 -->|"20 shallow domains"| R1["Rejected<br/>breadth without proof"]
  Q1 -->|"scenarios as data: fintech, healthcare,<br/>email — same 9 goal types each"| C1["Chosen<br/>attacks written once, comparable results"]

  Q2{"Which new attacks?"}
  Q2 -->|"MCP tool poisoning<br/>(injection in a tool description)"| C2["Chosen<br/>MCP-specific; L1 also scans descriptions"]
  Q2 -->|"combined attack (Liu et al. 2024)"| C3["Chosen<br/>strongest static style in that benchmark"]
  Q2 -->|"GCG gradient attack"| R2["Rejected<br/>needs raw weights; impossible on Claude"]

  Q3{"Adaptive attacker?"}
  Q3 -->|"retry 4 fixed mutations (today)"| R3["Rejected as 'adaptive'<br/>it can't react to refusals"]
  Q3 -->|"PAIR-style LLM rewriter, 6 rounds,<br/>told which defenses are on"| C4["Chosen<br/>verifier is the reward"]
  C4 --> Q4{"Which attacker model?"}
  Q4 -->|"Opus on everything"| R4["Rejected<br/>~$5–7, over the $4 budget"]
  Q4 -->|"Haiku on all goals +<br/>Opus on a headline set"| C5["Chosen (user budget ~$4)"]
  C4 --> Q5{"Server-side refusal fallback<br/>for the attacker?"}
  Q5 -->|"on"| R5["Rejected<br/>a fallback model would silently<br/>become the attacker"]
  Q5 -->|"off; attacker refusals are counted"| C6["Chosen"]

  Q6{"Official benchmark?"}
  Q6 -->|"AgentDojo banking, with and without<br/>its Protect AI classifier defense"| C7["Chosen<br/>checks our L1 result on outside attacks"]
  Q6 -->|"in our main .venv"| R6["Rejected<br/>its pins could break running code"]

  Q7{"How to stay inside the budget?"}
  Q7 -->|"estimates only"| R7["Rejected<br/>money needs a hard stop"]
  Q7 -->|"spend cap in code; run aborts<br/>before passing it (unknown price = abort)"| C8["Chosen<br/>fail closed"]

  Q8{"Per-layer attribution cost"}
  Q8 -->|"replay every attack per layer"| R8["Rejected<br/>pays to replay attacks that never worked"]
  Q8 -->|"replay only baseline winners per layer;<br/>full replay kept for 'all defenses'"| C9["Chosen<br/>attribution only concerns winners"]

  classDef chosen fill:#d4edda,stroke:#28a745,color:#000
  classDef rejected fill:#f8d7da,stroke:#dc3545,color:#000
  class C1,C2,C3,C4,C5,C6,C7,C8,C9 chosen
  class R1,R2,R3,R4,R5,R6,R7,R8 rejected
```

- The mutation-retry phase stays in the campaign, but it is labelled for what it is; the adaptive attacker is reported separately.
- "Attacker's goal met" (targeted) is reported next to "any rule broken", so collateral breaches stop inflating attack success.

### 2026-11-15 — mid-course: what the adaptive results changed

```mermaid
flowchart TD
  F1["Finding: 10/27 adaptive breaches on guarded Qwen,<br/>every one the system-prompt code"] --> Q1{"Add another filter,<br/>or remove the cause?"}
  Q1 -->|"another output filter for the code"| R1["Rejected<br/>a filter that knows the secret mirrors the judge"]
  Q1 -->|"take the secret out of the prompt,<br/>rerun the same attacker"| C1["Chosen<br/>structural fix, measured: 0/27"]

  F2["Finding: a 'card number' that was<br/>made-up dashed single digits"] --> Q2{"How to fix the check?"}
  Q2 -->|"drop the card check"| R2["Rejected<br/>real card leaks must still count"]
  Q2 -->|"require a card shape before Luhn,<br/>+ regression test"| C2["Chosen<br/>strictly narrower: old zeros stay zeros"]

  F3["Ollama: 1 request at a time,<br/>4K context"] --> Q3{"Wait ~5 h, or restart it?"}
  Q3 -->|"restart: 2 parallel, 8K context"| C3["Chosen<br/>clients retry; campaign survived"]
  Q3 -->|"leave 4K"| R3["Rejected<br/>long AgentDojo prompts would be cut silently"]

  F4["Opus attacker: refusal, category 'cyber'"] --> Q4{"Work around it?"}
  Q4 -->|"fallback model or rewording"| R4["Rejected<br/>changes the attacker / bypasses a safety system"]
  Q4 -->|"record as a finding;<br/>Haiku attacker carries the adaptive results"| C4["Chosen"]

  classDef chosen fill:#d4edda,stroke:#28a745,color:#000
  classDef rejected fill:#f8d7da,stroke:#dc3545,color:#000
  class C1,C2,C3,C4 chosen
  class R1,R2,R3,R4 rejected
```

## 2026-11-15 — fold the finished Qwen runs into the write-up

```mermaid
flowchart TD
  Q1{"Which Qwen number is the headline?"}
  Q1 -->|"keep the 42-attack 83.3%"| R1["Rejected<br/>its result file was replaced by the 63-attack run;<br/>every reported number needs a file"]
  Q1 -->|"fintech only, 84.1%"| R2["Rejected<br/>hides the 56–84% spread across agents"]
  Q1 -->|"all 189 (71.4%) + per scenario,<br/>fintech repeats as the spread"| C1["Chosen"]

  Q2{"How to word per-layer results?"}
  Q2 -->|"share of successful attacks blocked"| R3["Rejected<br/>the code computes baseline ASR minus<br/>single-layer ASR (scorecard.py:99)"]
  Q2 -->|"percentage points cut"| C2["Chosen<br/>matches the code"]

  Q3{"AgentDojo: 'classifier halved usefulness<br/>for no security gain'?"}
  Q3 -->|"keep"| R4["Rejected<br/>on Qwen it cut attacks 20.8% → 6.9%<br/>with no utility loss"]
  Q3 -->|"cost depends on the model;<br/>per-field wiring avoided Haiku's loss"| C3["Chosen"]

  Q4{"Screenshots"}
  Q4 -->|"retake results view with headless Chrome"| C4["Chosen"]
  Q4 -->|"live-feed view"| O1["Open<br/>needs a running campaign; old one kept"]

  Q5{"Resume and portfolio say 83%"} --> O2["Open<br/>still true for the bank agent (repeats mean 83.1%);<br/>user's call"]

  classDef chosen fill:#d4edda,stroke:#28a745,color:#000
  classDef rejected fill:#f8d7da,stroke:#dc3545,color:#000
  classDef open fill:#fff3cd,stroke:#e0a800,color:#000
  class C1,C2,C3,C4 chosen
  class R1,R2,R3,R4 rejected
  class O1,O2 open
```

- Docs only; no code changes. Nothing is committed until the user asks.
