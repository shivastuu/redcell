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
