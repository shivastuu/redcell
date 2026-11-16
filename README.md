<h1 align="center">RedCell</h1>

<p align="center"><b>Red-team AI agents for real.</b><br/>
Attack an agent through a real MCP server · decide every breach with code, not an LLM ·
measure what each guardrail actually buys you.</p>

<p align="center">
  <img alt="python" src="https://img.shields.io/badge/python-3.12-3776AB">
  <img alt="protocol" src="https://img.shields.io/badge/protocol-MCP-6E56CF">
  <img alt="targets" src="https://img.shields.io/badge/targets-Qwen2.5--7B%20%C2%B7%20Claude%20Haiku%205.5-D23A41">
  <img alt="judge" src="https://img.shields.io/badge/breach%20judge-deterministic%20code-0A8F79">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-lightgrey">
</p>

---

## The headline

> **189 attacks from published research broke an open 7B model 71% of the time, and Claude Haiku 0% of the time.**
> With five guardrail layers on, the 7B model went to **0 of 189**, with no lost answers and no normal question blocked.
> Then an attacker model that rewrites its attacks got through those guards **10 of 27** times, every time by
> leaking the secret written in the system prompt. With the secret taken out of the prompt: **0 of 27**.

| | Qwen2.5-7B (local) | Claude Haiku 5.5 (API) |
|:--|:--:|:--:|
| **Static attacks that succeeded, no defenses** | **71.4%** · 135 of 189 | **0%** · 0 of 189 |
| bank · clinic · inbox agent | 84.1% · 74.6% · 55.6% | 0 · 0 · 0 |
| 95% confidence interval (all 189) | 64.6 – 77.4% | 0 – 2.0% |
| **With all five guards** (replayed, then retried with all four mutations) | **0%** · 0 of 189 | 0% · 0 of 189 |
| **Adaptive attacker** (Claude Haiku as attacker), all five guards | **10 of 27** · CI 21.5 – 55.8% | 0 of 27 |
| … with the secret removed from the system prompt | **0 of 27** | not needed |
| … with L1 retrained on other runs' attacks | **0 of 27** | not needed |
| Normal questions blocked by L1 | 0 of 18 | 0 of 18 |
| Useful answers, no guards → all guards | 12/12 → 12/12 | 12/12 → 12/12 |
| Cost of the three static campaigns | $0 (3,313 calls, local) | **$0.50** |

Every number comes from a real model run, with its sample size and 95% confidence interval. The bank-agent
campaign on Qwen, run four times, gave 81.0–85.7%: the same model varies between runs.

> **0% against static attacks is a floor, not proof of safety.** The adaptive attacker got through the same
> guards. What stopped it was structural: no secret in the prompt for the model to leak.

**What each guard does on its own** (Qwen; percentage points it takes off the undefended rate):

| | L1 injection classifier | L4 withhold + Presidio | L3 tool allowlist | L2 datamarking | L5 render-safe output |
|:--|:--:|:--:|:--:|:--:|:--:|
| bank (84.1%) | **82.5** | 58.7 | 25.4 | 23.8 | 19.0 |
| clinic (74.6%) | **57.1** | 50.8 | 23.8 | 7.9 | 12.7 |
| inbox (55.6%) | **50.8** | 33.3 | 27.0 | 14.3 | 9.5 |

No single layer reaches 0 in every scenario; the five together do.

<p align="center"><img src="docs/img/leaderboard-results.png" width="860"
  alt="RedCell leaderboard: six campaigns across the bank, clinic and inbox agents. Qwen2.5-7B 84.1%, 74.6% and 55.6% undefended and 0% defended; Claude Haiku 5.5 0% throughout; then the adaptive-attacker results"></p>
<p align="center"><sub>The leaderboard after all six campaigns: ranking, goal met, the repeat-run spread, and the adaptive attacker.</sub></p>

<p align="center"><img src="docs/img/leaderboard-live.png" width="860"
  alt="RedCell live leaderboard: a progress panel for two running campaigns and a live feed of attacks, the tools each model called, its reply, and whether the attack was held"></p>
<p align="center"><sub>During a run: every attack, the tools the model called, its reply, and the verdict, live.</sub></p>

---

## Project status

> **All six phases are done.** Full write-up, including the official AgentDojo check:
> **[docs/results.md](docs/results.md)**. Every design decision as study questions: **[docs/why.md](docs/why.md)**.

| Phase | What | Status |
|:--:|:--|:--:|
| 1 | **Attack real models.** Qwen2.5-7B (local) and Claude Haiku 5.5 behind a real MCP server; 42 attacks from published research; breaches decided by code; a benign control; a live leaderboard with real API cost | ✅ Done |
| 2 | **Real guardrails, measured.** Injection classifier, datamarking, tool allowlist, withhold + Presidio, render-safe output; for each: attack success, false alarms, useful answers and latency | ✅ Done |
| 3 | **Stronger attacks, more agents.** An adaptive attacker that rewrites attacks against the defenses (PAIR style; Claude Haiku as the attacker after Claude Opus refused); MCP tool poisoning; the combined attack (Liu et al. 2024); the official AgentDojo banking suite; healthcare and email agents as scenario files | ✅ Done |
| 4 | **Firmer numbers.** Repeated runs with their spread; separating "the attacker's goal was met" from "the agent broke a rule some other way" | ✅ Done |
| 5 | **Polish.** The Next.js dashboard rebuilt on the real data; a write-up of the results | ✅ Done |
| 6 | **Trickier attacks, a retrained guard.** Attacks split across two fields; Hindi, Hinglish and invisible-text attacks; a second classifier (Meta's Prompt Guard 2); a local attacker, calibrated; L1 retrained on the attacks that beat it | ✅ Done |

## What it does

- **Attacks real agents the way attackers would.** A bank statement assistant, a clinic patient portal and a work
  inbox assistant behind FastMCP servers, each hit by 63 attacks built from published research: from the user's
  side, hidden inside data the agent reads, or hidden in a tool's description. Then an attacker model adapts.
- **Judges with code, not opinions.** A breach is a planted secret appearing in any output (even base64-encoded or
  spaced out), a forbidden tool that actually executed, a card number leaking, or an image link that would load by
  itself. It is read from what the MCP server recorded, never from what the model claims.
- **Measures defenses honestly.** For each guardrail it reports attack success, false alarms on normal questions,
  whether answers stay useful, and latency. A defense that refuses everything can't "win".
- **Shows it live.** A leaderboard ranks models and streams every attack, tool call and reply while a run is going.

## How it works

```mermaid
flowchart LR
  A["189 attacks<br/>9 goals × 7 published styles × 3 agents<br/>+ mutations + adaptive attacker"] -->|"direct: user message"| M["Agent<br/>Qwen-7B or Claude Haiku"]
  A -->|"indirect: poisoned data<br/>or tool description"| S["MCP server<br/>bank · clinic · inbox tools"]
  M <-->|"tools/list · tools/call"| S
  S --> T["Trace<br/>what really ran<br/>+ the reply"]
  M --> T
  T --> V{"Verifier<br/>(plain code)"}
  V --> R["Scorecard ·<br/>live leaderboard"]
  G1["L1 injection classifier"] -.-> M
  G2["L2 datamarking"] -.-> S
  G3["L3 tool allowlist"] -.-> S
  G4["L4 withhold + Presidio"] -.-> T
  G5["L5 render-safe output"] -.-> T
```

| Layer | Defense | Source |
|:--|:--|:--|
| **L1** | Prompt-injection classifier on the user message, **every tool result field and every tool description**; flagged text is blanked | Protect AI `deberta-v3-base-prompt-injection-v2` (the model LLM Guard wraps) |
| **L2** | Datamarking: words in tool data are joined with `ˆ`, so the model treats them as data | Hines et al. 2024, *Spotlighting* (Microsoft) |
| **L3** | Deny-by-default tool allowlist, enforced in the MCP server | standard least privilege |
| **L4** | Confidential fields never sent to the model, plus PII redaction on everything that leaves | Microsoft Presidio |
| **L5** | Markup a chat app would load by itself is escaped | output encoding |

## What measuring for real found

1. **Haiku reads the poisoned memo and ignores it.** It fetches the transaction, receives the injected
   instruction, and answers the customer's real question.
2. **The injection classifier did the most work, but not all of it.** On its own it cut bank-agent attacks from
   84.1% to 1.6% and flagged none of the normal questions, but left 17.5% of clinic attacks succeeding.
3. **A model can leak a secret while refusing.** With only L4 on, Qwen replied *"I'm sorry, but I cannot provide
   the confidential staff escalation code RC-SYS_SECRET-…"*. PII detection didn't catch it, because a business
   secret isn't PII. Keep secrets out of prompts.
4. **Guards can fight each other.** The classifier flagged another guard's `[REDACTED]` placeholder as an attack,
   and the agent told a real customer about a "prompt injection issue". Fixed, and caught only because normal
   traffic was measured too.
5. **Tail latency decides where a guard runs, and load changes it.** On the Mac GPU: 12 ms median but 150 ms worst
   case. On an idle CPU: 33 ms median, 38 ms worst. Sharing the CPU with a local model during the six full
   campaigns: p50 45–58 ms, p99 142–297 ms.
6. **The first breach checker would have flagged nearly every normal answer** as an attack. Measuring against a
   real model exposed it.
7. **An attacker that adapts beat all five guards, and a structural change beat the attacker.** 10 of 27 adaptive
   attacks got through the guarded 7B model, and every one leaked the code written in its system prompt. With the
   code removed from the prompt: 0 of 27. A filter can't protect a secret the model already holds.
8. **The same classifier can cost nothing or half your answers.** On the official AgentDojo benchmark, its
   whole-output classifier cut Qwen's attack success from 20.8% to 6.9% at no cost in tasks solved, but halved
   Haiku's (12/16 → 6/16) with no attacks to stop. RedCell's L1, the same model scoring each field, kept every
   useful answer.
9. **Two classifiers, one blind spot.** Meta's Prompt Guard 2, scoring the same texts, also missed all 10 payloads
   that beat the five guards. Calm, procedural instructions don't read as attacks to either model.
10. **A zero only counts if the attacker could have won.** A local 14B attacker that barely refuses got 0/27
    against Haiku, but also 0/9 against the guarded 7B model, where the Haiku attacker got 5/9. Too weak to count.
11. **Splitting an attack across two fields, or writing it in Hindi or Hinglish, didn't get past the guards.**
    L1 flagged at least one half of every split attack, and Hindi and Hinglish attacks more often than English.
12. **Invisible text slips past the classifier, but no model obeyed it.** L1 missed 23 of 27 attacks hidden in
    Unicode tag characters. Qwen can't read them; Haiku can, and refused all 54.
13. **Retraining the guard on what beat it worked, within limits.** Fine-tuned on other runs' attacks plus
    realistic clean text, L1 caught all 10 winning payloads it had never seen (before: 0), false alarms on clean
    text fell from 13% to 3%, and the adaptive attacker went from 10/27 to 0/27. It learned this attacker's
    style; removing the secret from the prompt is the fix that doesn't depend on that.

The reasoning behind every decision, as study questions ("why this, why not that, what will an interviewer
ask?"), is in **[docs/why.md](docs/why.md)**.

## Quick start

```bash
# 1. pipeline check, nothing to install (the simulator only tests plumbing; its numbers are never reported)
python3 scripts/run_campaign.py && for t in tests/test_*.py; do python3 "$t"; done

# 2. real models
uv sync
uv pip install torch transformers presidio-analyzer \
  https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
ollama pull qwen2.5:7b && ollama serve
.venv/bin/python scripts/run_benign.py                     # false alarms + useful answers
.venv/bin/python scripts/run_campaign.py --live            # bank agent on Qwen (free); --scenario healthcare|email

echo 'ANTHROPIC_API_KEY=...' > .env && set -a && . ./.env && set +a
.venv/bin/python scripts/run_campaign.py --live --model claude-haiku-5-5   # ≈ $0.18 per scenario

# 3. watch it
sh scripts/serve_board.sh        # → http://127.0.0.1:8766/leaderboard.html?live
```

<details>
<summary><b>Where the attacks come from</b></summary>

Reimplemented from published templates (`packages/redcell-attackers/src/redcell_attackers/specs.py`). These are
not the official attack suites; the official AgentDojo banking suite is run separately
([results](docs/results.md#4-outside-check-the-official-agentdojo-benchmark)).

| Style | Source |
|:--|:--|
| "This is an important message from me… before you can solve the task…" | AgentDojo (Debenedetti et al., NeurIPS 2024) |
| "IMPORTANT!!! Ignore all previous instructions…" | InjecAgent (Zhan et al., ACL Findings 2024) |
| "Ignore the previous instructions and instead…" | Perez & Ribeiro 2022, *Ignore Previous Prompt* |
| Fake conversation turn | Liu et al., USENIX Security 2024 (fake completion) |
| Combined attack: fake completion + escape characters + "ignore previous" | Liu et al., USENIX Security 2024 |
| Refusal suppression, prefix injection, base64 | Wei et al., NeurIPS 2023, *Jailbroken* |
| Role-play ("DevMode") | Shen et al., CCS 2024, *Do Anything Now* |
| Fake system notice, note-to-assistant, authority claim | common real-world patterns |

Goals map to the OWASP Top 10 for LLM apps (2025). Qwen with no defenses (bank · clinic · inbox): LLM01 prompt
injection 95 · 95 · 38% · LLM02 data disclosure 86% in all three · LLM05 unsafe output 100% in all three ·
LLM06 excessive agency 67 · 43 · 38% · LLM07 system-prompt leakage 86 · 71 · 86% (n = 7 to 21 each).
</details>

<details>
<summary><b>How results are measured</b></summary>

- **Undefended:** each attack is retried with up to 4 mutations until one works.
- **Defended, frozen replay:** the attacks that worked are replayed unchanged against the defended agent, to isolate the defenses' effect.
- **Defended, mutation retry:** every attack is retried against the defenses with the same four mutations.
- **Adaptive attacker:** an attacker model (Claude Haiku 5.5) rewrites its attack after each reply, for up to 6
  rounds, knowing which defenses are on but never seeing the secrets. Frozen replay alone overstates safety.
- **Repeats:** the Qwen bank campaign was run four times to show the spread (81.0–85.7%).
- **Each layer on its own:** shows what every guard contributes.
- **Benign control:** 6 normal questions, without and with all guards. Reports false breaches, questions blocked,
  and whether answers still contain the facts the tools returned. Clean tool fields are scored separately: L1
  flagged 1 of 36 (an email subject), which the benign check alone would have missed.
- **Wilson 95% confidence intervals** on every rate. **Cost** comes from the token counts the API returns.
- **Guard latency** (M3 Pro, CPU): L1 p50 33 ms idle; p50 45–58 ms / p99 142–297 ms during full campaigns, while
  the local model shares the CPU.
</details>

<details>
<summary><b>Honest limitations</b></summary>

- **Three synthetic agents**, one open 7B model and one API model; 63 attacks per agent, reimplemented from
  published templates.
- **Small samples.** That's why every rate carries its confidence interval. Only the Qwen bank campaign was repeated.
- **Adaptive results are lower bounds** where the attacker model refused (about half its goals against Haiku);
  a local attacker that doesn't refuse was too weak to replace it.
- **The retrained guard** was tested against the same attacker model whose other runs it was trained on.
- **CI gate:** `scripts/run_gate.py` runs on the simulator, so it protects the pipeline logic, not a real model's behaviour.
- **Not part of any reported number:** the LLM-judge agreement study (`redcell-eval`), the LangGraph version of
  the loop (`coordinator.py`) and the scope gate in [SCOPE.md](SCOPE.md).
</details>

<details>
<summary><b>How it relates to garak, PyRIT and promptfoo</b></summary>

Those are broad red-teaming tools, and the right choice for scanning an app for many kinds of vulnerability.
RedCell answers a narrower question: **does a given guardrail reduce attack success, at what cost in false alarms,
useful answers and latency, and does it still hold when the attacker adapts?** Breaches are decided by code from
what the MCP server recorded.
</details>

## Scope and safety

RedCell attacks only the author's own agent and locally run instances, using synthetic data and planted fake
secrets. The "attacker" domain `rc-collect.invalid` can never resolve. See [SCOPE.md](SCOPE.md),
[ETHICS.md](ETHICS.md) and [DISCLOSURE.md](DISCLOSURE.md).

## Repo map

```
packages/redcell-target/      the agent, MCP server, guardrails (guards.py), simulator
packages/redcell-attackers/   attack catalog, mutation loop, campaign phases, scorecard
packages/redcell-verifiers/   the breach checks (plain code)
packages/redcell-core/        shared types, planted secrets, model prices
scripts/                      run_campaign · run_benign · run_adaptive · run_repeats · run_agentdojo ·
                              compare_classifiers · run_variants · gen_clean_text · train_l1 ·
                              build_leaderboard · serve_board · run_gate
apps/dashboard/               Next.js dashboard, built from the result files in dashboard/
docs/results.md               the full write-up of every measured result
docs/why.md                   every design decision, as study questions
decision.md · flow.md         decision diagrams and the work log
```
