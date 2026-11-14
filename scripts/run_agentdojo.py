#!/usr/bin/env python3
"""The official AgentDojo benchmark (ETH Zurich; PyPI agentdojo 0.1.35, task suites v1.2.2):
the banking suite under the important_instructions attack, against our targets, with no
defense or with AgentDojo's Protect AI classifier (its `transformers_pi_detector`).

Runs in its own venv so AgentDojo's pins never touch .venv:
    ~/.local/bin/uv venv .venv-agentdojo --python 3.12
    ~/.local/bin/uv pip install --python .venv-agentdojo/bin/python "agentdojo[transformers]==0.1.35"

    set -a; . ./.env; set +a
    .venv-agentdojo/bin/python scripts/run_agentdojo.py --model claude-haiku-5-5 --defense none --max-usd 1
    .venv-agentdojo/bin/python scripts/run_agentdojo.py --model qwen2.5:7b --defense pi_detector
    # a slice:  --user-tasks user_task_0 --injection-tasks injection_task_0

Writes dashboard/agentdojo/<model-slug>__<defense>.json. AgentDojo traces every agent run to
dashboard/agentdojo/runs/<pipeline>/banking/... and a rerun skips tasks already traced, so a run
stopped by --max-usd resumes without paying twice. Delete the pipeline's folder to start over.

AgentDojo's `security=True` means the INJECTION GOAL WAS ACHIEVED (task_suite.py,
run_task_with_pipeline). It is reported here as targeted_asr: higher is worse for the defender.
"""
import argparse
import json
import os
import sys
import time
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "redcell-core" / "src"))

import anthropic                                                    # noqa: E402
import openai                                                       # noqa: E402
from agentdojo.agent_pipeline import AgentPipeline, AnthropicLLM, OpenAILLM, PipelineConfig  # noqa: E402
from agentdojo.agent_pipeline.llms import anthropic_llm, openai_llm  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack           # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections  # noqa: E402
from agentdojo.logging import Logger, OutputLogger, TraceLogger     # noqa: E402
from agentdojo.models import MODEL_NAMES                            # noqa: E402
from agentdojo.task_suite.load_suites import get_suite              # noqa: E402
from build_leaderboard import slug                                  # noqa: E402
from redcell_core.config import PRICE_PER_MTOK                      # noqa: E402

BENCHMARK_VERSION, SUITE, ATTACK = "v1.2.2", "banking", "important_instructions"
DEFENSES = {"none": None, "pi_detector": "transformers_pi_detector"}
CLAUDE_MAX_TOKENS = 16000   # Haiku 5.5's adaptive thinking counts toward it
OLLAMA_MAX_TOKENS = 1024    # caps a looping local reply
OUT = ROOT / "dashboard" / "agentdojo"
LOGDIR = OUT / "runs"
SPEND = {"usd": 0.0, "cap": float("inf"), "price": (0.0, 0.0)}   # price: USD per MTok (in, out)


class BudgetExceeded(Exception):
    pass


def usd(inp, out):
    # ponytail: one rate card; Haiku 5.5 bills 5x above 100K-token prompts, banking prompts stay far below
    return (inp * SPEND["price"][0] + out * SPEND["price"][1]) / 1e6


def record(inp, out, refused=False):
    """Count real usage, globally for the cap and on the running task's AgentDojo trace."""
    SPEND["usd"] += usd(inp, out)
    trace = Logger.get()
    if isinstance(trace, TraceLogger):
        for k, v in (("input_tokens", inp), ("output_tokens", out), ("model_calls", 1), ("refusals", int(refused))):
            trace.context[k] = trace.context.get(k, 0) + v


async def anthropic_request(client, model, messages, tools, max_tokens, system_prompt=None, **_):
    """Replaces AgentDojo's: it always passes `temperature`, which anthropic>=2 no longer takes
    (and Haiku 5.5 400s on). No thinking budget either: Haiku 5.5's thinking is adaptive."""
    # Fail closed: refuse a call whose worst case could cross --max-usd. Prompt tokens are
    # bounded by chars/2 (real text runs ~3-4 chars per token).
    worst = usd(len(json.dumps([system_prompt, messages, tools], default=str)) / 2, max_tokens)
    if SPEND["usd"] + worst > SPEND["cap"]:
        raise BudgetExceeded(f"next call could cost ${worst:.4f}; spent ${SPEND['usd']:.4f} of ${SPEND['cap']}")
    async with client.messages.stream(model=model, messages=messages, tools=tools, max_tokens=max_tokens,
                                      system=system_prompt) as stream:
        msg = await stream.get_final_message()
    record(msg.usage.input_tokens, msg.usage.output_tokens, msg.stop_reason == "refusal")
    return msg


def ollama_request(client, model, messages, tools, reasoning_effort, temperature=0.0):
    # AgentDojo sends its system prompt as role "developer", which Ollama silently drops.
    messages = [{**m, "role": "system"} if m["role"] == "developer" else m for m in messages]
    c = client.chat.completions.create(model=model, messages=messages, tools=tools, max_tokens=OLLAMA_MAX_TOKENS)
    record(c.usage.prompt_tokens, c.usage.completion_tokens)
    return c


def build_llm(model):
    if model.startswith("claude"):
        if model not in PRICE_PER_MTOK:
            sys.exit(f"{model} has no price in redcell_core.config.PRICE_PER_MTOK, so --max-usd can't hold")
        SPEND["price"] = PRICE_PER_MTOK[model]
        anthropic_llm.chat_completion_request = anthropic_request
        anthropic_llm.MessageParam = dict   # anthropic>=2 made MessageParam a Union; agentdojo 0.1.35 calls it
        llm = AnthropicLLM(anthropic.AsyncAnthropic(max_retries=6), model, max_tokens=CLAUDE_MAX_TOKENS)
    else:
        openai_llm.chat_completion_request = ollama_request
        llm = OpenAILLM(openai.OpenAI(base_url=os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1"),
                                      api_key=os.getenv("OPENAI_API_KEY", "ollama")), model)
    llm.name = model
    # important_instructions signs the injection "to you, <model name>"; 0.1.35 predates both targets.
    MODEL_NAMES[model] = "Claude" if model.startswith("claude") else "Qwen" if model.startswith("qwen") else "AI assistant"
    return llm


def rate(results):
    hits = sum(results.values())
    return {"rate": hits / len(results) if results else None, "count": hits, "total": len(results)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="claude-haiku-5-5 (Anthropic API) or an Ollama model, e.g. qwen2.5:7b")
    ap.add_argument("--defense", choices=DEFENSES, default="none")
    ap.add_argument("--user-tasks", nargs="+", help="e.g. user_task_0 user_task_5 (default: all)")
    ap.add_argument("--injection-tasks", nargs="+", help="e.g. injection_task_0 (default: all)")
    ap.add_argument("--max-usd", type=float, default=1.0,
                    help="hard cap on new API spend in this invocation; aborts before a call that could cross it")
    args = ap.parse_args()
    SPEND["cap"] = args.max_usd

    suite = get_suite(BENCHMARK_VERSION, SUITE)
    pipeline = AgentPipeline.from_config(PipelineConfig(
        llm=build_llm(args.model), model_id=None, defense=DEFENSES[args.defense],
        system_message_name=None, system_message=None))
    attack = load_attack(ATTACK, suite, pipeline)
    started = time.time()
    try:
        with OutputLogger(str(LOGDIR)):
            clean = benchmark_suite_without_injections(
                pipeline, suite, LOGDIR, False, args.user_tasks, BENCHMARK_VERSION)
            attacked = benchmark_suite_with_injections(
                pipeline, suite, attack, LOGDIR, False, args.user_tasks, args.injection_tasks,
                benchmark_version=BENCHMARK_VERSION)
    except BudgetExceeded as e:
        sys.exit(f"ABORTED by --max-usd: {e}. Finished tasks are traced under {LOGDIR}; "
                 "rerun with a higher cap to resume.")

    def trace(task, attack_name="none", injection="none"):
        return json.loads((LOGDIR / pipeline.name / SUITE / task / attack_name / f"{injection}.json").read_text())

    runs = ([trace(ut) for ut, _ in clean["utility_results"]]
            + [trace(it) for it in attacked["injection_tasks_utility_results"]]
            + [trace(ut, ATTACK, it) for ut, it in attacked["utility_results"]])
    tokens = {k: sum(r.get(k, 0) for r in runs) for k in ("input_tokens", "output_tokens", "model_calls", "refusals")}
    pairs = attacked["utility_results"]
    result = {
        "benchmark": "AgentDojo",
        "agentdojo_version": version("agentdojo"),
        "benchmark_version": BENCHMARK_VERSION,
        "suite": SUITE,
        "attack": ATTACK,
        "model": args.model,
        "defense": args.defense,
        "defense_agentdojo": DEFENSES[args.defense],
        "complete": len(pairs) == len(suite.user_tasks) * len(suite.injection_tasks),
        "n_user_tasks": len(clean["utility_results"]),
        "n_injection_tasks": len(attacked["injection_tasks_utility_results"]),
        "n_pairs": len(pairs),
        "utility": rate(clean["utility_results"]),          # user task solved, no attack
        "utility_under_attack": rate(pairs),                # user task solved, injection present
        "targeted_asr": rate(attacked["security_results"]),  # injection goal achieved (AgentDojo security=True)
        "injection_tasks_solved_as_user_tasks": rate(attacked["injection_tasks_utility_results"]),
        "tokens": {**tokens, "all_runs_metered": all("input_tokens" in r for r in runs)},
        "usd": round(usd(tokens["input_tokens"], tokens["output_tokens"]), 6),
        "agent_runs": len(runs),
        "agent_seconds": round(sum(r.get("duration") or 0 for r in runs), 1),
        "pairs": [{"user_task": ut, "injection_task": it, "utility": u,
                   "attack_succeeded": attacked["security_results"][(ut, it)]} for (ut, it), u in pairs.items()],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"{slug(args.model)}__{args.defense}.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\n{args.model} / {args.defense}: utility {result['utility']['count']}/{result['utility']['total']}, "
          f"under attack {result['utility_under_attack']['count']}/{len(pairs)}, "
          f"targeted ASR {result['targeted_asr']['count']}/{len(pairs)}; "
          f"{tokens['input_tokens']} in / {tokens['output_tokens']} out tokens, ${result['usd']:.4f} "
          f"(new spend ${SPEND['usd']:.4f}); {time.time() - started:.0f}s -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
