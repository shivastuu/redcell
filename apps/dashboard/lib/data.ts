// Reads the Python pipeline's result files at build time (static export: no server, no API).
// Every number on the page comes from ../../dashboard/*.json, written by the scripts in /scripts.
import fs from "node:fs";
import path from "node:path";

const DASH = path.join(process.cwd(), "..", "..", "dashboard");

export type CI = { asr: number; lo: number; hi: number; k: number; n: number };
export type Latency = Record<string, { p50: number; p99: number; n: number }>;

export type Scorecard = {
  target: string;
  scenario?: string;
  corpus_version: string;
  asr: { baseline: CI; baseline_targeted?: CI; defended_frozen: CI; defended_adaptive?: CI | null };
  owasp: { category: string; baseline: number; defended: number; n: number }[];
  layers: { name: string; asr: number; kills: number }[];
  cost: { model_calls?: number; input_tokens?: number; output_tokens?: number; usd?: number | null };
  guard_latency_ms?: Latency;
};

type BenignMode = { n: number; breaches: number; blocked: number; useful: number; checkable: number };
export type Benign = { baseline: BenignMode; defended: BenignMode; guard_latency_ms?: Latency };

export type Repeats = { repeats: number; mean: number; min: number; max: number };

export type Adaptive = {
  target: string; attacker: string; scenario: string; defense: string; rounds: number;
  complete: boolean; goals: number; breached: number; targeted: number; asr: number; lo: number; hi: number;
  attacker_refusals: number; cost: { total_usd: number };
};

type Rate = { rate: number; count: number; total: number };
export type AgentDojo = {
  model: string; defense: string; complete?: boolean; usd?: number | null;
  utility: Rate; utility_under_attack: Rate; targeted_asr: Rate;
};

export type Card = Scorecard & { scenario: string; benign?: Benign; repeats?: Repeats };

const slug = (t: string) => t.replaceAll(":", "_").replaceAll("/", "_");

function readJson<T>(file: string): T | undefined {
  return fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as T) : undefined;
}

function readAll<T>(folder: string): T[] {
  const dir = path.join(DASH, folder);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()
    .map((f) => readJson<T>(path.join(dir, f)) as T);
}

export function loadAll() {
  const cards: Card[] = readAll<Scorecard>("scorecards").map((s) => {
    const scenario = s.scenario ?? "fintech";
    const key = slug(`${s.target}__${scenario}`) + ".json";
    return {
      ...s, scenario,
      benign: readJson<Benign>(path.join(DASH, "benign", key)),
      repeats: readJson<Repeats>(path.join(DASH, "repeats", key)),
    };
  });
  cards.sort((a, b) => b.asr.baseline.asr - a.asr.baseline.asr);
  return { cards, adaptive: readAll<Adaptive>("adaptive"), agentdojo: readAll<AgentDojo>("agentdojo") };
}
