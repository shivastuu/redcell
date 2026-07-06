import scorecard from "../data/scorecard.json";
import evalData from "../data/eval.json";

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

type CI = { asr: number; lo: number; hi: number; n: number };
const a = scorecard.asr as { baseline: CI; defended_frozen: CI; defended_adaptive: CI };

function Bar({ frac, cls }: { frac: number; cls: string }) {
  return <span className={`bar ${cls}`} style={{ width: `${Math.max(frac, 0) * 100}%` }} />;
}

function Kpi({ v, cls, k, ci }: { v: string; cls: string; k: string; ci: string }) {
  return (
    <div className="kpi">
      <div className={`v ${cls}`}>{v}</div>
      <div className="k">{k}</div>
      <div className="ci">{ci}</div>
    </div>
  );
}

export default function Page() {
  return (
    <main className="wrap">
      <h1><span className="dot" />RedCell — Attack Leaderboard</h1>
      <p className="sub">Adversarial robustness of a fintech agent, before vs after the layered defense.</p>
      <p className="tags">
        target: {scorecard.target} &nbsp;·&nbsp; corpus: {scorecard.corpus_version} &nbsp;·&nbsp;
        n={a.baseline.n} goals &nbsp;·&nbsp; deterministic verifier (no LLM in the reward path)
      </p>

      <div className="hero">
        <Kpi v={pct(a.baseline.asr)} cls="red" k="baseline · undefended"
             ci={`95% CI [${pct(a.baseline.lo)}, ${pct(a.baseline.hi)}]`} />
        <Kpi v={pct(a.defended_frozen.asr)} cls="teal" k="defended · frozen replay"
             ci={`95% CI [${pct(a.defended_frozen.lo)}, ${pct(a.defended_frozen.hi)}]`} />
        <Kpi v={pct(a.defended_adaptive.asr)} cls="amber" k="defended · ADAPTIVE"
             ci={`the honest number · [${pct(a.defended_adaptive.lo)}, ${pct(a.defended_adaptive.hi)}]`} />
      </div>

      <h2>Per-OWASP category</h2>
      <p className="legend"><span className="bar red" style={{ width: 11 }} /> baseline &nbsp;
        <span className="bar teal" style={{ width: 11 }} /> defended</p>
      <table><tbody>
        {scorecard.owasp.map((o: any) => (
          <tr key={o.category}>
            <td className="cat">{o.category}</td>
            <td className="tnum r">{pct(o.baseline)}</td>
            <td className="track"><Bar frac={o.baseline} cls="red" /><Bar frac={o.defended} cls="teal" /></td>
            <td className="tnum t">{pct(o.defended)}</td>
          </tr>
        ))}
      </tbody></table>

      <h2>Per-layer attribution (add-one-in)</h2>
      <table><tbody>
        {scorecard.layers.map((l: any) => (
          <tr key={l.name}>
            <td>{l.name}</td>
            <td className="track"><Bar frac={l.kills} cls="teal" /></td>
            <td className="tnum t">kills {pct(l.kills)}</td>
          </tr>
        ))}
      </tbody></table>

      <h2>Judge quality (LLM-judge vs deterministic verifier)</h2>
      <p className="mono" style={{ color: "var(--muted)" }}>
        Cohen&apos;s κ {(evalData as any).kappa.toFixed(3)} ({(evalData as any).band}) &nbsp;·&nbsp;
        judge precision {(evalData as any).precision.toFixed(2)} &nbsp;·&nbsp;
        recall {(evalData as any).recall.toFixed(2)} &nbsp;·&nbsp;
        misses {(evalData as any).fn} encoded-exfil cases the verifier catches
      </p>

      <h2>Cost — heterogeneous routing</h2>
      <p className="mono" style={{ color: "var(--muted)" }}>
        all-frontier ${scorecard.cost.all_frontier_usd} → routed ${scorecard.cost.routed_usd} &nbsp;·&nbsp;
        mutation cost cut ~{scorecard.cost.mutation_cost_cut_pct}% &nbsp;·&nbsp;
        {scorecard.cost.attacks_per_usd} attacks/$
      </p>

      <div className="note">
        <b>Read the adaptive number.</b> The frozen replay is the headline; the adaptive result is the truth.
        Structural controls (spotlight, tool allowlist, schema) hold under adaptive pressure; probabilistic
        content filters (input classifier, PII redaction) fall to encoding+obfuscation — which is why you report both.
      </div>
      <p className="foot">Reads dashboard/scorecard.json (run `npm run sync`). Every verdict is a deterministic
        function of a server-recorded trace.</p>
    </main>
  );
}
