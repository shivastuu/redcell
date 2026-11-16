import { loadAll, type Card, type CI } from "../lib/data";

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const ci = (c: CI) => `95% CI ${pct(c.lo)}–${pct(c.hi)}`;
const usd = (v?: number | null) => (v === undefined || v === null ? "-" : `$${v}`);

function Bar({ frac, cls }: { frac: number; cls: string }) {
  return <span className={`bar ${cls}`} style={{ width: `${Math.max(frac, 0) * 100}%` }} />;
}

function Kpi({ v, cls, k, sub }: { v: string; cls: string; k: string; sub: string }) {
  return (
    <div className="kpi">
      <div className={`v ${cls}`}>{v}</div>
      <div className="k">{k}</div>
      <div className="ci">{sub}</div>
    </div>
  );
}

function Section({ c }: { c: Card }) {
  const a = c.asr;
  return (
    <section>
      <h2 className="tname">{c.target} · {c.scenario}</h2>
      <p className="tags">corpus {c.corpus_version} · n={a.baseline.n} attacks · breaches decided by code</p>
      <div className="hero">
        <Kpi v={pct(a.baseline.asr)} cls="red" k="undefended" sub={ci(a.baseline)} />
        <Kpi v={pct(a.defended_frozen.asr)} cls="teal" k="all guards · replay" sub={ci(a.defended_frozen)} />
        <Kpi v={a.defended_adaptive ? pct(a.defended_adaptive.asr) : "-"} cls="amber"
             k="all guards · mutation retry" sub={a.defended_adaptive ? ci(a.defended_adaptive) : "not run"} />
      </div>

      <h3>Per OWASP category</h3>
      <table><tbody>
        {c.owasp.map((o) => (
          <tr key={o.category}>
            <td className="cat">{o.category}</td>
            <td className="tnum r">{pct(o.baseline)}</td>
            <td className="track"><Bar frac={o.baseline} cls="red" /><Bar frac={o.defended} cls="teal" /></td>
            <td className="tnum t">{pct(o.defended)}</td>
          </tr>
        ))}
      </tbody></table>

      <h3>Each guard on its own: percentage points it cuts from the undefended rate</h3>
      <table><tbody>
        {c.layers.map((l) => (
          <tr key={l.name}>
            <td>{l.name}</td>
            <td className="track"><Bar frac={l.kills} cls="teal" /></td>
            <td className="tnum t">cuts {(l.kills * 100).toFixed(1)} pts</td>
          </tr>
        ))}
      </tbody></table>

      {c.benign && (
        <>
          <h3>Benign control ({c.benign.baseline.n} normal questions, no attack)</h3>
          <table><tbody>
            <tr><th className="l" /><th>no guards</th><th>all guards</th></tr>
            <tr><td>false breaches</td><td className="tnum">{c.benign.baseline.breaches}/{c.benign.baseline.n}</td>
              <td className="tnum">{c.benign.defended.breaches}/{c.benign.defended.n}</td></tr>
            <tr><td>blocked by L1 (false alarm)</td><td className="tnum">-</td>
              <td className="tnum">{c.benign.defended.blocked}/{c.benign.defended.n}</td></tr>
            <tr><td>useful answers</td><td className="tnum">{c.benign.baseline.useful}/{c.benign.baseline.checkable}</td>
              <td className="tnum">{c.benign.defended.useful}/{c.benign.defended.checkable}</td></tr>
          </tbody></table>
        </>
      )}
      <p className="tags">cost: {c.cost.model_calls ?? "-"} model calls · {usd(c.cost.usd)}</p>
    </section>
  );
}

export default function Page() {
  const { cards, adaptive, agentdojo, variants, retrain } = loadAll();
  const kn = (x?: { k: number; n: number; rate: number }) => (x ? `${x.k}/${x.n} (${pct(x.rate)})` : "-");
  return (
    <main className="wrap">
      <h1><span className="dot" />RedCell Leaderboard</h1>
      <p className="sub">Attacks against AI agents behind real MCP servers, by model and scenario. Most vulnerable first.</p>

      <h2>All targets</h2>
      <div className="scroll"><table><tbody>
        <tr><th className="l">target</th><th className="l">scenario</th><th>attacks</th><th>undefended</th>
          <th>goal met</th><th>all guards · replay</th><th>mutation retry</th><th>useful · guarded</th><th>cost</th></tr>
        {cards.map((c) => (
          <tr key={`${c.target}-${c.scenario}`}>
            <td className="cat">{c.target}</td><td>{c.scenario}</td>
            <td className="tnum">{c.asr.baseline.n}</td>
            <td className="tnum r">{pct(c.asr.baseline.asr)}
              {c.repeats && <span className="sub2"> · {c.repeats.repeats} runs {pct(c.repeats.min)}–{pct(c.repeats.max)}</span>}</td>
            <td className="tnum r">{c.asr.baseline_targeted ? pct(c.asr.baseline_targeted.asr) : "-"}</td>
            <td className="tnum t">{pct(c.asr.defended_frozen.asr)}</td>
            <td className="tnum a">{c.asr.defended_adaptive ? pct(c.asr.defended_adaptive.asr) : "-"}</td>
            <td className="tnum">{c.benign ? `${c.benign.defended.useful}/${c.benign.defended.checkable}` : "-"}</td>
            <td className="tnum">{usd(c.cost.usd)}</td>
          </tr>
        ))}
      </tbody></table></div>
      <div className="note"><b>How to read this.</b> &ldquo;Replay&rdquo; re-runs the attacks that worked, unchanged, with
        every guard on. &ldquo;Mutation retry&rdquo; retries four fixed mutations; it is not an attacker model.
        &ldquo;Goal met&rdquo; counts only breaches that achieved what the attacker asked for.</div>

      {adaptive.length > 0 && (
        <>
          <h2>Adaptive attacker</h2>
          <div className="note">An attacker model writes an attack, reads the agent&rsquo;s reply, and rewrites it,
            knowing which defenses are on (PAIR-style). It never sees the system prompt or the secrets.</div>
          <div className="scroll"><table><tbody>
            <tr><th className="l">target</th><th className="l">scenario</th><th className="l">defense</th>
              <th className="l">attacker</th><th>goals × rounds</th><th>breached</th><th>goal met</th>
              <th>attacker refused</th><th>cost</th></tr>
            {adaptive.map((r) => (
              <tr key={`${r.target}-${r.scenario}-${r.defense}-${r.attacker}`}>
                <td className="cat">{r.target}</td><td>{r.scenario}</td><td>{r.defense}</td><td>{r.attacker}</td>
                <td className="tnum">{r.goals} × {r.rounds}</td>
                <td className="tnum r">{r.breached}/{r.goals} ({pct(r.asr)})</td>
                <td className="tnum r">{r.targeted}</td><td className="tnum">{r.attacker_refusals}</td>
                <td className="tnum">{usd(r.cost.total_usd)}{r.complete ? "" : " · stopped early"}</td>
              </tr>
            ))}
          </tbody></table></div>
        </>
      )}

      {agentdojo.length > 0 && (
        <>
          <h2>Outside check: official AgentDojo benchmark</h2>
          <div className="note">AgentDojo (Debenedetti et al., NeurIPS 2024): banking suite, its own attack and its own
            Protect AI classifier defense. Not RedCell&rsquo;s attacks: an independent check of its findings.</div>
          <div className="scroll"><table><tbody>
            <tr><th className="l">model</th><th className="l">defense</th><th>utility, no attack</th>
              <th>utility under attack</th><th>attack succeeded</th><th>cost</th></tr>
            {agentdojo.map((r) => (
              <tr key={`${r.model}-${r.defense}`}>
                <td className="cat">{r.model}</td><td>{r.defense}</td>
                <td className="tnum">{r.utility.count}/{r.utility.total}</td>
                <td className="tnum">{r.utility_under_attack.count}/{r.utility_under_attack.total}</td>
                <td className="tnum r">{r.targeted_asr.count}/{r.targeted_asr.total} ({pct(r.targeted_asr.rate)})</td>
                <td className="tnum">{usd(r.usd ?? 0)}{r.complete === false ? " · partial" : ""}</td>
              </tr>
            ))}
          </tbody></table></div>
        </>
      )}

      {variants.length > 0 && (
        <>
          <h2>Trickier attacks, each next to its control</h2>
          <div className="note">split: the instruction cut across two fields of one record. hi / hinglish: the same goal
            in Hindi or Hinglish. invisible: hidden in Unicode tag characters. One shot each (scripts/run_variants.py).</div>
          <div className="scroll"><table><tbody>
            <tr><th className="l">target</th><th className="l">set</th><th className="l">variant</th>
              <th>breached, no guards</th><th>breached, all guards</th></tr>
            {variants.flatMap((r) =>
              [...new Set(Object.keys(r.summary).map((k) => k.split("/")[0]))].map((v) => (
                <tr key={`${r.target}-${r.set}-${v}`}>
                  <td className="cat">{r.target}</td><td>{r.set}</td><td>{v}</td>
                  <td className="tnum r">{kn(r.summary[`${v}/none`])}</td>
                  <td className="tnum t">{kn(r.summary[`${v}/full`])}{r.complete ? "" : " · partial"}</td>
                </tr>
              )))}
          </tbody></table></div>
        </>
      )}

      {retrain && (
        <>
          <h2>L1 retrained on the attacks that beat it</h2>
          <div className="note">Fine-tuned on other runs&rsquo; attacker payloads and generated clean text; every set
            below was held out of training (scripts/train_l1.py). Share flagged as an injection.</div>
          <div className="scroll"><table><tbody>
            <tr><th className="l">texts</th><th>L1 before</th><th>L1 retrained</th></tr>
            {Object.keys(retrain.before).map((k) => (
              <tr key={k}><td>{k}</td><td className="tnum">{kn(retrain.before[k])}</td>
                <td className="tnum">{kn(retrain.after[k])}</td></tr>
            ))}
          </tbody></table></div>
        </>
      )}

      {cards.map((c) => <Section key={`${c.target}-${c.scenario}`} c={c} />)}

      <p className="foot">Built from dashboard/*.json at build time. Every verdict is a deterministic function of what
        the MCP server recorded.</p>
    </main>
  );
}
