#!/usr/bin/env python3
"""Render dashboard/scorecard.json -> dashboard/leaderboard.html (self-contained).

    python3 scripts/run_campaign.py && python3 scripts/build_leaderboard.py

This is the offline, zero-dependency leaderboard. The Next.js version reads the
same scorecard.json and renders the same numbers with live Langfuse deep-links.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "dashboard")


def pct(x):
    return f"{x * 100:.1f}%"


def bar(frac, cls):
    return f'<div class="bar {cls}" style="width:{max(frac,0)*100:.1f}%"></div>'


def build(data):
    a = data["asr"]
    owasp_rows = "".join(
        f'<tr><td class="cat">{o["category"]}</td>'
        f'<td class="tnum r">{pct(o["baseline"])}</td>'
        f'<td class="track">{bar(o["baseline"],"red")}{bar(o["defended"],"teal")}</td>'
        f'<td class="tnum t">{pct(o["defended"])}</td></tr>'
        for o in data["owasp"])
    layer_rows = "".join(
        f'<tr><td>{l["name"]}</td><td class="track">{bar(l["kills"],"teal")}</td>'
        f'<td class="tnum t">kills {pct(l["kills"])}</td></tr>'
        for l in data["layers"])
    c = data["cost"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RedCell — Leaderboard</title><style>
:root{{--ink:#f3f5f8;--panel:#fff;--line:#dbe1e9;--text:#111823;--muted:#566274;
--red:#d23a41;--teal:#0a8f79;--amber:#8f6410;--rf:rgba(210,58,65,.1);--tf:rgba(10,143,121,.1)}}
@media(prefers-color-scheme:dark){{:root{{--ink:#0b0f16;--panel:#131a24;--line:#28323f;--text:#e7edf4;
--muted:#93a1b3;--red:#f0555b;--teal:#22a88f;--amber:#e0a83a;--rf:rgba(240,85,91,.14);--tf:rgba(34,168,143,.14)}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--ink);color:var(--text);
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:32px 22px 64px}}
.mono{{font-family:ui-monospace,"SF Mono",Menlo,monospace}}
h1{{font-family:ui-monospace,Menlo,monospace;font-size:30px;margin:0;letter-spacing:-.01em}}
.dot{{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--red);
box-shadow:0 0 0 4px var(--rf);margin-right:9px;vertical-align:middle}}
.sub{{color:var(--muted);margin:6px 0 0}}
.tags{{margin-top:10px;font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}}
.hero{{display:flex;gap:14px;flex-wrap:wrap;margin:26px 0}}
.kpi{{flex:1;min-width:150px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.kpi .v{{font-family:ui-monospace,monospace;font-size:34px;font-weight:700;font-variant-numeric:tabular-nums}}
.kpi .k{{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-top:4px}}
.kpi .ci{{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted);margin-top:6px}}
.v.red{{color:var(--red)}}.v.teal{{color:var(--teal)}}.v.amber{{color:var(--amber)}}
h2{{font-size:15px;font-family:ui-monospace,monospace;letter-spacing:.04em;text-transform:uppercase;
color:var(--muted);margin:34px 0 12px}}
table{{width:100%;border-collapse:collapse}}
td{{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:middle;font-size:14px}}
.cat{{font-family:ui-monospace,monospace;font-weight:600}}
.track{{width:46%}}.bar{{height:11px;border-radius:6px;display:inline-block;vertical-align:middle}}
.bar.red{{background:var(--red);margin-right:3px}}.bar.teal{{background:var(--teal)}}
.tnum{{font-family:ui-monospace,monospace;font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}}
.tnum.r{{color:var(--red)}}.tnum.t{{color:var(--teal)}}
.legend{{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted);margin-bottom:8px}}
.legend b.r{{color:var(--red)}}.legend b.t{{color:var(--teal)}}
.note{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--amber);
border-radius:0 12px 12px 0;padding:14px 16px;margin-top:28px;font-size:14px;color:var(--muted)}}
.foot{{margin-top:24px;color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}}
</style></head><body><div class="wrap">
<h1><span class="dot"></span>RedCell — Attack Leaderboard</h1>
<p class="sub">Adversarial robustness of a fintech agent, before vs after the layered defense.</p>
<p class="tags mono">target: {data["target"]} &nbsp;·&nbsp; corpus: {data["corpus_version"]} &nbsp;·&nbsp; n={a["baseline"]["n"]} goals &nbsp;·&nbsp; deterministic verifier (no LLM in the reward path)</p>

<div class="hero">
  <div class="kpi"><div class="v red">{pct(a["baseline"]["asr"])}</div><div class="k">baseline · undefended</div>
    <div class="ci">95% CI [{pct(a["baseline"]["lo"])}, {pct(a["baseline"]["hi"])}]</div></div>
  <div class="kpi"><div class="v teal">{pct(a["defended_frozen"]["asr"])}</div><div class="k">defended · frozen replay</div>
    <div class="ci">95% CI [{pct(a["defended_frozen"]["lo"])}, {pct(a["defended_frozen"]["hi"])}]</div></div>
  <div class="kpi"><div class="v amber">{pct(a["defended_adaptive"]["asr"])}</div><div class="k">defended · ADAPTIVE</div>
    <div class="ci">the honest number · 95% CI [{pct(a["defended_adaptive"]["lo"])}, {pct(a["defended_adaptive"]["hi"])}]</div></div>
</div>

<h2>Per-OWASP category</h2>
<div class="legend mono"><b class="r">■</b> baseline &nbsp; <b class="t">■</b> defended</div>
<table>{owasp_rows}</table>

<h2>Per-layer attribution (add-one-in)</h2>
<table>{layer_rows}</table>

<h2>Cost — heterogeneous routing</h2>
<p class="mono" style="color:var(--muted)">all-frontier ${c["all_frontier_usd"]} &nbsp;→&nbsp; routed ${c["routed_usd"]} &nbsp;·&nbsp;
mutation cost cut ~{c["mutation_cost_cut_pct"]}% &nbsp;·&nbsp; {c["attacks_per_usd"]} attacks/$</p>

<div class="note"><b>Read the adaptive number.</b> The frozen replay is the headline; the adaptive result is the truth.
Structural controls (spotlight, tool allowlist, schema validation) hold under adaptive pressure; probabilistic
content filters (input classifier, PII redaction) fall to encoding+obfuscation — which is why you report both.</div>
<p class="foot">Generated from dashboard/scorecard.json · every verdict is a deterministic function of a server-recorded trace.</p>
</div></body></html>"""


def main():
    src = os.path.join(DASH, "scorecard.json")
    if not os.path.exists(src):
        raise SystemExit("no scorecard.json — run `python3 scripts/run_campaign.py` first.")
    with open(src) as f:
        data = json.load(f)
    out = os.path.join(DASH, "leaderboard.html")
    with open(out, "w") as f:
        f.write(build(data))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
