#!/usr/bin/env python3
"""Render the scorecards -> dashboard/leaderboard.html (self-contained, no deps).

    python3 scripts/build_leaderboard.py && open dashboard/leaderboard.html

Reads every real-model run in dashboard/scorecards/*.json (one file per target,
written by `run_campaign.py --live`) and ranks them, most vulnerable first. With no
real runs yet it falls back to dashboard/scorecard.json (e.g. the simulator in CI).
"""
import glob
import html
import json
import os
import time

esc = html.escape   # attacker text and model replies are DATA: never render them as markup

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(ROOT, "dashboard")


def slug(target: str) -> str:
    """live:qwen2.5:7b -> live_qwen2.5_7b (a safe file name)."""
    return target.replace(":", "_").replace("/", "_")


def pct(x):
    return f"{x * 100:.1f}%"


def bar(frac, cls):
    return f'<div class="bar {cls}" style="width:{max(frac,0)*100:.1f}%"></div>'


def cost_text(c):
    if "model_calls" not in c:
        return "not recorded (this run predates cost tracking)"
    usd = "unknown" if c["usd"] is None else f"${c['usd']}"
    return f'{c["model_calls"]} model calls &nbsp;·&nbsp; {c["input_tokens"]:,} input + {c["output_tokens"]:,} output tokens &nbsp;·&nbsp; {usd}'


def progress_panel():
    """Runs still going (dashboard/progress/*.json). Partial, so labelled loudly."""
    items, events = [], []
    for p in sorted(glob.glob(os.path.join(DASH, "progress", "*.json"))):
        with open(p) as f:
            s = json.load(f)
        events += [{**e, "target": s["target"]} for e in s.get("feed", [])]
        idle = time.time() - s["updated"]
        stalled = f" &nbsp;·&nbsp; <b>no update for {int(idle // 60)} min, the run probably stopped</b>" if idle > 300 else ""
        usd = "unknown" if s["usd"] is None else f"${s['usd']}"
        items.append(
            f'<p class="mono">{s["target"]} &nbsp;·&nbsp; phase {s["phase_no"]}/{s["phases"]}: {s["phase"]}'
            f' &nbsp;·&nbsp; attack {s["attack"]}/{s["attacks"]} &nbsp;·&nbsp; {s["model_calls"]} model calls'
            f' &nbsp;·&nbsp; {usd} so far &nbsp;·&nbsp; {int((time.time() - s["started"]) // 60)} min{stalled}</p>')
    if not items:
        return ""
    feed = "".join(feed_event(e) for e in sorted(events, key=lambda e: e["t"], reverse=True)[:25])
    return ('<div class="note run"><b>Run in progress: partial, not a result.</b> '
            "Its numbers appear below only once every phase has finished." + "".join(items) + "</div>"
            + (f'<h2>Live attack feed</h2><div class="feed">{feed}</div>' if feed else ""))


def feed_event(e):
    verdict = (f'<span class="badge b">BREACH · {esc(", ".join(e["detectors"]))}</span>' if e["breach"]
               else '<span class="badge h">held</span>')
    tools = ", ".join(n + ("" if ok else " (blocked)") for n, ok in e["tools"]) or "no tool calls"
    ops = f' &nbsp;·&nbsp; mutations: {esc("+".join(e["ops"]))}' if e["ops"] else ""
    one_line = lambda s: esc(" ".join(s.split()))   # noqa: E731
    return (f'<div class="ev"><div class="evh mono">{time.strftime("%H:%M:%S", time.localtime(e["t"]))} '
            f'&nbsp;{verdict}&nbsp; {esc(e["target"])} &nbsp;·&nbsp; {esc(e["attack"])} &nbsp;·&nbsp; '
            f'defense: {esc(e["defense"])}{ops}</div>'
            f'<div class="evb"><span class="lbl">attack</span>{one_line(e["payload"])}</div>'
            f'<div class="evb"><span class="lbl">tools</span>{esc(tools)}</div>'
            f'<div class="evb"><span class="lbl">reply</span>{one_line(e["answer"])}</div></div>')


def useful_text(b):
    return f'{b["defended"]["useful"]}/{b["defended"]["checkable"]}' if b else "-"


def summary(cards):
    rows = "".join(
        f'<tr><td class="cat">{d["target"]}</td><td class="tnum">{d["asr"]["baseline"]["n"]}</td>'
        f'<td class="tnum r">{pct(d["asr"]["baseline"]["asr"])}</td>'
        f'<td class="tnum t">{pct(d["asr"]["defended_frozen"]["asr"])}</td>'
        f'<td class="tnum a">{pct(d["asr"]["defended_adaptive"]["asr"])}</td>'
        f'<td class="tnum">{useful_text(d.get("benign"))}</td>'
        f'<td class="tnum">{"-" if "usd" not in d["cost"] or d["cost"]["usd"] is None else "$" + str(d["cost"]["usd"])}</td></tr>'
        for d in cards) or '<tr><td colspan="7">no finished runs yet</td></tr>'
    return (f'<table><tr><th class="l">target</th><th>attacks</th><th>undefended</th>'
            f'<th>defended · frozen</th><th>defended · adaptive</th><th>useful answers · defended</th><th>cost</th></tr>{rows}</table>')


def benign_block(b):
    """Normal questions, no attack: false breaches, L1 false alarms, useful answers, guard latency."""
    if not b:
        return ""
    o, d = b["baseline"], b["defended"]
    lat = "".join(f'<tr><td>{esc(k)}</td><td class="tnum" colspan="2">p50 {v["p50"]} ms &nbsp;·&nbsp; p99 {v["p99"]} ms (n={v["n"]})</td></tr>'
                  for k, v in b.get("guard_latency_ms", {}).items())
    return f"""
<h3>Benign control ({o["n"]} normal questions, no attack)</h3>
<table><tr><th class="l"></th><th>no defenses</th><th>all defenses</th></tr>
<tr><td>false breaches</td><td class="tnum">{o["breaches"]}/{o["n"]}</td><td class="tnum">{d["breaches"]}/{d["n"]}</td></tr>
<tr><td>blocked by L1 (false alarm)</td><td class="tnum">-</td><td class="tnum">{d["blocked"]}/{d["n"]}</td></tr>
<tr><td>useful answers (facts present)</td><td class="tnum">{o["useful"]}/{o["checkable"]}</td><td class="tnum">{d["useful"]}/{d["checkable"]}</td></tr>
{lat}</table>"""


def section(data):
    a = data["asr"]
    owasp_rows = "".join(
        f'<tr><td class="cat">{o["category"]}</td>'
        f'<td class="tnum r">{pct(o["baseline"])}</td>'
        f'<td class="track">{bar(o["baseline"],"red")}{bar(o["defended"],"teal")}</td>'
        f'<td class="tnum t">{pct(o["defended"])}</td></tr>'
        for o in data["owasp"])
    layer_rows = "".join(
        f'<tr><td>{layer["name"]}</td><td class="track">{bar(layer["kills"],"teal")}</td>'
        f'<td class="tnum t">kills {pct(layer["kills"])}</td></tr>'
        for layer in data["layers"])
    return f"""
<h2 class="tname">{data["target"]}</h2>
<p class="tags mono">corpus: {data["corpus_version"]} &nbsp;·&nbsp; n={a["baseline"]["n"]} attacks &nbsp;·&nbsp; deterministic verifier (no LLM in the reward path)</p>
<div class="hero">
  <div class="kpi"><div class="v red">{pct(a["baseline"]["asr"])}</div><div class="k">undefended</div>
    <div class="ci">95% CI [{pct(a["baseline"]["lo"])}, {pct(a["baseline"]["hi"])}]</div></div>
  <div class="kpi"><div class="v teal">{pct(a["defended_frozen"]["asr"])}</div><div class="k">defended · frozen replay</div>
    <div class="ci">95% CI [{pct(a["defended_frozen"]["lo"])}, {pct(a["defended_frozen"]["hi"])}]</div></div>
  <div class="kpi"><div class="v amber">{pct(a["defended_adaptive"]["asr"])}</div><div class="k">defended · adaptive</div>
    <div class="ci">95% CI [{pct(a["defended_adaptive"]["lo"])}, {pct(a["defended_adaptive"]["hi"])}]</div></div>
</div>
<h3>Per-OWASP category</h3>
<div class="legend mono"><b class="r">■</b> undefended &nbsp; <b class="t">■</b> defended</div>
<table>{owasp_rows}</table>
<h3>Per-layer attribution (each layer on its own)</h3>
<table>{layer_rows}</table>
<h3>Cost — token counts reported by the model API</h3>
<p class="mono" style="color:var(--muted)">{cost_text(data["cost"])}</p>{benign_block(data.get("benign"))}"""


def build(cards):
    sections = "".join(section(d) for d in cards)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RedCell Leaderboard</title>
<script>
// ?live: re-fetch this page every 2s and swap the content in place (no flicker, scroll kept).
// Needs the page served over http (scripts/serve_board.sh, port 8766); opened from disk it reloads instead.
if (new URLSearchParams(location.search).has("live")) setInterval(async () => {{
  try {{
    const r = await fetch(location.pathname + "?t=" + Date.now(), {{ cache: "no-store" }});
    const doc = new DOMParser().parseFromString(await r.text(), "text/html");
    document.querySelector(".wrap").innerHTML = doc.querySelector(".wrap").innerHTML;
  }} catch (e) {{ location.reload(); }}
}}, 2000);
</script>
<style>
:root{{--ink:#f3f5f8;--panel:#fff;--line:#dbe1e9;--text:#111823;--muted:#566274;
--red:#d23a41;--teal:#0a8f79;--amber:#8f6410;--rf:rgba(210,58,65,.1);--tf:rgba(10,143,121,.1)}}
@media(prefers-color-scheme:dark){{:root{{--ink:#0b0f16;--panel:#131a24;--line:#28323f;--text:#e7edf4;
--muted:#93a1b3;--red:#f0555b;--teal:#22a88f;--amber:#e0a83a;--rf:rgba(240,85,91,.14);--tf:rgba(34,168,143,.14)}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--ink);color:var(--text);
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:32px 16px 64px}}
.mono{{font-family:ui-monospace,"SF Mono",Menlo,monospace}}
h1{{font-family:ui-monospace,Menlo,monospace;font-size:30px;margin:0;letter-spacing:-.01em}}
.dot{{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--red);
box-shadow:0 0 0 4px var(--rf);margin-right:9px;vertical-align:middle}}
.sub{{color:var(--muted);margin:6px 0 0}}
.tags{{margin-top:6px;font-family:ui-monospace,monospace;font-size:12px;color:var(--muted)}}
.hero{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
.kpi{{flex:1;min-width:150px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}
.kpi .v{{font-family:ui-monospace,monospace;font-size:34px;font-weight:700;font-variant-numeric:tabular-nums}}
.kpi .k{{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-top:4px}}
.kpi .ci{{font-family:ui-monospace,monospace;font-size:11px;color:var(--muted);margin-top:6px}}
.v.red{{color:var(--red)}}.v.teal{{color:var(--teal)}}.v.amber{{color:var(--amber)}}
h2,h3{{font-family:ui-monospace,monospace;color:var(--muted)}}
h2{{font-size:15px;letter-spacing:.04em;text-transform:uppercase;margin:34px 0 12px}}
h2.tname{{font-size:20px;color:var(--text);text-transform:none;letter-spacing:0;margin-top:48px;
padding-top:20px;border-top:1px solid var(--line)}}
h3{{font-size:13px;letter-spacing:.04em;text-transform:uppercase;margin:26px 0 10px}}
.scroll{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse}}
th{{font:600 11px ui-monospace,monospace;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
text-align:right;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}}th.l{{text-align:left}}
td{{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:middle;font-size:14px}}
.cat{{font-family:ui-monospace,monospace;font-weight:600}}
.track{{width:46%}}.bar{{height:11px;border-radius:6px;display:inline-block;vertical-align:middle}}
.bar.red{{background:var(--red);margin-right:3px}}.bar.teal{{background:var(--teal)}}
.tnum{{font-family:ui-monospace,monospace;font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}}
.tnum.r{{color:var(--red)}}.tnum.t{{color:var(--teal)}}.tnum.a{{color:var(--amber)}}
.legend{{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted);margin-bottom:8px}}
.legend b.r{{color:var(--red)}}.legend b.t{{color:var(--teal)}}
.note{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--amber);
border-radius:0 12px 12px 0;padding:14px 16px;margin-top:22px;font-size:14px;color:var(--muted)}}
.note.run{{border-left-color:var(--red)}}.note.run p{{margin:8px 0 0;font-size:13px;color:var(--text)}}
.feed{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:4px 14px}}
.ev{{padding:10px 0;border-bottom:1px solid var(--line)}}.ev:last-child{{border-bottom:0}}
.evh{{font-size:12px;color:var(--text);overflow-wrap:anywhere}}
.evb{{font-size:13px;color:var(--muted);margin-top:3px;overflow-wrap:anywhere}}
.lbl{{font:600 10px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.06em;margin-right:8px;color:var(--muted)}}
.badge{{display:inline-block;padding:1px 8px;border-radius:9px;font:700 11px ui-monospace,monospace}}
.badge.b{{background:var(--rf);color:var(--red)}}.badge.h{{background:var(--tf);color:var(--teal)}}
.foot{{margin-top:24px;color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}}
</style></head><body><div class="wrap">
<h1><span class="dot"></span>RedCell Leaderboard</h1>
<p class="sub">Attack success against a fintech agent behind an MCP server, by target model. Most vulnerable first.</p>
{progress_panel()}
<h2>All targets</h2>
<div class="scroll">{summary(cards)}</div>
<div class="note"><b>How to read this.</b> <i>Frozen</i> replays the attacks that worked, unchanged, against the
defended agent. <i>Adaptive</i> lets the mutation loop search again against it. Report both: frozen alone
overstates how safe the agent is. Here "adaptive" means retrying four fixed mutations against the defenses; it is
not an attacker model that rewrites its attacks, which is the stronger test. Small n means wide confidence intervals.</div>
{sections}
<p class="foot">Generated from dashboard/scorecards/*.json · every verdict is a deterministic function of a server-recorded trace.</p>
</div></body></html>"""


def main(quiet: bool = False):
    paths = sorted(glob.glob(os.path.join(DASH, "scorecards", "*.json")))
    if not paths:                                    # no real runs yet: show the simulator, if any
        paths = [p for p in [os.path.join(DASH, "scorecard.json")] if os.path.exists(p)]
    cards = []
    for p in paths:
        with open(p) as f:
            cards.append(json.load(f))
    for d in cards:
        bp = os.path.join(DASH, "benign", slug(d["target"]) + ".json")
        if os.path.exists(bp):
            with open(bp) as f:
                d["benign"] = json.load(f)
    cards.sort(key=lambda d: d["asr"]["baseline"]["asr"], reverse=True)
    out = os.path.join(DASH, "leaderboard.html")
    tmp = f"{out}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(build(cards))
    os.replace(tmp, out)            # atomic: the live page never fetches a half-written file
    if not quiet:
        print(f"wrote {out}  ({len(cards)} target{'s' if len(cards) != 1 else ''})")


if __name__ == "__main__":
    main()
