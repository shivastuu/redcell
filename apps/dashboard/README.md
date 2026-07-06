# RedCell Dashboard (Next.js)

The shareable web leaderboard. Reads `data/scorecard.json` + `data/eval.json`
(produced by the Python campaign) and renders the ASR collapse, per-OWASP, per-layer,
judge-κ, and cost — the same numbers as the offline `dashboard/leaderboard.html`.

```bash
# from the repo root, regenerate the data:
python3 scripts/run_campaign.py && python3 scripts/run_eval.py

# then run the app:
cd apps/dashboard
npm install        # or pnpm install
npm run sync       # copy the latest scorecard.json + eval.json into data/
npm run dev        # http://localhost:3000
```

Deploy: Vercel (first-party Next.js). Point it at `apps/dashboard`. For live trace
deep-links, add `LANGSMITH_PROJECT` / Langfuse links per row (TODO — the trace ids
are already in the Python `AttackTrace`; surface them into scorecard.json first).
