# RedCell Dashboard (Next.js)

The shareable web version of the leaderboard. At build time it reads every result file the Python
scripts write under `../../dashboard/` (scorecards, benign controls, repeated runs, adaptive-attacker
runs and the AgentDojo check) and exports a static site to `out/`. There is no server and no copy step.

```bash
cd apps/dashboard
npm install
npm run build      # static site in out/
npm run dev        # http://localhost:3000 while editing
```

Deploy `out/` to any static host. The self-contained `dashboard/leaderboard.html`
(`scripts/build_leaderboard.py`) shows the same numbers, plus the live attack feed during a run.
